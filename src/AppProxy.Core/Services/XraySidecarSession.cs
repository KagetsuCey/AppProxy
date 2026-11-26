using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using AppProxy.Core.Models;

namespace AppProxy.Core.Services;

/// <summary>
/// Manages a headless xray.exe child process configured via stdin JSON ("run -c stdin:"),
/// bound to a Kill-on-Close Windows Job Object and optionally chained into PhysicalDirectSocksProxy.
/// </summary>
public sealed class XraySidecarSession : IDisposable
{
    private const int JobObjectExtendedLimitInformation = 9;
    private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_BASIC_LIMIT_INFORMATION
    {
        public long PerProcessUserTimeLimit;
        public long PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize;
        public UIntPtr MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass;
        public uint SchedulingClass;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct IO_COUNTERS
    {
        public ulong ReadOperationCount;
        public ulong WriteOperationCount;
        public ulong OtherOperationCount;
        public ulong ReadTransferCount;
        public ulong WriteTransferCount;
        public ulong OtherTransferCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION
    {
        public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
        public IO_COUNTERS IoInfo;
        public UIntPtr ProcessMemoryLimit;
        public UIntPtr JobMemoryLimit;
        public UIntPtr PeakProcessMemoryUsed;
        public UIntPtr PeakJobMemoryUsed;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObjectW(IntPtr lpJobAttributes, string? lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(
        IntPtr hJob,
        int jobObjectInformationClass,
        ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION lpJobObjectInformation,
        int cbJobObjectInformationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    private readonly Process _process;
    private readonly PhysicalDirectSocksProxy? _physicalDialer;
    private readonly IntPtr _jobHandle;
    private readonly Dictionary<Guid, ProxyProfile> _localProfilesByProxyId;
    private readonly ConcurrentQueue<string> _stderrLines = new();
    private bool _disposed;

    public int ProcessId => _process.Id;
    public ProxyProfile PrimaryLocalSocksProfile { get; }

    private XraySidecarSession(
        Process process,
        PhysicalDirectSocksProxy? physicalDialer,
        IntPtr jobHandle,
        Dictionary<Guid, ProxyProfile> localProfilesByProxyId,
        ProxyProfile primaryProfile)
    {
        _process = process;
        _physicalDialer = physicalDialer;
        _jobHandle = jobHandle;
        _localProfilesByProxyId = localProfilesByProxyId;
        PrimaryLocalSocksProfile = primaryProfile;
    }

    public ProxyProfile? GetLocalSocksProfile(Guid proxyId) =>
        _localProfilesByProxyId.TryGetValue(proxyId, out ProxyProfile? profile) ? profile : null;

    public static Task<XraySidecarSession> StartSingleAsync(
        string xrayExePath,
        ProxyProfile proxy,
        bool bypassGlobalTun,
        string? preferredOutboundInterface,
        CancellationToken ct) =>
        StartBatchAsync(xrayExePath, [proxy], bypassGlobalTun, preferredOutboundInterface, ct);

    public static async Task<XraySidecarSession> StartBatchAsync(
        string xrayExePath,
        IReadOnlyList<ProxyProfile> proxies,
        bool bypassGlobalTun,
        string? preferredOutboundInterface,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(xrayExePath) || !File.Exists(xrayExePath))
        {
            throw new FileNotFoundException("未找到 Xray-core 可执行文件 (xray.exe)。", xrayExePath);
        }

        ArgumentNullException.ThrowIfNull(proxies);
        if (proxies.Count == 0)
        {
            throw new ArgumentException("At least one proxy is required.", nameof(proxies));
        }

        string socksUser = Guid.NewGuid().ToString("N")[..16];
        string socksPass = Guid.NewGuid().ToString("N")[..16];

        var allocatedPorts = new List<int>(proxies.Count);
        var usedPorts = new HashSet<int>();
        for (int i = 0; i < proxies.Count; i++)
        {
            int port = AllocateLoopbackPort(usedPorts);
            allocatedPorts.Add(port);
        }

        var mappings = new List<XrayInboundMapping>(proxies.Count);
        var localProfiles = new Dictionary<Guid, ProxyProfile>(proxies.Count);
        for (int i = 0; i < proxies.Count; i++)
        {
            ProxyProfile orig = proxies[i];
            int port = allocatedPorts[i];
            mappings.Add(new XrayInboundMapping(port, $"socks-in-{i}", $"vless-out-{i}", orig));
            localProfiles[orig.Id] = new ProxyProfile
            {
                Id = orig.Id,
                Name = orig.Name,
                Protocol = ProxyProtocol.Socks5,
                Host = "127.0.0.1",
                Port = port,
                Username = socksUser,
                Password = socksPass
            };
        }

        PhysicalDirectSocksProxy? physicalDialer = bypassGlobalTun
            ? new PhysicalDirectSocksProxy(bypassGlobalTun: true, preferredOutboundInterface)
            : null;

        IntPtr jobHandle = IntPtr.Zero;
        Process? process = null;

        try
        {
            string configJson = XrayConfigBuilder.BuildMultiProxyConfigJson(
                mappings,
                socksUser,
                socksPass,
                physicalDialer?.Port,
                physicalDialer?.Username,
                physicalDialer?.Password);

            jobHandle = CreateKillOnCloseJob();

            var psi = new ProcessStartInfo
            {
                FileName = xrayExePath,
                Arguments = "run -c stdin:",
                WorkingDirectory = Path.GetDirectoryName(xrayExePath) ?? AppPaths.ResolveBaseDirectory(),
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                StandardInputEncoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };

            process = new Process { StartInfo = psi };
            if (!process.Start())
            {
                throw new InvalidOperationException("无法启动 xray.exe 进程。");
            }

            if (jobHandle != IntPtr.Zero)
            {
                AssignProcessToJobObject(jobHandle, process.Handle);
            }

            var session = new XraySidecarSession(
                process,
                physicalDialer,
                jobHandle,
                localProfiles,
                localProfiles[proxies[0].Id]);

            _ = session.DrainReaderAsync(process.StandardOutput);
            _ = session.DrainReaderAsync(process.StandardError);

            await process.StandardInput.WriteAsync(configJson.AsMemory(), ct);
            await process.StandardInput.FlushAsync(ct);
            process.StandardInput.Close();

            await session.WaitForListenerReadyAsync(allocatedPorts[0], ct);
            return session;
        }
        catch
        {
            try { process?.Kill(entireProcessTree: true); } catch { }
            process?.Dispose();
            if (jobHandle != IntPtr.Zero) CloseHandle(jobHandle);
            physicalDialer?.Dispose();
            throw;
        }
    }

    private async Task DrainReaderAsync(StreamReader reader)
    {
        try
        {
            while (true)
            {
                string? line = await reader.ReadLineAsync();
                if (line is null) break;
                if (string.IsNullOrWhiteSpace(line)) continue;

                _stderrLines.Enqueue(line.Trim());
                while (_stderrLines.Count > 20)
                {
                    _stderrLines.TryDequeue(out _);
                }
            }
        }
        catch
        {
        }
    }

    private async Task WaitForListenerReadyAsync(int firstPort, CancellationToken ct)
    {
        using var readyCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        readyCts.CancelAfter(TimeSpan.FromSeconds(5));

        while (!readyCts.IsCancellationRequested)
        {
            if (_process.HasExited)
            {
                string tail = string.Join(" | ", _stderrLines.ToArray());
                throw new InvalidOperationException(string.IsNullOrWhiteSpace(tail)
                    ? $"Xray-core 进程提前退出 (ExitCode={_process.ExitCode})。"
                    : $"Xray-core 启动失败: {tail}");
            }

            try
            {
                using var probe = new TcpClient();
                await probe.ConnectAsync(IPAddress.Loopback, firstPort, readyCts.Token);
                return;
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                await Task.Delay(25, readyCts.Token);
            }
        }

        if (_process.HasExited)
        {
            string tail = string.Join(" | ", _stderrLines.ToArray());
            throw new InvalidOperationException(string.IsNullOrWhiteSpace(tail)
                ? $"Xray-core 进程提前退出 (ExitCode={_process.ExitCode})。"
                : $"Xray-core 启动失败: {tail}");
        }

        throw new TimeoutException($"等待 Xray-core 本地入站端口 127.0.0.1:{firstPort} 就绪超时。");
    }

    private static int AllocateLoopbackPort(HashSet<int> usedPorts)
    {
        for (int i = 0; i < 16; i++)
        {
            using var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            int port = ((IPEndPoint)listener.LocalEndpoint).Port;
            if (usedPorts.Add(port))
            {
                return port;
            }
        }
        throw new InvalidOperationException("无法分配可用的本地回环端口。");
    }

    private static IntPtr CreateKillOnCloseJob()
    {
        IntPtr job = CreateJobObjectW(IntPtr.Zero, null);
        if (job == IntPtr.Zero) return IntPtr.Zero;

        var info = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION
        {
            BasicLimitInformation = new JOBOBJECT_BASIC_LIMIT_INFORMATION
            {
                LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            }
        };

        if (!SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                ref info,
                Marshal.SizeOf<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()))
        {
            CloseHandle(job);
            return IntPtr.Zero;
        }

        return job;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;

        try
        {
            if (!_process.HasExited)
            {
                _process.Kill(entireProcessTree: true);
            }
        }
        catch
        {
        }

        try { _process.Dispose(); } catch { }
        if (_jobHandle != IntPtr.Zero)
        {
            CloseHandle(_jobHandle);
        }
        _physicalDialer?.Dispose();
    }
}

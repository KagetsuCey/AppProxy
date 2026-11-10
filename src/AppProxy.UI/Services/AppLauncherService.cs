using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using AppProxy.UI.Models;

namespace AppProxy.UI.Services;

public sealed class AppLauncherService : IDisposable
{
    private readonly SharedMemoryService _shm;
    private readonly LocalProxyBridge _bridge;
    private readonly CancellationTokenSource _cts = new();
    private uint _nextSessionId = 1;
    private bool _disposed;

    public event Action<ProcessEventRecord>? ProcessEventReceived;

    private sealed class InjectorOutput
    {
        [JsonPropertyName("ok")]
        public bool Ok { get; set; }

        [JsonPropertyName("pid")]
        public uint Pid { get; set; }

        [JsonPropertyName("arch")]
        public string? Arch { get; set; }

        [JsonPropertyName("error")]
        public string? Error { get; set; }
    }

    private sealed class PipeLogPayload
    {
        [JsonPropertyName("ts")]
        public long Ts { get; set; }

        [JsonPropertyName("sessionId")]
        public uint SessionId { get; set; }

        [JsonPropertyName("pid")]
        public uint Pid { get; set; }

        [JsonPropertyName("parentPid")]
        public uint ParentPid { get; set; }

        [JsonPropertyName("arch")]
        public string? Arch { get; set; }

        [JsonPropertyName("process")]
        public string? Process { get; set; }

        [JsonPropertyName("event")]
        public string? Event { get; set; }

        [JsonPropertyName("message")]
        public string? Message { get; set; }
    }

    public AppLauncherService(SharedMemoryService shm, LocalProxyBridge bridge)
    {
        _shm = shm;
        _bridge = bridge;
        StartPipeServer();
    }

    public async Task<(bool Ok, uint Pid, string Message)> LaunchAppAsync(AppProfile app, ProxyProfile? proxy)
    {
        if (string.IsNullOrWhiteSpace(app.ExePath) || !File.Exists(app.ExePath))
        {
            return (false, 0, $"Executable not found: {app.ExePath}");
        }

        string nativeDir = Path.Combine(AppContext.BaseDirectory, "native");
        string detectedArch = PeInspector.DetectArchitecture(app.ExePath);
        string injectorName = detectedArch == "x86" ? "AppProxy.Injector.x86.exe" : "AppProxy.Injector.x64.exe";
        string injectorPath = Path.Combine(nativeDir, injectorName);

        if (!File.Exists(injectorPath))
        {
            // Fallback to x64 injector (which also delegates x86 targets via IsWow64Process2)
            string fallback = Path.Combine(nativeDir, "AppProxy.Injector.x64.exe");
            if (File.Exists(fallback))
            {
                injectorPath = fallback;
            }
            else
            {
                return (false, 0, $"Native injector missing at {injectorPath}. Please build native x86/x64 projects.");
            }
        }

        uint sessionId = Interlocked.Increment(ref _nextSessionId);
        NativeSessionFlags flags = NativeSessionFlags.None;
        if (proxy is null) flags |= NativeSessionFlags.DirectMode;
        if (app.RemoteDns) flags |= NativeSessionFlags.RemoteDns;
        if (app.BypassLan) flags |= NativeSessionFlags.BypassLan;
        if (app.InjectChildren) flags |= NativeSessionFlags.InjectChildren;

        _shm.RegisterSession(sessionId, flags);
        _bridge.RegisterSession(new SessionContext
        {
            SessionId = sessionId,
            AppName = Path.GetFileName(app.ExePath),
            Proxy = proxy,
            BypassLan = app.BypassLan,
            RemoteDns = app.RemoteDns
        });

        string exeB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(app.ExePath));
        string argsB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(app.Arguments ?? string.Empty));
        string workDir = string.IsNullOrWhiteSpace(app.WorkingDirectory)
            ? (Path.GetDirectoryName(app.ExePath) ?? string.Empty)
            : app.WorkingDirectory;
        string workDirB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(workDir));

        var injectorArgs = new StringBuilder($"--launch --exe-b64 {exeB64}");
        if (!string.IsNullOrEmpty(argsB64))
        {
            injectorArgs.Append($" --args-b64 {argsB64}");
        }
        if (!string.IsNullOrEmpty(workDirB64))
        {
            injectorArgs.Append($" --workdir-b64 {workDirB64}");
        }

        var psi = new ProcessStartInfo
        {
            FileName = injectorPath,
            Arguments = injectorArgs.ToString(),
            WorkingDirectory = nativeDir,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        psi.Environment["APPPROXY_BRIDGE_PID"] = _shm.BridgeId.ToString();
        psi.Environment["APPPROXY_SESSION_ID"] = sessionId.ToString();
        psi.Environment["APPPROXY_FLAGS"] = ((uint)flags).ToString();
        psi.Environment["APPPROXY_SELF_DIR"] = nativeDir;

        using var proc = Process.Start(psi);
        if (proc is null)
        {
            _bridge.UnregisterSession(sessionId);
            _shm.UnregisterSession(sessionId);
            return (false, 0, "Failed to start native injector process.");
        }

        string stdout = await proc.StandardOutput.ReadToEndAsync();
        string stderr = await proc.StandardError.ReadToEndAsync();
        await proc.WaitForExitAsync();

        InjectorOutput? result = null;
        try
        {
            result = JsonSerializer.Deserialize<InjectorOutput>(stdout.Trim());
        }
        catch
        {
        }

        if (proc.ExitCode != 0 || result is null || !result.Ok)
        {
            _bridge.UnregisterSession(sessionId);
            _shm.UnregisterSession(sessionId);
            string errMsg = result?.Error ?? (string.IsNullOrWhiteSpace(stderr) ? stdout : stderr);
            return (false, 0, $"Launch injection failed: {errMsg.Trim()}");
        }

        ProcessEventReceived?.Invoke(new ProcessEventRecord
        {
            Timestamp = DateTime.Now,
            SessionId = sessionId,
            Pid = result.Pid,
            ParentPid = (uint)Environment.ProcessId,
            Arch = result.Arch ?? detectedArch,
            ProcessName = Path.GetFileName(app.ExePath),
            EventType = "Launched",
            Message = proxy is not null
                ? $"Launched via {proxy.Name} ({proxy.ProtocolDisplay} {proxy.EndpointDisplay})"
                : "Launched in Direct mode"
        });

        return (true, result.Pid, $"Launched PID {result.Pid} ({result.Arch})");
    }

    private void StartPipeServer()
    {
        string pipeName = $"AppProxy_Log_{_shm.BridgeId}";
        _ = Task.Run(async () =>
        {
            while (!_cts.IsCancellationRequested)
            {
                NamedPipeServerStream? server = null;
                try
                {
                    server = new NamedPipeServerStream(
                        pipeName,
                        PipeDirection.In,
                        NamedPipeServerStream.MaxAllowedServerInstances,
                        PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous);

                    await server.WaitForConnectionAsync(_cts.Token);
                    var connectedPipe = server;
                    server = null;
                    _ = Task.Run(() => ReadPipeClientAsync(connectedPipe, _cts.Token), _cts.Token);
                }
                catch (OperationCanceledException)
                {
                    server?.Dispose();
                    break;
                }
                catch
                {
                    server?.Dispose();
                    await Task.Delay(100, _cts.Token);
                }
            }
        });
    }

    private async Task ReadPipeClientAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        await using (pipe)
        using (var reader = new StreamReader(pipe, Encoding.UTF8))
        {
            while (!ct.IsCancellationRequested && pipe.IsConnected)
            {
                string? line;
                try
                {
                    line = await reader.ReadLineAsync(ct);
                }
                catch
                {
                    break;
                }

                if (line is null) break;
                if (string.IsNullOrWhiteSpace(line)) continue;

                try
                {
                    var payload = JsonSerializer.Deserialize<PipeLogPayload>(line);
                    if (payload is not null)
                    {
                        var record = new ProcessEventRecord
                        {
                            Timestamp = payload.Ts > 0
                                ? DateTimeOffset.FromUnixTimeMilliseconds(payload.Ts).LocalDateTime
                                : DateTime.Now,
                            SessionId = payload.SessionId,
                            Pid = payload.Pid,
                            ParentPid = payload.ParentPid,
                            Arch = payload.Arch ?? string.Empty,
                            ProcessName = payload.Process ?? string.Empty,
                            EventType = payload.Event ?? "Log",
                            Message = payload.Message ?? string.Empty
                        };
                        ProcessEventReceived?.Invoke(record);
                    }
                }
                catch
                {
                }
            }
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cts.Cancel();
        _cts.Dispose();
    }
}

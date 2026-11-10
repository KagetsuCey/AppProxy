using System.Collections.Concurrent;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace AppProxy.UI.Interop;

/// <summary>
/// Binds a launched child process tree to a Windows Job Object and signals
/// when the last active process in that tree exits (JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO).
/// </summary>
public sealed class JobObjectTracker : IDisposable
{
    private const int JobObjectAssociateCompletionPortInformation = 7;
    private const uint JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO = 4;
    private const uint JOB_OBJECT_MSG_NEW_PROCESS = 6;
    private const uint JOB_OBJECT_MSG_EXIT_PROCESS = 7;
    private const uint JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS = 8;

    private const uint CREATE_SUSPENDED = 0x00000004;
    private const uint CREATE_NO_WINDOW = 0x08000000;
    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const uint STARTF_USESTDHANDLES = 0x00000100;
    private const uint HANDLE_FLAG_INHERIT = 0x00000001;

    private static readonly IntPtr InvalidHandleValue = new(-1);

    [StructLayout(LayoutKind.Sequential)]
    private struct JOBOBJECT_ASSOCIATE_COMPLETION_PORT
    {
        public IntPtr CompletionKey;
        public IntPtr CompletionPort;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)]
        public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFOW
    {
        public int cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateJobObjectW(IntPtr lpJobAttributes, string? lpName);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetInformationJobObject(
        IntPtr hJob,
        int jobObjectInformationClass,
        ref JOBOBJECT_ASSOCIATE_COMPLETION_PORT lpJobObjectInformation,
        int cbJobObjectInformationLength);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool AssignProcessToJobObject(IntPtr hJob, IntPtr hProcess);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateIoCompletionPort(
        IntPtr fileHandle,
        IntPtr existingCompletionPort,
        UIntPtr completionKey,
        uint numberOfConcurrentThreads);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetQueuedCompletionStatus(
        IntPtr completionPort,
        out uint lpNumberOfBytesTransferred,
        out UIntPtr lpCompletionKey,
        out IntPtr lpOverlapped,
        uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool PostQueuedCompletionStatus(
        IntPtr completionPort,
        uint dwNumberOfBytesTransferred,
        UIntPtr dwCompletionKey,
        IntPtr lpOverlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CreatePipe(
        out SafeFileHandle hReadPipe,
        out SafeFileHandle hWritePipe,
        ref SECURITY_ATTRIBUTES lpPipeAttributes,
        uint nSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetHandleInformation(SafeFileHandle hObject, uint dwMask, uint dwFlags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessW(
        string? lpApplicationName,
        StringBuilder lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFOW lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(SafeProcessHandle hProcess, out uint lpExitCode);

    private readonly IntPtr _hJob;
    private readonly IntPtr _hIocp;
    private readonly Thread? _iocpThread;
    private readonly ConcurrentDictionary<uint, byte> _trackedPids = new();
    private readonly TaskCompletionSource _allExitedTcs = new(TaskCreationOptions.RunContinuationsAsynchronously);
    private int _assignedCount;
    private int _disposed;

    public bool IsJobSupported => _hJob != IntPtr.Zero && _hIocp != IntPtr.Zero;
    public Task AllProcessesExited => _allExitedTcs.Task;

    public JobObjectTracker()
    {
        _hJob = CreateJobObjectW(IntPtr.Zero, null);
        if (_hJob == IntPtr.Zero)
        {
            return;
        }

        _hIocp = CreateIoCompletionPort(InvalidHandleValue, IntPtr.Zero, UIntPtr.Zero, 1);
        if (_hIocp == IntPtr.Zero)
        {
            CloseHandle(_hJob);
            _hJob = IntPtr.Zero;
            return;
        }

        var assoc = new JOBOBJECT_ASSOCIATE_COMPLETION_PORT
        {
            CompletionKey = _hJob,
            CompletionPort = _hIocp
        };

        if (!SetInformationJobObject(
                _hJob,
                JobObjectAssociateCompletionPortInformation,
                ref assoc,
                Marshal.SizeOf<JOBOBJECT_ASSOCIATE_COMPLETION_PORT>()))
        {
            CloseHandle(_hIocp);
            CloseHandle(_hJob);
            _hIocp = IntPtr.Zero;
            _hJob = IntPtr.Zero;
            return;
        }

        _iocpThread = new Thread(IocpLoop)
        {
            IsBackground = true,
            Name = "AppProxy-JobObject-IOCP"
        };
        _iocpThread.Start();
    }

    public void TrackPidFallback(uint pid)
    {
        if (pid == 0) return;
        if (_trackedPids.TryAdd(pid, 1))
        {
            _ = WaitPidFallbackAsync(pid);
        }
    }

    private async Task WaitPidFallbackAsync(uint pid)
    {
        try
        {
            using var proc = Process.GetProcessById((int)pid);
            await proc.WaitForExitAsync();
        }
        catch
        {
            // Already exited
        }
        finally
        {
            _trackedPids.TryRemove(pid, out _);
            if (_assignedCount == 0 && _trackedPids.IsEmpty)
            {
                _allExitedTcs.TrySetResult();
            }
        }
    }

    /// <summary>
    /// Launches a child helper process suspended, assigns it to the Job Object
    /// BEFORE resuming its main thread (so any process it spawns inherits the Job
    /// atomically from birth), and reads its stdout/stderr until exit.
    /// </summary>
    public async Task<(int ExitCode, string StdOut, string StdErr)> RunInJobAndCaptureAsync(
        string exePath,
        string arguments,
        string workingDirectory,
        IReadOnlyDictionary<string, string> extraEnv,
        CancellationToken ct = default)
    {
        var sa = new SECURITY_ATTRIBUTES
        {
            nLength = Marshal.SizeOf<SECURITY_ATTRIBUTES>(),
            bInheritHandle = true
        };

        if (!CreatePipe(out SafeFileHandle stdoutRead, out SafeFileHandle stdoutWrite, ref sa, 0))
            throw new Win32Exception(Marshal.GetLastWin32Error());

        if (!CreatePipe(out SafeFileHandle stderrRead, out SafeFileHandle stderrWrite, ref sa, 0))
        {
            stdoutRead.Dispose();
            stdoutWrite.Dispose();
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        using (stdoutRead)
        using (stderrRead)
        {
            SetHandleInformation(stdoutRead, HANDLE_FLAG_INHERIT, 0);
            SetHandleInformation(stderrRead, HANDLE_FLAG_INHERIT, 0);

            var si = new STARTUPINFOW
            {
                cb = Marshal.SizeOf<STARTUPINFOW>(),
                dwFlags = STARTF_USESTDHANDLES,
                hStdInput = IntPtr.Zero,
                hStdOutput = stdoutWrite.DangerousGetHandle(),
                hStdError = stderrWrite.DangerousGetHandle()
            };

            var cmdLine = new StringBuilder($"\"{exePath}\"");
            if (!string.IsNullOrWhiteSpace(arguments))
            {
                cmdLine.Append(' ').Append(arguments);
            }

            IntPtr envBlock = BuildUnicodeEnvironmentBlock(extraEnv);
            PROCESS_INFORMATION pi;
            try
            {
                bool created = CreateProcessW(
                    exePath,
                    cmdLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    bInheritHandles: true,
                    CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                    envBlock,
                    string.IsNullOrWhiteSpace(workingDirectory) ? null : workingDirectory,
                    ref si,
                    out pi);

                if (!created)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }
            finally
            {
                if (envBlock != IntPtr.Zero)
                {
                    Marshal.FreeHGlobal(envBlock);
                }
                stdoutWrite.Dispose();
                stderrWrite.Dispose();
            }

            try
            {
                if (IsJobSupported && AssignProcessToJobObject(_hJob, pi.hProcess))
                {
                    Interlocked.Increment(ref _assignedCount);
                }
            }
            finally
            {
                ResumeThread(pi.hThread);
                CloseHandle(pi.hThread);
            }

            using var procHandle = new SafeProcessHandle(pi.hProcess, ownsHandle: true);

            using var outStream = new FileStream(stdoutRead, FileAccess.Read, 4096, isAsync: false);
            using var errStream = new FileStream(stderrRead, FileAccess.Read, 4096, isAsync: false);
            using var outReader = new StreamReader(outStream, Encoding.UTF8);
            using var errReader = new StreamReader(errStream, Encoding.UTF8);

            Task<string> readOutTask = outReader.ReadToEndAsync(ct);
            Task<string> readErrTask = errReader.ReadToEndAsync(ct);
            await WaitForProcessHandleAsync(procHandle, ct);

            string stdout = await readOutTask;
            string stderr = await readErrTask;
            GetExitCodeProcess(procHandle, out uint exitCode);
            return (unchecked((int)exitCode), stdout, stderr);
        }
    }

    private sealed class ProcessWaitHandle : WaitHandle
    {
        public ProcessWaitHandle(SafeProcessHandle processHandle)
        {
            SafeWaitHandle = new SafeWaitHandle(processHandle.DangerousGetHandle(), ownsHandle: false);
        }
    }

    private static Task WaitForProcessHandleAsync(SafeProcessHandle handle, CancellationToken ct)
    {
        var waitHandle = new ProcessWaitHandle(handle);
        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        RegisteredWaitHandle? reg = null;
        CancellationTokenRegistration ctr = default;

        reg = ThreadPool.RegisterWaitForSingleObject(
            waitHandle,
            static (state, _) => ((TaskCompletionSource)state!).TrySetResult(),
            tcs,
            Timeout.Infinite,
            executeOnlyOnce: true);

        if (ct.CanBeCanceled)
        {
            ctr = ct.Register(static state => ((TaskCompletionSource)state!).TrySetCanceled(), tcs);
        }

        return tcs.Task.ContinueWith(
            _ =>
            {
                reg?.Unregister(null);
                ctr.Dispose();
                waitHandle.Dispose();
            },
            CancellationToken.None,
            TaskContinuationOptions.ExecuteSynchronously,
            TaskScheduler.Default);
    }

    private void IocpLoop()
    {
        while (Volatile.Read(ref _disposed) == 0)
        {
            bool ok = GetQueuedCompletionStatus(
                _hIocp,
                out uint msgId,
                out _,
                out IntPtr overlapped,
                uint.MaxValue);

            if (!ok && overlapped == IntPtr.Zero)
            {
                break;
            }

            if (msgId == JOB_OBJECT_MSG_NEW_PROCESS)
            {
                uint pid = (uint)overlapped.ToInt64();
                if (pid != 0) _trackedPids.TryAdd(pid, 1);
            }
            else if (msgId == JOB_OBJECT_MSG_EXIT_PROCESS || msgId == JOB_OBJECT_MSG_ABNORMAL_EXIT_PROCESS)
            {
                uint pid = (uint)overlapped.ToInt64();
                if (pid != 0) _trackedPids.TryRemove(pid, out _);
            }
            else if (msgId == JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO)
            {
                _allExitedTcs.TrySetResult();
                break;
            }
        }
    }

    private static IntPtr BuildUnicodeEnvironmentBlock(IReadOnlyDictionary<string, string> extraEnv)
    {
        var merged = new SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (System.Collections.DictionaryEntry entry in Environment.GetEnvironmentVariables())
        {
            if (entry.Key is string k && entry.Value is string v)
            {
                merged[k] = v;
            }
        }
        foreach (var kv in extraEnv)
        {
            merged[kv.Key] = kv.Value;
        }

        var sb = new StringBuilder();
        foreach (var kv in merged)
        {
            sb.Append(kv.Key).Append('=').Append(kv.Value).Append('\0');
        }
        sb.Append('\0');

        byte[] bytes = Encoding.Unicode.GetBytes(sb.ToString());
        IntPtr ptr = Marshal.AllocHGlobal(bytes.Length);
        Marshal.Copy(bytes, 0, ptr, bytes.Length);
        return ptr;
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
        if (_hIocp != IntPtr.Zero)
        {
            PostQueuedCompletionStatus(_hIocp, 0, UIntPtr.Zero, IntPtr.Zero);
            CloseHandle(_hIocp);
        }
        if (_hJob != IntPtr.Zero)
        {
            CloseHandle(_hJob);
        }
    }
}

/// <summary>
/// Launches AppProxy.Bridge.exe completely detached from the parent UI process tree
/// (via CREATE_BREAKAWAY_FROM_JOB | CREATE_NEW_PROCESS_GROUP) so closing the UI never
/// terminates the bridge process.
/// </summary>
public static class DetachedProcessLauncher
{
    private const uint CREATE_BREAKAWAY_FROM_JOB = 0x01000000;
    private const uint CREATE_NEW_PROCESS_GROUP = 0x00000200;
    private const uint CREATE_NO_WINDOW = 0x08000000;
    private const uint STARTF_USESTDHANDLES = 0x00000100;
    private const uint HANDLE_FLAG_INHERIT = 0x00000001;
    private const int ERROR_ACCESS_DENIED = 5;

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        [MarshalAs(UnmanagedType.Bool)]
        public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct STARTUPINFOW
    {
        public int cb;
        public IntPtr lpReserved;
        public IntPtr lpDesktop;
        public IntPtr lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public ushort wShowWindow;
        public ushort cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CreatePipe(
        out SafeFileHandle hReadPipe,
        out SafeFileHandle hWritePipe,
        ref SECURITY_ATTRIBUTES lpPipeAttributes,
        uint nSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetHandleInformation(SafeFileHandle hObject, uint dwMask, uint dwFlags);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessW(
        string? lpApplicationName,
        StringBuilder lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        [MarshalAs(UnmanagedType.Bool)] bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFOW lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(SafeProcessHandle hProcess, out uint lpExitCode);

    public static async Task<(uint ProcessId, string FirstLine)> StartDetachedAndReadFirstLineAsync(
        string exePath,
        string arguments,
        string workingDirectory,
        TimeSpan timeout)
    {
        var sa = new SECURITY_ATTRIBUTES
        {
            nLength = Marshal.SizeOf<SECURITY_ATTRIBUTES>(),
            bInheritHandle = true
        };

        if (!CreatePipe(out SafeFileHandle readPipe, out SafeFileHandle writePipe, ref sa, 0))
            throw new Win32Exception(Marshal.GetLastWin32Error());

        using (readPipe)
        {
            SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

            var si = new STARTUPINFOW
            {
                cb = Marshal.SizeOf<STARTUPINFOW>(),
                dwFlags = STARTF_USESTDHANDLES,
                hStdInput = IntPtr.Zero,
                hStdOutput = writePipe.DangerousGetHandle(),
                hStdError = writePipe.DangerousGetHandle()
            };

            var cmdLine = new StringBuilder($"\"{exePath}\"");
            if (!string.IsNullOrWhiteSpace(arguments))
            {
                cmdLine.Append(' ').Append(arguments);
            }

            PROCESS_INFORMATION pi;
            try
            {
                uint baseFlags = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP;
                bool ok = CreateProcessW(
                    exePath,
                    cmdLine,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    bInheritHandles: true,
                    baseFlags | CREATE_BREAKAWAY_FROM_JOB,
                    IntPtr.Zero,
                    string.IsNullOrWhiteSpace(workingDirectory) ? null : workingDirectory,
                    ref si,
                    out pi);

                if (!ok && Marshal.GetLastWin32Error() == ERROR_ACCESS_DENIED)
                {
                    cmdLine.Clear().Append($"\"{exePath}\"");
                    if (!string.IsNullOrWhiteSpace(arguments))
                    {
                        cmdLine.Append(' ').Append(arguments);
                    }
                    ok = CreateProcessW(
                        exePath,
                        cmdLine,
                        IntPtr.Zero,
                        IntPtr.Zero,
                        bInheritHandles: true,
                        baseFlags,
                        IntPtr.Zero,
                        string.IsNullOrWhiteSpace(workingDirectory) ? null : workingDirectory,
                        ref si,
                        out pi);
                }

                if (!ok)
                {
                    throw new Win32Exception(Marshal.GetLastWin32Error());
                }
            }
            finally
            {
                writePipe.Dispose();
            }

            uint pid = pi.dwProcessId;
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);

            using var cts = new CancellationTokenSource(timeout);
            using var stream = new FileStream(readPipe, FileAccess.Read, 4096, isAsync: false);
            using var reader = new StreamReader(stream, Encoding.UTF8);
            string? line = await reader.ReadLineAsync(cts.Token);
            return (pid, line ?? string.Empty);
        }
    }
}

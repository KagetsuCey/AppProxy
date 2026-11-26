using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using AppProxy.Core.Interop;

namespace AppProxy.Core.Services;

public sealed record RunningProcessEntry(
    uint ProcessId,
    uint ParentProcessId,
    string ExeFileName,
    string? FullPath = null);

public sealed record InstanceLimitCheckResult(
    bool Allowed,
    int RunningCount,
    int MaxInstances,
    string? BlockReason);

public static class ProcessInstanceCounter
{
    private const uint TH32CS_SNAPPROCESS = 0x00000002;
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint SYNCHRONIZE = 0x00100000;
    private const uint WAIT_OBJECT_0 = 0x00000000;
    private const uint STILL_ACTIVE = 259;
    private const int ERROR_ACCESS_DENIED = 5;
    private const int ERROR_INVALID_PARAMETER = 87;
    private const int ERROR_INSUFFICIENT_BUFFER = 122;

    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint FILE_SHARE_DELETE = 0x00000004;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const uint VOLUME_NAME_DOS = 0x0;

    private static readonly IntPtr INVALID_HANDLE_VALUE = new(-1);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct PROCESSENTRY32W
    {
        public uint dwSize;
        public uint cntUsage;
        public uint th32ProcessID;
        public UIntPtr th32DefaultHeapID;
        public uint th32ModuleID;
        public uint cntThreads;
        public uint th32ParentProcessID;
        public int pcPriClassBase;
        public uint dwFlags;
        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        public string szExeFile;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool Process32FirstW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool Process32NextW(IntPtr hSnapshot, ref PROCESSENTRY32W lppe);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(
        IntPtr hProcess,
        uint dwFlags,
        [Out] char[] lpExeName,
        ref uint lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateFileW(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern uint GetFinalPathNameByHandleW(
        IntPtr hFile,
        [Out] char[] lpszFilePath,
        uint cchFilePath,
        uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr hObject);

    public static int ClampMaxInstances(int configuredMaxInstances) =>
        configuredMaxInstances < 1 ? 1 : configuredMaxInstances;

    private static int _legacyCleanupStarted;

    private sealed class NamedMutexLockHandle : IDisposable
    {
        private readonly ManualResetEventSlim _releaseSignal;
        private readonly ManualResetEventSlim _releasedDone;
        private int _disposed;

        public NamedMutexLockHandle(ManualResetEventSlim releaseSignal, ManualResetEventSlim releasedDone)
        {
            _releaseSignal = releaseSignal;
            _releasedDone = releasedDone;
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;

            _releaseSignal.Set();
            if (_releasedDone.Wait(TimeSpan.FromSeconds(2)))
            {
                _releaseSignal.Dispose();
                _releasedDone.Dispose();
            }
        }
    }

    internal static string BuildLaunchMutexName(string exePath, string? customBaseDir = null)
    {
        string targetKey = (TryGetFinalFilePath(NormalizePath(exePath)) ?? NormalizePath(exePath)).ToUpperInvariant();
        string scopeKey = AppPaths.GetDataDirectory(customBaseDir).ToUpperInvariant() + "|" + targetKey;
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(scopeKey));
        return $"Local\\AppProxy_Launch_{Convert.ToHexString(hash)[..24]}";
    }

    public static Task<IDisposable?> AcquireLaunchLockAsync(
        string exePath,
        string? customBaseDir = null,
        TimeSpan? timeout = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(exePath))
        {
            return Task.FromResult<IDisposable?>(null);
        }

        if (ct.IsCancellationRequested)
        {
            return Task.FromCanceled<IDisposable?>(ct);
        }

        if (customBaseDir is null && Interlocked.Exchange(ref _legacyCleanupStarted, 1) == 0)
        {
            _ = Task.Run(() => CleanupLegacyLockFiles());
        }

        string mutexName = BuildLaunchMutexName(exePath, customBaseDir);
        int timeoutMs = Math.Max(0, (int)(timeout ?? TimeSpan.FromSeconds(5)).TotalMilliseconds);
        var acquiredTcs = new TaskCompletionSource<IDisposable?>(TaskCreationOptions.RunContinuationsAsynchronously);

        // Dedicate a thread to own the OS Mutex so WaitOne and ReleaseMutex always execute
        // on the same thread even when callers await across thread-pool continuations.
        var ownerThread = new Thread(() =>
        {
            var releaseSignal = new ManualResetEventSlim(false);
            var releasedDone = new ManualResetEventSlim(false);
            bool acquired = false;

            try
            {
                using var mutex = new Mutex(initiallyOwned: false, name: mutexName);
                try
                {
                    if (ct.CanBeCanceled)
                    {
                        int idx = WaitHandle.WaitAny([mutex, ct.WaitHandle], timeoutMs);
                        acquired = idx == 0;
                        if (idx == 1)
                        {
                            acquiredTcs.TrySetCanceled(ct);
                            releaseSignal.Dispose();
                            releasedDone.Dispose();
                            return;
                        }
                    }
                    else
                    {
                        acquired = mutex.WaitOne(timeoutMs);
                    }
                }
                catch (AbandonedMutexException)
                {
                    // Previous holder exited/crashed without releasing; OS transferred ownership to us.
                    acquired = true;
                }

                if (!acquired)
                {
                    acquiredTcs.TrySetResult(null);
                    releaseSignal.Dispose();
                    releasedDone.Dispose();
                    return;
                }

                var handle = new NamedMutexLockHandle(releaseSignal, releasedDone);
                acquiredTcs.TrySetResult(handle);

                releaseSignal.Wait();
                try
                {
                    mutex.ReleaseMutex();
                }
                catch
                {
                }
                finally
                {
                    releasedDone.Set();
                }
            }
            catch (OperationCanceledException)
            {
                acquiredTcs.TrySetCanceled(ct);
                releaseSignal.Dispose();
                releasedDone.Dispose();
            }
            catch
            {
                if (!acquired)
                {
                    acquiredTcs.TrySetResult(null);
                    releaseSignal.Dispose();
                    releasedDone.Dispose();
                }
                else
                {
                    releasedDone.Set();
                }
            }
        })
        {
            Name = "AppProxy.LaunchMutex",
            IsBackground = true
        };

        ownerThread.Start();
        return acquiredTcs.Task;
    }

    /// <summary>
    /// Cleans up legacy 0-byte launch_*.lock files from data\locks\ left by earlier versions
    /// and removes the locks directory if empty.
    /// </summary>
    public static int CleanupLegacyLockFiles(string? customBaseDir = null)
    {
        string lockDir = Path.Combine(AppPaths.GetDataDirectory(customBaseDir), "locks");
        if (!Directory.Exists(lockDir))
        {
            return 0;
        }

        int deleted = 0;
        try
        {
            foreach (string file in Directory.EnumerateFiles(lockDir, "launch_*.lock", SearchOption.TopDirectoryOnly))
            {
                try
                {
                    File.Delete(file);
                    deleted++;
                }
                catch
                {
                }
            }

            if (!Directory.EnumerateFileSystemEntries(lockDir).Any())
            {
                Directory.Delete(lockDir, recursive: false);
            }
        }
        catch
        {
        }

        return deleted;
    }

    public static InstanceLimitCheckResult CheckCanLaunch(
        string? exePath,
        int maxInstances,
        string? appDisplayName = null)
    {
        int effectiveMax = ClampMaxInstances(maxInstances);
        if (string.IsNullOrWhiteSpace(exePath))
        {
            return new InstanceLimitCheckResult(true, 0, effectiveMax, null);
        }

        int runningCount = CountRunningInstances(exePath);
        int projectedCount = runningCount + 1;
        if (projectedCount > effectiveMax)
        {
            string displayName = !string.IsNullOrWhiteSpace(appDisplayName)
                ? appDisplayName.Trim()
                : Path.GetFileName(exePath);
            string reason =
                $"无法启动「{displayName}」：当前已有 {runningCount} 个实例正在运行（无论是否通过代理启动均计入），" +
                $"启动后实例数 ({projectedCount}) 将超过配置的最大实例数 ({effectiveMax})，已取消启动。";
            return new InstanceLimitCheckResult(false, runningCount, effectiveMax, reason);
        }

        return new InstanceLimitCheckResult(true, runningCount, effectiveMax, null);
    }

    public static int CountRunningInstances(string exePath, uint? excludePid = null)
    {
        if (string.IsNullOrWhiteSpace(exePath)) return 0;

        string normalizedTarget = NormalizePath(exePath);
        string targetFileName = Path.GetFileName(normalizedTarget);
        if (string.IsNullOrWhiteSpace(targetFileName)) return 0;

        string? canonicalTarget = TryGetFinalFilePath(normalizedTarget);
        string? canonicalFileName = !string.IsNullOrEmpty(canonicalTarget)
            ? Path.GetFileName(canonicalTarget)
            : null;

        uint selfPid = excludePid ?? (uint)Environment.ProcessId;
        var matchingEntries = new List<RunningProcessEntry>();

        IntPtr snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == IntPtr.Zero || snapshot == INVALID_HANDLE_VALUE)
        {
            return 0;
        }

        try
        {
            var entry = new PROCESSENTRY32W
            {
                dwSize = (uint)Marshal.SizeOf<PROCESSENTRY32W>()
            };

            if (!Process32FirstW(snapshot, ref entry))
            {
                return 0;
            }

            do
            {
                uint pid = entry.th32ProcessID;
                if (pid == 0 || pid == selfPid)
                {
                    continue;
                }

                string procFileName = string.IsNullOrWhiteSpace(entry.szExeFile)
                    ? string.Empty
                    : Path.GetFileName(entry.szExeFile);

                bool fileNameMatches =
                    string.Equals(procFileName, targetFileName, StringComparison.OrdinalIgnoreCase) ||
                    (!string.IsNullOrEmpty(canonicalFileName) &&
                     string.Equals(procFileName, canonicalFileName, StringComparison.OrdinalIgnoreCase));

                if (!fileNameMatches)
                {
                    continue;
                }

                if (!TryInspectRunningProcess(pid, entry.cntThreads, out string? imagePath))
                {
                    continue;
                }

                if (!string.IsNullOrWhiteSpace(imagePath))
                {
                    if (!PathsMatch(imagePath, normalizedTarget, canonicalTarget))
                    {
                        continue;
                    }
                }
                // If imagePath could not be queried due to elevated privileges (ACCESS_DENIED),
                // fall back to matching by exe file name (already checked above) so elevated
                // non-proxied instances still count toward the limit.

                string? commandLine = ProcessInspectionHelper.TryGetCommandLine(pid);
                if (ProcessInspectionHelper.IsNonPrimaryHelperProcess(pid, procFileName, commandLine))
                {
                    continue;
                }

                matchingEntries.Add(new RunningProcessEntry(
                    pid,
                    entry.th32ParentProcessID,
                    procFileName,
                    imagePath));
            }
            while (Process32NextW(snapshot, ref entry));
        }
        finally
        {
            CloseHandle(snapshot);
        }

        return CountRootInstances(matchingEntries);
    }

    public static int CountRootInstances(IReadOnlyCollection<RunningProcessEntry> matchingProcesses)
    {
        if (matchingProcesses.Count == 0) return 0;

        var byPid = new Dictionary<uint, RunningProcessEntry>(matchingProcesses.Count);
        foreach (var proc in matchingProcesses)
        {
            if (proc.ProcessId != 0)
            {
                byPid[proc.ProcessId] = proc;
            }
        }

        if (byPid.Count == 0) return 0;

        var childrenByParent = new Dictionary<uint, List<uint>>();
        var roots = new List<uint>();

        foreach (var kv in byPid)
        {
            uint pid = kv.Key;
            uint ppid = kv.Value.ParentProcessId;

            if (ppid != 0 && ppid != pid && byPid.ContainsKey(ppid))
            {
                if (!childrenByParent.TryGetValue(ppid, out var children))
                {
                    children = new List<uint>();
                    childrenByParent[ppid] = children;
                }
                children.Add(pid);
            }
            else
            {
                roots.Add(pid);
            }
        }

        var visited = new HashSet<uint>();
        int instanceCount = 0;

        foreach (uint rootPid in roots)
        {
            if (visited.Add(rootPid))
            {
                instanceCount++;
                MarkDescendantsVisited(rootPid, childrenByParent, visited);
            }
        }

        // Defensive cycle handling in the rare case PID reuse formed a parent loop with no external root
        foreach (uint pid in byPid.Keys)
        {
            if (visited.Contains(pid)) continue;

            uint cursor = pid;
            var seenInWalk = new HashSet<uint>();
            while (seenInWalk.Add(cursor) &&
                   byPid.TryGetValue(cursor, out var current) &&
                   current.ParentProcessId != 0 &&
                   current.ParentProcessId != cursor &&
                   byPid.ContainsKey(current.ParentProcessId))
            {
                cursor = current.ParentProcessId;
            }

            instanceCount++;
            visited.Add(cursor);
            MarkDescendantsVisited(cursor, childrenByParent, visited);
            foreach (uint walked in seenInWalk)
            {
                visited.Add(walked);
            }
        }

        return instanceCount;
    }

    private static void MarkDescendantsVisited(
        uint rootPid,
        Dictionary<uint, List<uint>> childrenByParent,
        HashSet<uint> visited)
    {
        var stack = new Stack<uint>();
        stack.Push(rootPid);
        while (stack.Count > 0)
        {
            uint current = stack.Pop();
            if (!childrenByParent.TryGetValue(current, out var children)) continue;
            foreach (uint child in children)
            {
                if (visited.Add(child))
                {
                    stack.Push(child);
                }
            }
        }
    }

    private static bool TryInspectRunningProcess(uint pid, uint snapshotThreads, out string? imagePath)
    {
        imagePath = null;

        IntPtr handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, false, pid);
        if (handle != IntPtr.Zero)
        {
            try
            {
                if (WaitForSingleObject(handle, 0) == WAIT_OBJECT_0)
                {
                    return false;
                }

                imagePath = QueryProcessImagePath(handle);
                return true;
            }
            finally
            {
                CloseHandle(handle);
            }
        }

        int err = Marshal.GetLastWin32Error();
        if (err == ERROR_INVALID_PARAMETER)
        {
            return false;
        }

        handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (handle != IntPtr.Zero)
        {
            try
            {
                if (GetExitCodeProcess(handle, out uint exitCode) && exitCode != STILL_ACTIVE)
                {
                    return false;
                }

                imagePath = QueryProcessImagePath(handle);
                return true;
            }
            finally
            {
                CloseHandle(handle);
            }
        }

        int err2 = Marshal.GetLastWin32Error();
        if (err2 == ERROR_ACCESS_DENIED)
        {
            // Protected or elevated process; still alive as long as it has active threads.
            return snapshotThreads > 0;
        }

        return false;
    }

    private static string? QueryProcessImagePath(IntPtr hProcess)
    {
        char[] buffer = new char[1024];
        uint size = (uint)buffer.Length;
        if (QueryFullProcessImageNameW(hProcess, 0, buffer, ref size) && size > 0)
        {
            return new string(buffer, 0, (int)size);
        }

        if (Marshal.GetLastWin32Error() == ERROR_INSUFFICIENT_BUFFER)
        {
            buffer = new char[4096];
            size = (uint)buffer.Length;
            if (QueryFullProcessImageNameW(hProcess, 0, buffer, ref size) && size > 0)
            {
                return new string(buffer, 0, (int)size);
            }
        }

        return null;
    }

    public static bool PathsMatch(string candidatePath, string normalizedTarget, string? canonicalTarget)
    {
        string normalizedCandidate = NormalizePath(candidatePath);
        if (string.Equals(normalizedCandidate, normalizedTarget, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (!string.IsNullOrEmpty(canonicalTarget))
        {
            if (string.Equals(normalizedCandidate, canonicalTarget, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }

            string? canonicalCandidate = TryGetFinalFilePath(normalizedCandidate);
            if (!string.IsNullOrEmpty(canonicalCandidate) &&
                string.Equals(canonicalCandidate, canonicalTarget, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    public static string NormalizePath(string path)
    {
        string trimmed = path.Trim().Trim('"');
        try
        {
            return Path.TrimEndingDirectorySeparator(Path.GetFullPath(trimmed));
        }
        catch
        {
            return Path.TrimEndingDirectorySeparator(trimmed);
        }
    }

    internal static string? TryGetFinalFilePath(string fullPath)
    {
        try
        {
            IntPtr hFile = CreateFileW(
                fullPath,
                0,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                IntPtr.Zero,
                OPEN_EXISTING,
                FILE_FLAG_BACKUP_SEMANTICS,
                IntPtr.Zero);

            if (hFile == IntPtr.Zero || hFile == INVALID_HANDLE_VALUE)
            {
                return null;
            }

            try
            {
                char[] buf = new char[1024];
                uint len = GetFinalPathNameByHandleW(hFile, buf, (uint)buf.Length, VOLUME_NAME_DOS);
                if (len > buf.Length)
                {
                    buf = new char[len + 1];
                    len = GetFinalPathNameByHandleW(hFile, buf, (uint)buf.Length, VOLUME_NAME_DOS);
                }

                if (len == 0 || len >= buf.Length)
                {
                    return null;
                }

                string raw = new(buf, 0, (int)len);
                if (raw.StartsWith(@"\\?\UNC\", StringComparison.OrdinalIgnoreCase))
                {
                    raw = @"\\" + raw.AsSpan(8).ToString();
                }
                else if (raw.StartsWith(@"\\?\", StringComparison.Ordinal))
                {
                    raw = raw[4..];
                }

                return Path.TrimEndingDirectorySeparator(raw);
            }
            finally
            {
                CloseHandle(hFile);
            }
        }
        catch
        {
            return null;
        }
    }
}

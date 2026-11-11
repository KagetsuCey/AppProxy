using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using AppProxy.UI.Interop;

namespace AppProxy.UI.Services;

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

    public static async Task<IDisposable?> AcquireLaunchLockAsync(
        string exePath,
        string? customBaseDir = null,
        TimeSpan? timeout = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(exePath)) return null;

        string targetKey = (TryGetFinalFilePath(NormalizePath(exePath)) ?? NormalizePath(exePath)).ToUpperInvariant();
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(targetKey));
        string lockFileName = $"launch_{Convert.ToHexString(hash)[..16]}.lock";
        string lockDir = Path.Combine(AppPaths.GetDataDirectory(customBaseDir), "locks");
        string lockPath = Path.Combine(lockDir, lockFileName);

        try
        {
            Directory.CreateDirectory(lockDir);
        }
        catch
        {
            return null;
        }

        DateTime deadline = DateTime.UtcNow + (timeout ?? TimeSpan.FromSeconds(5));
        while (true)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                return new FileStream(lockPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.None);
            }
            catch (IOException)
            {
                if (DateTime.UtcNow >= deadline)
                {
                    return null;
                }
                await Task.Delay(25, ct);
            }
            catch
            {
                return null;
            }
        }
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
                if (ProcessInspectionHelper.IsCrashpadOrCrashReporterProcess(procFileName, commandLine))
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

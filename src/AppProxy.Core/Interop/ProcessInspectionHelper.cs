using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace AppProxy.UI.Interop;

public enum ProcessLiveState
{
    Alive,
    Exited,
    AccessDenied
}

public static class ProcessInspectionHelper
{
    private const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;
    private const uint SYNCHRONIZE = 0x00100000;
    private const uint WAIT_OBJECT_0 = 0x00000000;
    private const uint STILL_ACTIVE = 259;

    private const int ERROR_INVALID_PARAMETER = 87;
    private const int ERROR_INSUFFICIENT_BUFFER = 122;
    private const int ERROR_ACCESS_DENIED = 5;

    private const int ProcessCommandLineInformation = 60;
    private const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);
    private const int STATUS_BUFFER_TOO_SMALL = unchecked((int)0xC0000023);

    private static readonly HashSet<string> CrashReporterExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "crashpad_handler.exe",
        "werfault.exe",
        "werfaultsecure.exe",
        "wermgr.exe",
        "bssndrpt.exe",
        "bssndrpt64.exe"
    };

    private static readonly HashSet<string> PureInfraExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "conhost.exe",
        "openconsole.exe",
        "appproxy.injector.x64.exe",
        "appproxy.injector.x86.exe",
        "csrss.exe"
    };

    private static readonly HashSet<string> ShellOrWrapperExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "update.exe",
        "squirrel.exe",
        "rundll32.exe",
        "msiexec.exe",
        "bash.exe",
        "sh.exe",
        "wt.exe",
        "explorer.exe"
    };

    [StructLayout(LayoutKind.Sequential)]
    private struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct RECT
    {
        public int Left;
        public int Top;
        public int Right;
        public int Bottom;
    }

    private delegate bool EnumWindowsProc(IntPtr hwnd, IntPtr lParam);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetExitCodeProcess(IntPtr hProcess, out uint lpExitCode);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool QueryFullProcessImageNameW(
        IntPtr hProcess,
        uint dwFlags,
        [Out] char[] lpExeName,
        ref uint lpdwSize);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);

    [DllImport("ntdll.dll")]
    private static extern int NtQueryInformationProcess(
        IntPtr processHandle,
        int processInformationClass,
        IntPtr processInformation,
        uint processInformationLength,
        out uint returnLength);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumWindows(EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsWindowVisible(IntPtr hWnd);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool IsIconic(IntPtr hWnd);

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int GetClassNameW(IntPtr hWnd, [Out] char[] lpClassName, int nMaxCount);

    public static ProcessLiveState InspectProcess(
        uint pid,
        bool includeCommandLine,
        out string? imagePath,
        out string? commandLine)
    {
        imagePath = null;
        commandLine = null;
        if (pid == 0) return ProcessLiveState.Exited;

        IntPtr handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, false, pid);
        if (handle != IntPtr.Zero)
        {
            try
            {
                if (WaitForSingleObject(handle, 0) == WAIT_OBJECT_0)
                {
                    return ProcessLiveState.Exited;
                }

                imagePath = QueryProcessImagePath(handle);
                if (includeCommandLine)
                {
                    commandLine = TryGetCommandLine(handle);
                }
                return ProcessLiveState.Alive;
            }
            finally
            {
                CloseHandle(handle);
            }
        }

        int err = Marshal.GetLastWin32Error();
        if (err == ERROR_INVALID_PARAMETER)
        {
            return ProcessLiveState.Exited;
        }

        handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (handle != IntPtr.Zero)
        {
            try
            {
                if (GetExitCodeProcess(handle, out uint exitCode) && exitCode != STILL_ACTIVE)
                {
                    return ProcessLiveState.Exited;
                }

                imagePath = QueryProcessImagePath(handle);
                if (includeCommandLine)
                {
                    commandLine = TryGetCommandLine(handle);
                }
                return ProcessLiveState.Alive;
            }
            finally
            {
                CloseHandle(handle);
            }
        }

        int err2 = Marshal.GetLastWin32Error();
        return err2 == ERROR_ACCESS_DENIED ? ProcessLiveState.AccessDenied : ProcessLiveState.Exited;
    }

    public static string? TryGetCommandLine(uint pid)
    {
        if (pid == 0) return null;
        IntPtr handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (handle == IntPtr.Zero) return null;
        try
        {
            return TryGetCommandLine(handle);
        }
        finally
        {
            CloseHandle(handle);
        }
    }

    private static string? TryGetCommandLine(IntPtr hProcess)
    {
        try
        {
            uint capacity = 1024;
            for (int attempt = 0; attempt < 3; attempt++)
            {
                if (capacity > 262144u) return null;

                IntPtr buf = Marshal.AllocHGlobal((int)capacity);
                try
                {
                    int status = NtQueryInformationProcess(hProcess, ProcessCommandLineInformation, buf, capacity, out uint needed);
                    if (status == 0)
                    {
                        var us = Marshal.PtrToStructure<UNICODE_STRING>(buf);
                        if (us.Length == 0 || us.Buffer == IntPtr.Zero)
                        {
                            return string.Empty;
                        }

                        long bufStart = buf.ToInt64();
                        long bufEnd = bufStart + capacity;
                        long strStart = us.Buffer.ToInt64();
                        if (strStart < bufStart || strStart + us.Length > bufEnd)
                        {
                            return null;
                        }

                        return Marshal.PtrToStringUni(us.Buffer, us.Length / 2);
                    }

                    if ((status == STATUS_INFO_LENGTH_MISMATCH || status == STATUS_BUFFER_TOO_SMALL) && needed > capacity)
                    {
                        capacity = needed + 64u;
                        continue;
                    }

                    return null;
                }
                finally
                {
                    Marshal.FreeHGlobal(buf);
                }
            }
        }
        catch
        {
        }

        return null;
    }

    public static string? QueryProcessImagePath(IntPtr hProcess)
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

    public static bool IsCrashpadOrCrashReporterProcess(string? exeFileNameOrPath, string? commandLine)
    {
        if (!string.IsNullOrWhiteSpace(exeFileNameOrPath))
        {
            string fileName = Path.GetFileName(exeFileNameOrPath.Trim().Trim('"'));
            if (!string.IsNullOrEmpty(fileName) && CrashReporterExeNames.Contains(fileName))
            {
                return true;
            }
        }

        if (!string.IsNullOrWhiteSpace(commandLine))
        {
            return ContainsSwitchToken(commandLine, "--type=crashpad-handler") ||
                   ContainsSwitchToken(commandLine, "--type=crashpad") ||
                   ContainsSwitchToken(commandLine, "--type=crash-reporter");
        }

        return false;
    }

    public static bool IsPureInfrastructureProcess(string? exeFileNameOrPath, string? commandLine)
    {
        if (IsCrashpadOrCrashReporterProcess(exeFileNameOrPath, commandLine))
        {
            return true;
        }

        if (!string.IsNullOrWhiteSpace(exeFileNameOrPath))
        {
            string fileName = Path.GetFileName(exeFileNameOrPath.Trim().Trim('"'));
            if (!string.IsNullOrEmpty(fileName) && PureInfraExeNames.Contains(fileName))
            {
                return true;
            }
        }

        return false;
    }

    public static bool IsShellOrWrapperLauncherExe(string? exePath)
    {
        if (string.IsNullOrWhiteSpace(exePath)) return false;
        string fileName = Path.GetFileName(exePath.Trim().Trim('"'));
        return !string.IsNullOrEmpty(fileName) && ShellOrWrapperExeNames.Contains(fileName);
    }

    public static bool ContainsSwitchToken(string commandLine, string token)
    {
        if (string.IsNullOrEmpty(commandLine) || string.IsNullOrEmpty(token)) return false;

        int searchFrom = 0;
        while (searchFrom <= commandLine.Length - token.Length)
        {
            int idx = commandLine.IndexOf(token, searchFrom, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return false;

            bool validBefore = idx == 0 ||
                               char.IsWhiteSpace(commandLine[idx - 1]) ||
                               commandLine[idx - 1] == '"' ||
                               commandLine[idx - 1] == '\'';

            int endIdx = idx + token.Length;
            bool validAfter = endIdx >= commandLine.Length ||
                              char.IsWhiteSpace(commandLine[endIdx]) ||
                              commandLine[endIdx] == '"' ||
                              commandLine[endIdx] == '\'' ||
                              commandLine[endIdx] == '=';

            if (validBefore && validAfter)
            {
                return true;
            }

            searchFrom = idx + 1;
        }

        return false;
    }

    public static HashSet<uint> GetProcessIdsWithVisibleWindows(IReadOnlySet<uint> candidatePids)
    {
        var result = new HashSet<uint>();
        if (candidatePids.Count == 0) return result;

        char[] classBuf = new char[128];
        EnumWindows((hwnd, _) =>
        {
            if (!IsWindowVisible(hwnd))
            {
                return true;
            }

            GetWindowThreadProcessId(hwnd, out uint pid);
            if (pid == 0 || !candidatePids.Contains(pid))
            {
                return true;
            }

            if (!IsIconic(hwnd))
            {
                if (!GetWindowRect(hwnd, out RECT rect) ||
                    rect.Right <= rect.Left ||
                    rect.Bottom <= rect.Top)
                {
                    return true;
                }
            }

            int clsLen = GetClassNameW(hwnd, classBuf, classBuf.Length);
            if (clsLen > 0)
            {
                ReadOnlySpan<char> cls = classBuf.AsSpan(0, clsLen);
                if (cls.Equals("ConsoleWindowClass".AsSpan(), StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            result.Add(pid);
            return true;
        }, IntPtr.Zero);

        return result;
    }
}

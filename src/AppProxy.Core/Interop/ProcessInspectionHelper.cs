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
    private const uint PROCESS_QUERY_INFORMATION = 0x0400;
    private const uint PROCESS_VM_READ = 0x0010;
    private const uint SYNCHRONIZE = 0x00100000;
    private const uint WAIT_OBJECT_0 = 0x00000000;
    private const uint STILL_ACTIVE = 259;

    private const int ERROR_INVALID_PARAMETER = 87;
    private const int ERROR_INSUFFICIENT_BUFFER = 122;
    private const int ERROR_ACCESS_DENIED = 5;

    private const int ProcessBasicInformation = 0;
    private const int ProcessWow64Information = 26;
    private const int ProcessCommandLineInformation = 60;
    private const int STATUS_INFO_LENGTH_MISMATCH = unchecked((int)0xC0000004);
    private const int STATUS_BUFFER_TOO_SMALL = unchecked((int)0xC0000023);
    private const int MaxEnvBlockBytes = 131072;

    private static readonly HashSet<string> CrashReporterExeNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "crashpad_handler.exe",
        "werfault.exe",
        "werfaultsecure.exe",
        "wermgr.exe",
        "bssndrpt.exe",
        "bssndrpt64.exe"
    };

    private static readonly HashSet<string> ChromiumSubprocessTypes = new(StringComparer.OrdinalIgnoreCase)
    {
        "renderer",
        "gpu-process",
        "utility",
        "zygote",
        "broker",
        "ppapi",
        "ppapi-broker",
        "plugin",
        "plugin-zygote",
        "nacl-loader",
        "nacl-broker",
        "crashpad-handler",
        "crashpad",
        "crash-reporter",
        "watcher",
        "cloud-print-service",
        "sandbox",
        "service",
        "node",
        "electron-as-node"
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
    private struct PROCESS_BASIC_INFORMATION
    {
        public IntPtr ExitStatus;
        public IntPtr PebBaseAddress;
        public UIntPtr AffinityMask;
        public IntPtr BasePriority;
        public UIntPtr UniqueProcessId;
        public UIntPtr InheritedFromUniqueProcessId;
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
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool ReadProcessMemory(
        IntPtr hProcess,
        IntPtr lpBaseAddress,
        [Out] byte[] lpBuffer,
        UIntPtr nSize,
        out UIntPtr lpNumberOfBytesRead);

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

        string? procType = TryGetChromiumProcessType(commandLine);
        if (!string.IsNullOrEmpty(procType))
        {
            return string.Equals(procType, "crashpad-handler", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(procType, "crashpad", StringComparison.OrdinalIgnoreCase) ||
                   string.Equals(procType, "crash-reporter", StringComparison.OrdinalIgnoreCase);
        }

        return false;
    }

    public static string? TryGetChromiumProcessType(string? commandLine)
    {
        if (string.IsNullOrWhiteSpace(commandLine)) return null;

        const string prefix = "--type=";
        int searchFrom = 0;
        while (searchFrom <= commandLine.Length - prefix.Length)
        {
            int idx = commandLine.IndexOf(prefix, searchFrom, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return null;

            bool validBefore = idx == 0 ||
                               char.IsWhiteSpace(commandLine[idx - 1]) ||
                               commandLine[idx - 1] == '"' ||
                               commandLine[idx - 1] == '\'';
            if (!validBefore)
            {
                searchFrom = idx + 1;
                continue;
            }

            int valueStart = idx + prefix.Length;
            if (valueStart >= commandLine.Length)
            {
                return null;
            }

            char openQuote = idx > 0 && (commandLine[idx - 1] == '"' || commandLine[idx - 1] == '\'')
                ? commandLine[idx - 1]
                : '\0';

            int cursor = valueStart;
            if (openQuote == '\0' && (commandLine[cursor] == '"' || commandLine[cursor] == '\''))
            {
                openQuote = commandLine[cursor];
                cursor++;
                valueStart = cursor;
            }

            while (cursor < commandLine.Length)
            {
                char ch = commandLine[cursor];
                if (openQuote != '\0')
                {
                    if (ch == openQuote) break;
                }
                else if (char.IsWhiteSpace(ch) || ch == '"' || ch == '\'')
                {
                    break;
                }
                cursor++;
            }

            if (cursor > valueStart)
            {
                return commandLine.Substring(valueStart, cursor - valueStart);
            }

            searchFrom = idx + 1;
        }

        return null;
    }

    public static bool IsChromiumSubprocessType(string? processType) =>
        !string.IsNullOrWhiteSpace(processType) &&
        ChromiumSubprocessTypes.Contains(processType.Trim());

    public static bool IsChromiumSubprocess(string? commandLine) =>
        IsChromiumSubprocessType(TryGetChromiumProcessType(commandLine));

    public static bool IsElectronRunAsNodeEnabled(string? commandLine, string? electronRunAsNodeEnvValue)
    {
        if (!string.IsNullOrWhiteSpace(commandLine) &&
            ContainsSwitchToken(commandLine, "--ms-enable-electron-run-as-node"))
        {
            return true;
        }

        if (string.IsNullOrWhiteSpace(electronRunAsNodeEnvValue))
        {
            return false;
        }

        string trimmed = electronRunAsNodeEnvValue.Trim();
        return !string.Equals(trimmed, "0", StringComparison.OrdinalIgnoreCase) &&
               !string.Equals(trimmed, "false", StringComparison.OrdinalIgnoreCase) &&
               !string.Equals(trimmed, "off", StringComparison.OrdinalIgnoreCase) &&
               !string.Equals(trimmed, "no", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsElectronRunAsNodeProcess(uint pid, string? commandLine)
    {
        if (!string.IsNullOrWhiteSpace(commandLine) &&
            ContainsSwitchToken(commandLine, "--ms-enable-electron-run-as-node"))
        {
            return true;
        }

        string? envVal = TryGetEnvironmentVariable(pid, "ELECTRON_RUN_AS_NODE");
        return IsElectronRunAsNodeEnabled(null, envVal);
    }

    public static bool IsNonPrimaryHelperProcess(uint pid, string? exeFileNameOrPath, string? commandLine) =>
        IsCrashpadOrCrashReporterProcess(exeFileNameOrPath, commandLine) ||
        IsChromiumSubprocess(commandLine) ||
        IsElectronRunAsNodeProcess(pid, commandLine);

    public static string? TryGetEnvironmentVariable(uint pid, string variableName)
    {
        if (pid == 0 || string.IsNullOrWhiteSpace(variableName)) return null;

        IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
        if (hProcess == IntPtr.Zero) return null;

        try
        {
            ulong envPtr = TryGetRemoteEnvironmentAddress(hProcess);
            if (envPtr == 0) return null;

            using var ms = new MemoryStream(4096);
            byte[] chunk = new byte[4096];
            ulong cursor = envPtr;
            int total = 0;

            while (total < MaxEnvBlockBytes)
            {
                int pageRemaining = (int)(0x1000UL - (cursor & 0xFFFUL));
                int toRead = Math.Min(pageRemaining, Math.Min(chunk.Length, MaxEnvBlockBytes - total));
                if (toRead <= 0) break;

                if (!ReadProcessMemory(hProcess, new IntPtr(unchecked((long)cursor)), chunk, (UIntPtr)toRead, out UIntPtr bytesRead) ||
                    bytesRead.ToUInt64() == 0)
                {
                    break;
                }

                int got = (int)bytesRead.ToUInt64();
                ms.Write(chunk, 0, got);
                int prevTotal = total;
                total += got;
                cursor += (ulong)got;

                byte[] buf = ms.GetBuffer();
                int checkStart = Math.Max(0, ((prevTotal - 4) / 2) * 2);
                bool foundEnd = false;
                for (int i = checkStart; i + 3 < total; i += 2)
                {
                    if (buf[i] == 0 && buf[i + 1] == 0 && buf[i + 2] == 0 && buf[i + 3] == 0)
                    {
                        total = i + 2;
                        foundEnd = true;
                        break;
                    }
                }

                if (foundEnd) break;
            }

            int usableBytes = total & ~1;
            if (usableBytes <= 0) return null;

            string block = Encoding.Unicode.GetString(ms.GetBuffer(), 0, usableBytes);
            return ParseEnvironmentVariableFromBlock(block, variableName);
        }
        catch
        {
            return null;
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }

    internal static string? ParseEnvironmentVariableFromBlock(string envBlock, string variableName)
    {
        if (string.IsNullOrEmpty(envBlock) || string.IsNullOrWhiteSpace(variableName)) return null;

        foreach (string entry in envBlock.Split('\0'))
        {
            if (string.IsNullOrEmpty(entry)) continue;
            int eq = entry.IndexOf('=');
            if (eq <= 0) continue;

            if (entry.AsSpan(0, eq).Equals(variableName.AsSpan(), StringComparison.OrdinalIgnoreCase))
            {
                return entry.Substring(eq + 1);
            }
        }

        return null;
    }

    private static ulong TryGetRemoteEnvironmentAddress(IntPtr hProcess)
    {
        ulong wow64Peb = 0;
        IntPtr wow64Buf = Marshal.AllocHGlobal(IntPtr.Size);
        try
        {
            if (NtQueryInformationProcess(hProcess, ProcessWow64Information, wow64Buf, (uint)IntPtr.Size, out _) == 0)
            {
                wow64Peb = IntPtr.Size == 8
                    ? (ulong)Marshal.ReadInt64(wow64Buf)
                    : (uint)Marshal.ReadInt32(wow64Buf);
            }
        }
        finally
        {
            Marshal.FreeHGlobal(wow64Buf);
        }

        if (wow64Peb != 0)
        {
            byte[] ptr32 = new byte[4];
            if (!ReadProcessMemory(hProcess, new IntPtr(unchecked((long)(wow64Peb + 0x10UL))), ptr32, (UIntPtr)4, out UIntPtr r1) ||
                r1.ToUInt64() != 4)
            {
                return 0;
            }

            uint rtl32 = BitConverter.ToUInt32(ptr32, 0);
            if (rtl32 == 0) return 0;

            if (!ReadProcessMemory(hProcess, new IntPtr(unchecked((long)((ulong)rtl32 + 0x48UL))), ptr32, (UIntPtr)4, out UIntPtr r2) ||
                r2.ToUInt64() != 4)
            {
                return 0;
            }

            return BitConverter.ToUInt32(ptr32, 0);
        }

        int pbiSize = Marshal.SizeOf<PROCESS_BASIC_INFORMATION>();
        IntPtr pbiBuf = Marshal.AllocHGlobal(pbiSize);
        ulong pebBase;
        try
        {
            if (NtQueryInformationProcess(hProcess, ProcessBasicInformation, pbiBuf, (uint)pbiSize, out _) != 0)
            {
                return 0;
            }

            var pbi = Marshal.PtrToStructure<PROCESS_BASIC_INFORMATION>(pbiBuf);
            pebBase = unchecked((ulong)pbi.PebBaseAddress.ToInt64());
        }
        finally
        {
            Marshal.FreeHGlobal(pbiBuf);
        }

        if (pebBase == 0) return 0;

        if (Environment.Is64BitProcess)
        {
            byte[] ptr64 = new byte[8];
            if (!ReadProcessMemory(hProcess, new IntPtr(unchecked((long)(pebBase + 0x20UL))), ptr64, (UIntPtr)8, out UIntPtr r1) ||
                r1.ToUInt64() != 8)
            {
                return 0;
            }

            ulong rtl64 = BitConverter.ToUInt64(ptr64, 0);
            if (rtl64 == 0) return 0;

            if (!ReadProcessMemory(hProcess, new IntPtr(unchecked((long)(rtl64 + 0x80UL))), ptr64, (UIntPtr)8, out UIntPtr r2) ||
                r2.ToUInt64() != 8)
            {
                return 0;
            }

            return BitConverter.ToUInt64(ptr64, 0);
        }

        byte[] ptrNative32 = new byte[4];
        if (!ReadProcessMemory(hProcess, new IntPtr(unchecked((long)(pebBase + 0x10UL))), ptrNative32, (UIntPtr)4, out UIntPtr rn1) ||
            rn1.ToUInt64() != 4)
        {
            return 0;
        }

        uint rtlNative32 = BitConverter.ToUInt32(ptrNative32, 0);
        if (rtlNative32 == 0) return 0;

        if (!ReadProcessMemory(hProcess, new IntPtr(unchecked((long)((ulong)rtlNative32 + 0x48UL))), ptrNative32, (UIntPtr)4, out UIntPtr rn2) ||
            rn2.ToUInt64() != 4)
        {
            return 0;
        }

        return BitConverter.ToUInt32(ptrNative32, 0);
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

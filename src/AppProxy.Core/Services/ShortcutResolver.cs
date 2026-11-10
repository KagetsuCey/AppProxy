using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using AppProxy.UI.Models;

namespace AppProxy.UI.Services;

public sealed record ResolvedAppTarget(
    bool Ok,
    string DisplayName,
    string TargetExePath,
    string Arguments,
    string WorkingDirectory,
    string? Error = null);

public static class ShortcutResolver
{
    private static readonly Guid ClsidShellLink = new("00021401-0000-0000-C000-000000000046");

    private const uint STGM_READ = 0x00000000;
    private const uint SLGP_UNCPRIORITY = 0x0002;
    private const uint SLGP_RAWPATH = 0x0004;

    [ComImport]
    [Guid("000214F9-0000-0000-C000-000000000046")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IShellLinkW
    {
        void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszFile, int cch, IntPtr pfd, uint fFlags);
        void GetIDList(out IntPtr ppidl);
        void SetIDList(IntPtr pidl);
        void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszName, int cch);
        void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string pszName);
        void GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszDir, int cch);
        void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string pszDir);
        void GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszArgs, int cch);
        void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string pszArgs);
        void GetHotkey(out short pwHotkey);
        void SetHotkey(short wHotkey);
        void GetShowCmd(out int piShowCmd);
        void SetShowCmd(int iShowCmd);
        void GetIconLocation([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder pszIconPath, int cch, out int piIcon);
        void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string pszIconPath, int iIcon);
        void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string pszPathRel, uint dwReserved);
        void Resolve(IntPtr hwnd, uint fFlags);
        void SetPath([MarshalAs(UnmanagedType.LPWStr)] string pszFile);
    }

    [ComImport]
    [Guid("0000010b-0000-0000-C000-000000000046")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IPersistFile
    {
        void GetClassID(out Guid pClassID);
        [PreserveSig]
        int IsDirty();
        void Load([MarshalAs(UnmanagedType.LPWStr)] string pszFileName, uint dwMode);
        void Save([MarshalAs(UnmanagedType.LPWStr)] string? pszFileName, [MarshalAs(UnmanagedType.Bool)] bool fRemember);
        void SaveCompleted([MarshalAs(UnmanagedType.LPWStr)] string? pszFileName);
        void GetCurFile([MarshalAs(UnmanagedType.LPWStr)] out string ppszFileName);
    }

    public static ResolvedAppTarget ResolveInputPath(string inputPath)
    {
        if (string.IsNullOrWhiteSpace(inputPath) || !File.Exists(inputPath))
        {
            return new ResolvedAppTarget(false, string.Empty, string.Empty, string.Empty, string.Empty, "File does not exist.");
        }

        string ext = Path.GetExtension(inputPath);
        if (string.Equals(ext, ".exe", StringComparison.OrdinalIgnoreCase))
        {
            return new ResolvedAppTarget(
                Ok: true,
                DisplayName: Path.GetFileNameWithoutExtension(inputPath),
                TargetExePath: inputPath,
                Arguments: string.Empty,
                WorkingDirectory: Path.GetDirectoryName(inputPath) ?? string.Empty);
        }

        if (string.Equals(ext, ".lnk", StringComparison.OrdinalIgnoreCase))
        {
            return ResolveLnkShortcut(inputPath);
        }

        return new ResolvedAppTarget(
            false,
            string.Empty,
            string.Empty,
            string.Empty,
            string.Empty,
            "Please drop a valid .exe executable or .lnk shortcut.");
    }

    public static ResolvedAppTarget ResolveLnkShortcut(string lnkPath)
    {
        object? comObj = null;
        try
        {
            Type? shellLinkType = Type.GetTypeFromCLSID(ClsidShellLink);
            if (shellLinkType is null)
            {
                return new ResolvedAppTarget(false, string.Empty, string.Empty, string.Empty, string.Empty, "Windows ShellLink COM class unavailable.");
            }

            comObj = Activator.CreateInstance(shellLinkType);
            if (comObj is not IShellLinkW link || comObj is not IPersistFile persistFile)
            {
                return new ResolvedAppTarget(false, string.Empty, string.Empty, string.Empty, string.Empty, "Failed to query IShellLinkW/IPersistFile.");
            }

            persistFile.Load(lnkPath, STGM_READ);

            var pathBuf = new StringBuilder(1024);
            link.GetPath(pathBuf, pathBuf.Capacity, IntPtr.Zero, SLGP_RAWPATH);
            string rawTarget = pathBuf.ToString().Trim().Trim('"');

            if (string.IsNullOrWhiteSpace(rawTarget))
            {
                pathBuf.Clear();
                link.GetPath(pathBuf, pathBuf.Capacity, IntPtr.Zero, SLGP_UNCPRIORITY);
                rawTarget = pathBuf.ToString().Trim().Trim('"');
            }

            string targetExe = string.IsNullOrWhiteSpace(rawTarget)
                ? string.Empty
                : Environment.ExpandEnvironmentVariables(rawTarget);

            var argsBuf = new StringBuilder(2048);
            link.GetArguments(argsBuf, argsBuf.Capacity);
            string arguments = argsBuf.ToString().Trim();

            var dirBuf = new StringBuilder(1024);
            link.GetWorkingDirectory(dirBuf, dirBuf.Capacity);
            string workDir = string.IsNullOrWhiteSpace(dirBuf.ToString())
                ? string.Empty
                : Environment.ExpandEnvironmentVariables(dirBuf.ToString().Trim().Trim('"'));

            string displayName = Path.GetFileNameWithoutExtension(lnkPath);

            // Handle Squirrel / Electron Update.exe --processStart <App.exe> shortcuts
            if (!string.IsNullOrEmpty(targetExe) &&
                string.Equals(Path.GetFileName(targetExe), "Update.exe", StringComparison.OrdinalIgnoreCase))
            {
                TryResolveSquirrelTarget(ref targetExe, ref arguments, ref workDir);
            }

            if (string.IsNullOrWhiteSpace(targetExe) ||
                !targetExe.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                return new ResolvedAppTarget(
                    false,
                    displayName,
                    targetExe,
                    arguments,
                    workDir,
                    $"Shortcut '{Path.GetFileName(lnkPath)}' does not point to an .exe executable.");
            }

            if (!File.Exists(targetExe))
            {
                return new ResolvedAppTarget(
                    false,
                    displayName,
                    targetExe,
                    arguments,
                    workDir,
                    $"Shortcut target not found: {targetExe}");
            }

            if (string.IsNullOrWhiteSpace(workDir))
            {
                workDir = Path.GetDirectoryName(targetExe) ?? string.Empty;
            }

            return new ResolvedAppTarget(
                Ok: true,
                DisplayName: displayName,
                TargetExePath: targetExe,
                Arguments: arguments,
                WorkingDirectory: workDir);
        }
        catch (Exception ex)
        {
            return new ResolvedAppTarget(
                false,
                string.Empty,
                string.Empty,
                string.Empty,
                string.Empty,
                $"Failed to parse shortcut: {ex.Message}");
        }
        finally
        {
            if (comObj is not null && Marshal.IsComObject(comObj))
            {
                Marshal.ReleaseComObject(comObj);
            }
        }
    }

    private static void TryResolveSquirrelTarget(ref string targetExe, ref string arguments, ref string workDir)
    {
        const string token = "--processStart";
        int idx = arguments.IndexOf(token, StringComparison.OrdinalIgnoreCase);
        if (idx < 0) return;

        string rest = arguments[(idx + token.Length)..].TrimStart();
        if (string.IsNullOrEmpty(rest)) return;

        string exeName;
        if (rest.StartsWith('"'))
        {
            int endQuote = rest.IndexOf('"', 1);
            if (endQuote <= 1) return;
            exeName = rest[1..endQuote];
        }
        else
        {
            int space = rest.IndexOf(' ');
            exeName = space > 0 ? rest[..space] : rest;
        }

        if (!exeName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) return;

        string? rootDir = Path.GetDirectoryName(targetExe);
        if (string.IsNullOrEmpty(rootDir) || !Directory.Exists(rootDir)) return;

        string? resolvedAppExe = Directory.GetDirectories(rootDir, "app-*")
            .OrderByDescending(d => d, StringComparer.OrdinalIgnoreCase)
            .Select(d => Path.Combine(d, exeName))
            .FirstOrDefault(File.Exists);

        if (resolvedAppExe is null) return;

        string extractedArgs = string.Empty;
        const string startArgsToken = "--process-start-args";
        int argsIdx = arguments.IndexOf(startArgsToken, StringComparison.OrdinalIgnoreCase);
        if (argsIdx >= 0)
        {
            string argsRest = arguments[(argsIdx + startArgsToken.Length)..].TrimStart();
            if (argsRest.StartsWith('"'))
            {
                int endQ = argsRest.IndexOf('"', 1);
                if (endQ > 1) extractedArgs = argsRest[1..endQ];
            }
            else
            {
                extractedArgs = argsRest;
            }
        }

        if (string.IsNullOrWhiteSpace(workDir) ||
            string.Equals(workDir.TrimEnd('\\'), rootDir.TrimEnd('\\'), StringComparison.OrdinalIgnoreCase))
        {
            workDir = Path.GetDirectoryName(resolvedAppExe) ?? workDir;
        }

        targetExe = resolvedAppExe;
        arguments = extractedArgs;
    }

    public static string CreateAppDesktopShortcut(
        AppProfile app,
        string? customDesktopDir = null,
        string? customBaseDir = null)
    {
        ArgumentNullException.ThrowIfNull(app);

        string desktopDir = !string.IsNullOrWhiteSpace(customDesktopDir)
            ? customDesktopDir
            : Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
        if (string.IsNullOrWhiteSpace(desktopDir))
        {
            desktopDir = Environment.GetFolderPath(Environment.SpecialFolder.Desktop);
        }
        Directory.CreateDirectory(desktopDir);

        string baseDir = !string.IsNullOrWhiteSpace(customBaseDir)
            ? customBaseDir
            : AppContext.BaseDirectory;
        string bridgeExePath = Path.Combine(baseDir, "AppProxy.Bridge.exe");

        string rawName = !string.IsNullOrWhiteSpace(app.Name)
            ? app.Name
            : Path.GetFileNameWithoutExtension(app.ExePath);
        string safeName = SanitizeShortcutFileName(rawName);
        string shortcutPath = Path.Combine(desktopDir, $"{safeName} (AppProxy).lnk");

        object? comObj = null;
        try
        {
            Type shellLinkType = Type.GetTypeFromCLSID(ClsidShellLink)
                ?? throw new InvalidOperationException("Windows ShellLink COM class unavailable.");
            comObj = Activator.CreateInstance(shellLinkType)!;
            var link = (IShellLinkW)comObj;
            var persist = (IPersistFile)comObj;

            link.SetPath(bridgeExePath);
            link.SetArguments($"--launch-app-id {app.Id:D}");
            link.SetWorkingDirectory(baseDir);
            link.SetDescription($"通过 AppProxy 代理启动 {rawName}");

            if (!string.IsNullOrWhiteSpace(app.ExePath) && File.Exists(app.ExePath))
            {
                link.SetIconLocation(app.ExePath, 0);
            }

            persist.Save(shortcutPath, true);
            return shortcutPath;
        }
        finally
        {
            if (comObj is not null && Marshal.IsComObject(comObj))
            {
                Marshal.ReleaseComObject(comObj);
            }
        }
    }

    public static (string TargetPath, string Arguments, string WorkingDirectory, string IconPath, int IconIndex) InspectShortcutForTest(string lnkPath)
    {
        object? comObj = null;
        try
        {
            Type shellLinkType = Type.GetTypeFromCLSID(ClsidShellLink)
                ?? throw new InvalidOperationException("ShellLink COM class unavailable.");
            comObj = Activator.CreateInstance(shellLinkType)!;
            var link = (IShellLinkW)comObj;
            var persist = (IPersistFile)comObj;

            persist.Load(lnkPath, STGM_READ);

            var pathBuf = new StringBuilder(1024);
            link.GetPath(pathBuf, pathBuf.Capacity, IntPtr.Zero, SLGP_RAWPATH);

            var argsBuf = new StringBuilder(2048);
            link.GetArguments(argsBuf, argsBuf.Capacity);

            var dirBuf = new StringBuilder(1024);
            link.GetWorkingDirectory(dirBuf, dirBuf.Capacity);

            var iconBuf = new StringBuilder(1024);
            link.GetIconLocation(iconBuf, iconBuf.Capacity, out int iconIdx);

            return (pathBuf.ToString(), argsBuf.ToString(), dirBuf.ToString(), iconBuf.ToString(), iconIdx);
        }
        finally
        {
            if (comObj is not null && Marshal.IsComObject(comObj))
            {
                Marshal.ReleaseComObject(comObj);
            }
        }
    }

    private static string SanitizeShortcutFileName(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return "AppProxy App";
        char[] invalid = Path.GetInvalidFileNameChars();
        var sb = new StringBuilder(name.Length);
        foreach (char c in name.Trim())
        {
            sb.Append(Array.IndexOf(invalid, c) >= 0 ? '_' : c);
        }
        string cleaned = sb.ToString().Trim('.', ' ');
        return string.IsNullOrEmpty(cleaned) ? "AppProxy App" : cleaned;
    }

    public static void CreateShortcutForTest(string lnkPath, string targetExePath, string arguments = "", string workingDirectory = "")
    {
        object? comObj = null;
        try
        {
            Type shellLinkType = Type.GetTypeFromCLSID(ClsidShellLink)
                ?? throw new InvalidOperationException("ShellLink COM class unavailable.");
            comObj = Activator.CreateInstance(shellLinkType)!;
            var link = (IShellLinkW)comObj;
            var persist = (IPersistFile)comObj;

            link.SetPath(targetExePath);
            if (!string.IsNullOrEmpty(arguments))
            {
                link.SetArguments(arguments);
            }
            if (!string.IsNullOrEmpty(workingDirectory))
            {
                link.SetWorkingDirectory(workingDirectory);
            }
            persist.Save(lnkPath, true);
        }
        finally
        {
            if (comObj is not null && Marshal.IsComObject(comObj))
            {
                Marshal.ReleaseComObject(comObj);
            }
        }
    }
}

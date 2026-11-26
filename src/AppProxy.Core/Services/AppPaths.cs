using System.IO;
using System.Text;

namespace AppProxy.Core.Services;

public static class AppPaths
{
    public const string DataFolderName = "data";
    public const string ConfigFileName = "config.json";
    public const string ProfilesFolderName = "profiles";
    public const string LogsFolderName = "logs";
    public const string CoresFolderName = "cores";
    public const string NativeFolderName = "native";
    public const string BridgeExecutableName = "AppProxy.Bridge.exe";
    public const string XrayExecutableName = "xray.exe";
    public const string UiCrashLogFileName = "AppProxy.UI.crash.log";
    public const string BridgeCrashLogFileName = "AppProxy.Bridge.crash.log";

    public static string ResolveBaseDirectory(string? customBaseDir = null)
    {
        string raw = string.IsNullOrWhiteSpace(customBaseDir)
            ? AppContext.BaseDirectory
            : customBaseDir.Trim();
        return Path.TrimEndingDirectorySeparator(Path.GetFullPath(raw));
    }

    public static string GetDataDirectory(string? customBaseDir = null) =>
        Path.Combine(ResolveBaseDirectory(customBaseDir), DataFolderName);

    public static string GetConfigFilePath(string? customBaseDir = null) =>
        Path.Combine(GetDataDirectory(customBaseDir), ConfigFileName);

    public static string GetProfilesDirectory(string? customBaseDir = null) =>
        Path.Combine(GetDataDirectory(customBaseDir), ProfilesFolderName);

    public static string GetAppProfileDirectory(
        string? appName,
        string? exePath = null,
        string? customBaseDir = null)
    {
        string seedName = !string.IsNullOrWhiteSpace(appName)
            ? appName
            : Path.GetFileNameWithoutExtension(exePath) ?? string.Empty;
        string safeFolder = SanitizeDirectoryName(seedName);
        return Path.Combine(GetProfilesDirectory(customBaseDir), safeFolder);
    }

    public static string GetLogsDirectory(string? customBaseDir = null) =>
        Path.Combine(GetDataDirectory(customBaseDir), LogsFolderName);

    public static string GetCrashLogFilePath(
        string fileName = UiCrashLogFileName,
        string? customBaseDir = null)
    {
        string safeFileName = string.IsNullOrWhiteSpace(fileName)
            ? UiCrashLogFileName
            : Path.GetFileName(fileName.Trim());
        return Path.Combine(GetLogsDirectory(customBaseDir), safeFileName);
    }

    public static string GetNativeDirectory(string? customBaseDir = null) =>
        Path.Combine(ResolveBaseDirectory(customBaseDir), NativeFolderName);

    public static string GetBridgeExePath(string? customBaseDir = null) =>
        Path.Combine(ResolveBaseDirectory(customBaseDir), BridgeExecutableName);

    public static string GetCoresDirectory(string? customBaseDir = null) =>
        Path.Combine(GetDataDirectory(customBaseDir), CoresFolderName);

    public static string GetDefaultXrayExePath(string? customBaseDir = null) =>
        Path.Combine(GetCoresDirectory(customBaseDir), XrayExecutableName);

    public static string? ResolveXrayExePath(string? configuredPath, string? customBaseDir = null)
    {
        if (!string.IsNullOrWhiteSpace(configuredPath))
        {
            string trimmed = configuredPath.Trim().Trim('"');
            if (!string.IsNullOrWhiteSpace(trimmed))
            {
                string candidate = Path.IsPathRooted(trimmed)
                    ? Path.GetFullPath(trimmed)
                    : Path.GetFullPath(Path.Combine(ResolveBaseDirectory(customBaseDir), trimmed));
                return File.Exists(candidate) ? candidate : null;
            }
        }

        string defaultPath = GetDefaultXrayExePath(customBaseDir);
        return File.Exists(defaultPath) ? defaultPath : null;
    }

    public static string EnsureDataDirectoryExists(string? customBaseDir = null)
    {
        string dataDir = GetDataDirectory(customBaseDir);
        Directory.CreateDirectory(dataDir);
        return dataDir;
    }

    public static string SanitizeDirectoryName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return "DefaultApp";
        char[] invalid = Path.GetInvalidFileNameChars();
        var sb = new StringBuilder(name.Length);
        foreach (char c in name.Trim())
        {
            sb.Append(Array.IndexOf(invalid, c) >= 0 ? '_' : c);
        }
        string cleaned = sb.ToString().Trim('.', ' ');
        return string.IsNullOrEmpty(cleaned) ? "DefaultApp" : cleaned;
    }
}

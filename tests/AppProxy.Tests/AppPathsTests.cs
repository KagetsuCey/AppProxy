using System.IO;
using AppProxy.UI.Services;
using Xunit;

namespace AppProxy.Tests;

public class AppPathsTests
{
    [Fact]
    public void DataAndSubdirectories_ResolveUnderRelativeDataFolder()
    {
        string baseDir = @"D:\Portable\AppProxy\";

        Assert.Equal(@"D:\Portable\AppProxy", AppPaths.ResolveBaseDirectory(baseDir));
        Assert.Equal(@"D:\Portable\AppProxy\data", AppPaths.GetDataDirectory(baseDir));
        Assert.Equal(@"D:\Portable\AppProxy\data\config.json", AppPaths.GetConfigFilePath(baseDir));
        Assert.Equal(@"D:\Portable\AppProxy\data\profiles", AppPaths.GetProfilesDirectory(baseDir));
        Assert.Equal(@"D:\Portable\AppProxy\data\logs", AppPaths.GetLogsDirectory(baseDir));
        Assert.Equal(@"D:\Portable\AppProxy\data\logs\AppProxy.UI.crash.log", AppPaths.GetCrashLogFilePath(AppPaths.UiCrashLogFileName, baseDir));
        Assert.Equal(@"D:\Portable\AppProxy\data\logs\AppProxy.Bridge.crash.log", AppPaths.GetCrashLogFilePath(AppPaths.BridgeCrashLogFileName, baseDir));
        Assert.Equal(@"D:\Portable\AppProxy\native", AppPaths.GetNativeDirectory(baseDir));
        Assert.Equal(@"D:\Portable\AppProxy\AppProxy.Bridge.exe", AppPaths.GetBridgeExePath(baseDir));
    }

    [Fact]
    public void GetAppProfileDirectory_SanitizesInvalidCharactersAndHandlesEmptyNames()
    {
        string baseDir = @"D:\Portable\AppProxy";

        Assert.Equal(
            @"D:\Portable\AppProxy\data\profiles\Edge _ Work",
            AppPaths.GetAppProfileDirectory("Edge / Work", null, baseDir));

        Assert.Equal(
            @"D:\Portable\AppProxy\data\profiles\msedge",
            AppPaths.GetAppProfileDirectory("   ", @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe", baseDir));

        Assert.Equal(
            @"D:\Portable\AppProxy\data\profiles\DefaultApp",
            AppPaths.GetAppProfileDirectory("...", null, baseDir));
    }

    [Fact]
    public void EnsureDataDirectoryExists_CreatesDataFolderInBaseDirectory()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "AppProxyPathsTests_" + Guid.NewGuid().ToString("N"));
        try
        {
            string dataDir = AppPaths.EnsureDataDirectoryExists(tempDir);
            Assert.Equal(Path.Combine(tempDir, "data"), dataDir);
            Assert.True(Directory.Exists(dataDir));
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }
}

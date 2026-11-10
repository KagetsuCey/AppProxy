using System.IO;
using AppProxy.UI.Services;
using Xunit;

namespace AppProxy.Tests;

public class ShortcutResolverTests
{
    [Fact]
    public void ResolveInputPath_DirectExe_ReturnsNormalizedTarget()
    {
        string cmdExe = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        ResolvedAppTarget resolved = ShortcutResolver.ResolveInputPath(cmdExe);

        Assert.True(resolved.Ok);
        Assert.Equal("cmd", resolved.DisplayName);
        Assert.Equal(cmdExe, resolved.TargetExePath);
        Assert.Equal(string.Empty, resolved.Arguments);
        Assert.Equal(Environment.SystemDirectory, resolved.WorkingDirectory);
    }

    [Fact]
    public void ResolveLnkShortcut_ExtractsTargetArgumentsWorkingDirAndFriendlyName()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "AppProxyShortcutTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            string cmdExe = Path.Combine(Environment.SystemDirectory, "cmd.exe");
            string customWorkDir = Path.GetTempPath().TrimEnd('\\');
            string lnkPath = Path.Combine(tempDir, "My Custom Terminal.lnk");

            ShortcutResolver.CreateShortcutForTest(
                lnkPath,
                cmdExe,
                arguments: "/k echo hello",
                workingDirectory: customWorkDir);

            ResolvedAppTarget resolved = ShortcutResolver.ResolveInputPath(lnkPath);

            Assert.True(resolved.Ok, resolved.Error);
            Assert.Equal("My Custom Terminal", resolved.DisplayName);
            Assert.Equal(cmdExe, resolved.TargetExePath, ignoreCase: true);
            Assert.Equal("/k echo hello", resolved.Arguments);
            Assert.Equal(customWorkDir, resolved.WorkingDirectory, ignoreCase: true);
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    [Fact]
    public void ResolveLnkShortcut_SquirrelUpdateExe_ResolvesActualAppExecutable()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "AppProxySquirrelTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            string updateExe = Path.Combine(tempDir, "Update.exe");
            File.WriteAllBytes(updateExe, new byte[] { 0x4D, 0x5A });

            string appVersionDir = Path.Combine(tempDir, "app-1.2.3");
            Directory.CreateDirectory(appVersionDir);
            string realAppExe = Path.Combine(appVersionDir, "DemoElectron.exe");
            File.WriteAllBytes(realAppExe, new byte[] { 0x4D, 0x5A });

            string lnkPath = Path.Combine(tempDir, "DemoElectron.lnk");
            ShortcutResolver.CreateShortcutForTest(
                lnkPath,
                updateExe,
                arguments: "--processStart DemoElectron.exe --process-start-args \"--proxy-test\"",
                workingDirectory: tempDir);

            ResolvedAppTarget resolved = ShortcutResolver.ResolveInputPath(lnkPath);

            Assert.True(resolved.Ok, resolved.Error);
            Assert.Equal("DemoElectron", resolved.DisplayName);
            Assert.Equal(realAppExe, resolved.TargetExePath, ignoreCase: true);
            Assert.Equal("--proxy-test", resolved.Arguments);
            Assert.Equal(appVersionDir, resolved.WorkingDirectory, ignoreCase: true);
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    [Fact]
    public void ResolveInputPath_NonExecutableFileOrShortcutToTxt_ReturnsFailure()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "AppProxyShortcutInvalid_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            string txtFile = Path.Combine(tempDir, "readme.txt");
            File.WriteAllText(txtFile, "hello");

            ResolvedAppTarget directTxt = ShortcutResolver.ResolveInputPath(txtFile);
            Assert.False(directTxt.Ok);

            string lnkToTxt = Path.Combine(tempDir, "Readme Shortcut.lnk");
            ShortcutResolver.CreateShortcutForTest(lnkToTxt, txtFile);

            ResolvedAppTarget shortcutTxt = ShortcutResolver.ResolveInputPath(lnkToTxt);
            Assert.False(shortcutTxt.Ok);
            Assert.Contains(".exe", shortcutTxt.Error ?? string.Empty);
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

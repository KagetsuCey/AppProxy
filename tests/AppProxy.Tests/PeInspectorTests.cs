using System.IO;
using AppProxy.UI.Services;
using Xunit;

namespace AppProxy.Tests;

public class PeInspectorTests
{
    [Fact]
    public void DetectArchitecture_CurrentProcess_ReturnsValidArch()
    {
        string? exe = Environment.ProcessPath;
        Assert.False(string.IsNullOrEmpty(exe));
        string arch = PeInspector.DetectArchitecture(exe!);
        Assert.Equal(Environment.Is64BitProcess ? "x64" : "x86", arch);
    }

    [Fact]
    public void DetectArchitecture_NativeInjectorsIfBuilt_MatchesExpected()
    {
        string repoRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
        string x64Inj = Path.Combine(repoRoot, "artifacts", "bin", "x64", "Release", "AppProxy.Injector.x64.exe");
        string x86Inj = Path.Combine(repoRoot, "artifacts", "bin", "Win32", "Release", "AppProxy.Injector.x86.exe");

        if (File.Exists(x64Inj))
        {
            Assert.Equal("x64", PeInspector.DetectArchitecture(x64Inj));
        }
        if (File.Exists(x86Inj))
        {
            Assert.Equal("x86", PeInspector.DetectArchitecture(x86Inj));
        }
    }
}

using System.IO;
using System.Reflection;
using System.Text.Json;
using AppProxy.Core.Models;
using AppProxy.Core.Services;
using AppProxy.UI.Services;
using Xunit;

namespace AppProxy.Tests;

public class PeInspectorTests
{
    private static readonly HashSet<string> WpfAssemblyNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "PresentationFramework",
        "PresentationCore",
        "WindowsBase",
        "System.Windows.Presentation"
    };

    [Fact]
    public void DetectArchitecture_CurrentProcess_ReturnsValidArch()
    {
        string? exe = Environment.ProcessPath;
        Assert.False(string.IsNullOrEmpty(exe));
        string coreArch = PeArchitectureDetector.DetectArchitecture(exe!);
        string uiArch = PeInspector.DetectArchitecture(exe!);
        Assert.Equal(Environment.Is64BitProcess ? "x64" : "x86", coreArch);
        Assert.Equal(coreArch, uiArch);
    }

    [Fact]
    public void DetectArchitecture_NativeInjectorsIfBuilt_MatchesExpected()
    {
        string repoRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
        string x64Inj = Path.Combine(repoRoot, "artifacts", "bin", "x64", "Release", "AppProxy.Injector.x64.exe");
        string x86Inj = Path.Combine(repoRoot, "artifacts", "bin", "Win32", "Release", "AppProxy.Injector.x86.exe");

        if (File.Exists(x64Inj))
        {
            Assert.Equal("x64", PeArchitectureDetector.DetectArchitecture(x64Inj));
            Assert.Equal("x64", PeInspector.DetectArchitecture(x64Inj));
        }
        if (File.Exists(x86Inj))
        {
            Assert.Equal("x86", PeArchitectureDetector.DetectArchitecture(x86Inj));
            Assert.Equal("x86", PeInspector.DetectArchitecture(x86Inj));
        }
    }

    [Fact]
    public void CoreAndBridge_AreDecoupledFromWpfAssemblies()
    {
        Assembly coreAsm = typeof(AppProfile).Assembly;
        string[] coreWpfRefs = coreAsm.GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty)
            .Where(name => WpfAssemblyNames.Contains(name))
            .ToArray();
        Assert.Empty(coreWpfRefs);

        string bridgeRuntimeConfig = Path.Combine(AppContext.BaseDirectory, "AppProxy.Bridge.runtimeconfig.json");
        if (File.Exists(bridgeRuntimeConfig))
        {
            string json = File.ReadAllText(bridgeRuntimeConfig);
            Assert.DoesNotContain("Microsoft.WindowsDesktop.App", json, StringComparison.OrdinalIgnoreCase);

            using JsonDocument doc = JsonDocument.Parse(json);
            JsonElement runtimeOptions = doc.RootElement.GetProperty("runtimeOptions");
            Assert.True(runtimeOptions.TryGetProperty("framework", out JsonElement framework));
            Assert.Equal("Microsoft.NETCore.App", framework.GetProperty("name").GetString());
        }
    }
}

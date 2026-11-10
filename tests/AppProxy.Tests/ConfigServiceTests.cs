using System.IO;
using AppProxy.UI.Models;
using AppProxy.UI.Services;
using Xunit;

namespace AppProxy.Tests;

public class ConfigServiceTests
{
    [Fact]
    public void DefaultConstructor_UsesExecutableSiblingConfigJson()
    {
        var service = new ConfigService();
        string expected = Path.Combine(AppContext.BaseDirectory, "config.json");
        Assert.Equal(expected, service.ConfigPath);
    }

    [Fact]
    public void SaveAndLoad_RoundTripsConfigurationInTargetDirectory()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "AppProxyTests_" + Guid.NewGuid().ToString("N"));
        string configFile = Path.Combine(tempDir, "config.json");

        try
        {
            var service = new ConfigService(configFile);
            var proxy = new ProxyProfile
            {
                Name = "Test SOCKS5",
                Protocol = ProxyProtocol.Socks5,
                Host = "127.0.0.1",
                Port = 10808,
                Username = "u1",
                Password = "p1"
            };
            var app = new AppProfile
            {
                Name = "curl",
                ExePath = @"C:\Windows\System32\curl.exe",
                Arguments = "https://example.com",
                ProxyProfileId = proxy.Id,
                RemoteDns = true,
                BypassLan = true,
                InjectChildren = false
            };

            var cfg = new AppConfig
            {
                IsDarkTheme = false,
                TestProbeHost = "example.org",
                TestProbePort = 443,
                Proxies = new List<ProxyProfile> { proxy },
                Apps = new List<AppProfile> { app }
            };

            service.Save(cfg);
            Assert.True(File.Exists(configFile));

            AppConfig loaded = service.Load();
            Assert.False(loaded.IsDarkTheme);
            Assert.Equal("example.org", loaded.TestProbeHost);
            Assert.Equal(443, loaded.TestProbePort);
            Assert.Single(loaded.Proxies);
            Assert.Equal("Test SOCKS5", loaded.Proxies[0].Name);
            Assert.Equal(10808, loaded.Proxies[0].Port);
            Assert.Single(loaded.Apps);
            Assert.Equal("curl", loaded.Apps[0].Name);
            Assert.Equal(proxy.Id, loaded.Apps[0].ProxyProfileId);
            Assert.False(loaded.Apps[0].InjectChildren);
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

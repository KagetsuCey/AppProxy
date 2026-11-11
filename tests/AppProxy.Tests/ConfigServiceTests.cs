using System.IO;
using AppProxy.UI.Models;
using AppProxy.UI.Services;
using Xunit;

namespace AppProxy.Tests;

public class ConfigServiceTests
{
    [Fact]
    public void DefaultConstructor_UsesAppRelativeDataConfigJson()
    {
        var service = new ConfigService();
        string expected = Path.Combine(
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(AppContext.BaseDirectory)),
            "data",
            "config.json");
        Assert.Equal(expected, service.ConfigPath);
    }

    [Fact]
    public void Load_IgnoresLegacyRootConfigJson_InParentBaseDirectory()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "AppProxyLegacyIgnoreTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        try
        {
            string legacyConfigPath = Path.Combine(tempDir, "config.json");
            File.WriteAllText(legacyConfigPath, """
                {
                  "IsDarkTheme": false,
                  "TestProbeHost": "legacy.example.com",
                  "TestProbePort": 8443,
                  "Proxies": [],
                  "Apps": []
                }
                """);

            string newConfigPath = AppPaths.GetConfigFilePath(tempDir);
            var service = new ConfigService(newConfigPath);
            AppConfig loaded = service.Load();

            Assert.True(loaded.IsDarkTheme);
            Assert.Equal("www.gstatic.com", loaded.TestProbeHost);
            Assert.Equal(80, loaded.TestProbePort);
            Assert.NotEmpty(loaded.Proxies);
            Assert.False(File.Exists(newConfigPath));
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

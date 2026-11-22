using System.IO;
using AppProxy.Core.Models;
using AppProxy.Core.Services;
using AppProxy.UI.ViewModels;
using Xunit;

namespace AppProxy.Tests;

public class ProxyProfileTests
{
    [Fact]
    public void LatencyDisplay_NotifiesAndUpdates_WhenIsTestingCompletes()
    {
        var profile = new ProxyProfile
        {
            Name = "JP",
            Protocol = ProxyProtocol.Https,
            Host = "jp.exfantasy.com",
            Port = 9999
        };

        var changedProperties = new List<string?>();
        profile.PropertyChanged += (_, e) => changedProperties.Add(e.PropertyName);

        profile.IsTesting = true;
        profile.LastLatencyMs = null;
        profile.LastTestStatus = "Testing...";
        Assert.Equal("Testing...", profile.LatencyDisplay);

        profile.LastLatencyMs = 84;
        profile.LastTestStatus = "OK";
        Assert.Equal("Testing...", profile.LatencyDisplay);

        changedProperties.Clear();
        profile.IsTesting = false;

        Assert.Contains(nameof(ProxyProfile.LatencyDisplay), changedProperties);
        Assert.Equal("84 ms", profile.LatencyDisplay);
    }

    [Fact]
    public void CreateDuplicate_GeneratesNewIdCopiesFieldsAndResetsTestState()
    {
        var source = new ProxyProfile
        {
            Name = "HK Node",
            Protocol = ProxyProtocol.Socks5,
            Host = "hk.example.com",
            Port = 10808,
            Username = "alice",
            Password = "secret",
            LastLatencyMs = 45,
            LastTestStatus = "OK",
            IsTesting = true
        };

        ProxyProfile duplicate = source.CreateDuplicate(new[] { source.Name });

        Assert.NotEqual(source.Id, duplicate.Id);
        Assert.Equal("HK Node (副本)", duplicate.Name);
        Assert.Equal(source.Protocol, duplicate.Protocol);
        Assert.Equal(source.Host, duplicate.Host);
        Assert.Equal(source.Port, duplicate.Port);
        Assert.Equal(source.Username, duplicate.Username);
        Assert.Equal(source.Password, duplicate.Password);
        Assert.Null(duplicate.LastLatencyMs);
        Assert.Equal("Untested", duplicate.LastTestStatus);
        Assert.False(duplicate.IsTesting);

        // Mutating the duplicate must not affect the source profile
        duplicate.Port = 10809;
        duplicate.Name = "HK Node 2";
        Assert.Equal(10808, source.Port);
        Assert.Equal("HK Node", source.Name);
    }

    [Fact]
    public void BuildDuplicateName_AvoidsCollisionsAndDoesNotStackCopySuffixes()
    {
        Assert.Equal("JP (副本)", ProxyProfile.BuildDuplicateName("JP", new[] { "JP" }));
        Assert.Equal("JP (副本 2)", ProxyProfile.BuildDuplicateName("JP", new[] { "JP", "JP (副本)" }));
        Assert.Equal("JP (副本 3)", ProxyProfile.BuildDuplicateName("JP (副本)", new[] { "JP", "JP (副本)", "JP (副本 2)" }));
        Assert.Equal("JP (副本 2)", ProxyProfile.BuildDuplicateName("JP (副本 5)", new[] { "JP", "jp (副本)" }));
        Assert.Equal("Proxy (副本)", ProxyProfile.BuildDuplicateName("   "));
    }

    [Fact]
    public async Task MainViewModel_CloneProxyDraftAndInsert_InsertsAfterSourceWithoutAffectingBindings()
    {
        string configPath = AppPaths.GetConfigFilePath();
        string? originalConfig = File.Exists(configPath) ? File.ReadAllText(configPath) : null;

        Exception? threadEx = null;
        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var staThread = new Thread(() =>
        {
            try
            {
                using var vm = new MainViewModel();
                vm.Proxies.Clear();
                vm.Apps.Clear();

                var p1 = new ProxyProfile { Name = "NodeA", Protocol = ProxyProtocol.Socks5, Host = "1.2.3.4", Port = 1080, Username = "u", Password = "p" };
                var p2 = new ProxyProfile { Name = "NodeB", Protocol = ProxyProtocol.Http, Host = "5.6.7.8", Port = 8080 };
                vm.Proxies.Add(p1);
                vm.Proxies.Add(p2);

                var app = new AppProfile { Name = "TestApp", ExePath = @"C:\test.exe", ProxyProfileId = p1.Id };
                vm.SyncAppBoundProxyName(app);
                vm.Apps.Add(app);

                ProxyProfile draft = vm.CreateClonedProxyDraft(p1);
                Assert.NotEqual(p1.Id, draft.Id);
                Assert.Equal("NodeA (副本)", draft.Name);

                vm.AddOrUpdateProxy(draft, insertAfterIndex: 0);

                Assert.Equal(3, vm.Proxies.Count);
                Assert.Equal(p1.Id, vm.Proxies[0].Id);
                Assert.Equal(draft.Id, vm.Proxies[1].Id);
                Assert.Equal(p2.Id, vm.Proxies[2].Id);
                Assert.Equal(p1.Id, app.ProxyProfileId);
                Assert.Equal("NodeA", app.BoundProxyName);
            }
            catch (Exception ex)
            {
                threadEx = ex;
            }
            finally
            {
                tcs.TrySetResult();
            }
        });

        try
        {
            staThread.SetApartmentState(ApartmentState.STA);
            staThread.Start();
            await tcs.Task.WaitAsync(TimeSpan.FromSeconds(15));
            staThread.Join(3000);
            if (threadEx is not null) throw threadEx;
        }
        finally
        {
            try
            {
                if (originalConfig is not null)
                {
                    File.WriteAllText(configPath, originalConfig);
                }
                else if (File.Exists(configPath))
                {
                    File.Delete(configPath);
                }
            }
            catch
            {
            }
        }
    }
}

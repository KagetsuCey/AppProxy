using AppProxy.UI.Models;
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
}

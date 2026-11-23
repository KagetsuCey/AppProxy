using System.Buffers.Binary;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using AppProxy.Core.Models;
using AppProxy.Core.Services;
using Xunit;

namespace AppProxy.Tests;

public class TunBypassTests
{
    [Fact]
    public void IsVirtualOrTunAdapter_And_IsTunOrVpnAdapter_ClassifyAdaptersCorrectly()
    {
        Assert.True(PhysicalNetworkSelector.IsVirtualOrTunAdapter(
            (NetworkInterfaceType)53, "singbox_tun", "sing-tun Tunnel"));
        Assert.True(PhysicalNetworkSelector.IsTunOrVpnAdapter(
            (NetworkInterfaceType)53, "singbox_tun", "sing-tun Tunnel"));

        Assert.True(PhysicalNetworkSelector.IsVirtualOrTunAdapter(
            NetworkInterfaceType.Ethernet, "Clash", "Clash Meta Wintun Adapter"));
        Assert.True(PhysicalNetworkSelector.IsTunOrVpnAdapter(
            NetworkInterfaceType.Ethernet, "Clash", "Clash Meta Wintun Adapter"));

        Assert.True(PhysicalNetworkSelector.IsVirtualOrTunAdapter(
            NetworkInterfaceType.Ethernet, "本地连接", "TAP-Windows Adapter V9"));
        Assert.True(PhysicalNetworkSelector.IsTunOrVpnAdapter(
            NetworkInterfaceType.Ethernet, "本地连接", "TAP-Windows Adapter V9"));

        // Hyper-V / WSL / Bluetooth are virtual (excluded as physical outbound), not TUN/VPN proxies
        Assert.True(PhysicalNetworkSelector.IsVirtualOrTunAdapter(
            NetworkInterfaceType.Ethernet, "vEthernet (WSL)", "Hyper-V Virtual Ethernet Adapter"));
        Assert.False(PhysicalNetworkSelector.IsTunOrVpnAdapter(
            NetworkInterfaceType.Ethernet, "vEthernet (WSL)", "Hyper-V Virtual Ethernet Adapter"));

        // Real physical adapters
        Assert.False(PhysicalNetworkSelector.IsVirtualOrTunAdapter(
            NetworkInterfaceType.Ethernet, "以太网", "Realtek Gaming 2.5GbE Family Controller"));
        Assert.False(PhysicalNetworkSelector.IsVirtualOrTunAdapter(
            NetworkInterfaceType.Wireless80211, "WLAN", "Intel(R) Wi-Fi 6 AX201 160MHz"));
    }

    [Fact]
    public void PhysicalDnsResolver_BuildAndParseDnsPacket_HandlesCompressionAndRecords()
    {
        byte[] query = PhysicalDnsResolver.BuildDnsQueryPacket("proxy.example.com", qtype: 1, txId: 0x1234);
        Assert.True(query.Length > 12);
        Assert.Equal(0x12, query[0]);
        Assert.Equal(0x34, query[1]);

        // Craft a minimal valid DNS response with a compressed name pointer (0xC00C) -> 103.24.219.166 (TTL=120)
        // plus a Fake-IP answer 198.18.0.10 that must be filtered out.
        byte[] resp =
        [
            0x12, 0x34, // TxID
            0x81, 0x80, // Standard response, NOERROR
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x02, // ANCOUNT = 2
            0x00, 0x00, // NSCOUNT = 0
            0x00, 0x00, // ARCOUNT = 0
            // Question: proxy.example.com (starts at offset 12 = 0x0C)
            5, (byte)'p', (byte)'r', (byte)'o', (byte)'x', (byte)'y',
            7, (byte)'e', (byte)'x', (byte)'a', (byte)'m', (byte)'p', (byte)'l', (byte)'e',
            3, (byte)'c', (byte)'o', (byte)'m',
            0,
            0x00, 0x01, // QTYPE = A
            0x00, 0x01, // QCLASS = IN
            // Answer 1: compressed name 0xC00C, A, IN, TTL=120, 103.24.219.166
            0xC0, 0x0C,
            0x00, 0x01,
            0x00, 0x01,
            0x00, 0x00, 0x00, 0x78,
            0x00, 0x04,
            103, 24, 219, 166,
            // Answer 2: Fake-IP 198.18.0.10 (must be stripped)
            0xC0, 0x0C,
            0x00, 0x01,
            0x00, 0x01,
            0x00, 0x00, 0x00, 0x3C,
            0x00, 0x04,
            198, 18, 0, 10
        ];

        var (addrs, minTtl) = PhysicalDnsResolver.ParseDnsResponsePacket(resp, 0x1234);
        Assert.Single(addrs);
        Assert.Equal(IPAddress.Parse("103.24.219.166"), addrs[0]);
        Assert.Equal(120, minTtl);

        Assert.True(PhysicalDnsResolver.IsFakeIp(IPAddress.Parse("198.18.0.1")));
        Assert.True(PhysicalDnsResolver.IsFakeIp(IPAddress.Parse("198.19.255.254")));
        Assert.True(PhysicalDnsResolver.IsFakeIp(IPAddress.Parse("fd98:18::c612:1")));
        Assert.False(PhysicalDnsResolver.IsFakeIp(IPAddress.Parse("103.24.219.166")));
    }

    [Fact]
    public async Task OutboundSocketConnector_LoopbackTarget_ConnectsCleanlyWithBypassEnabled()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        int port = ((IPEndPoint)listener.LocalEndpoint).Port;

        Task acceptTask = listener.AcceptTcpClientAsync(cts.Token).AsTask();
        using TcpClient client = await OutboundSocketConnector.ConnectAsync(
            "127.0.0.1",
            port,
            IPAddress.Loopback,
            bypassGlobalTun: true,
            preferredInterface: null,
            cts.Token);

        Assert.True(client.Connected);
        using TcpClient server = (TcpClient)await ((Task<TcpClient>)acceptTask);
        Assert.True(server.Connected);
    }

    [Fact]
    public void ConfigAndBridgeIpc_BypassGlobalTun_DefaultsTrueForLegacyJson_AndRoundTrips()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "AppProxyTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        string cfgPath = Path.Combine(tempDir, "config.json");

        try
        {
            // Legacy JSON without BypassGlobalTun / PreferredOutboundInterface
            File.WriteAllText(cfgPath, """
                {
                  "IsDarkTheme": true,
                  "Proxies": [],
                  "Apps": []
                }
                """);

            var svc = new ConfigService(cfgPath);
            AppConfig loaded = svc.Load();
            Assert.True(loaded.BypassGlobalTun);
            Assert.Null(loaded.PreferredOutboundInterface);

            loaded.BypassGlobalTun = false;
            loaded.PreferredOutboundInterface = "{TEST-NIC-ID}";
            svc.Save(loaded);

            AppConfig reloaded = svc.Load();
            Assert.False(reloaded.BypassGlobalTun);
            Assert.Equal("{TEST-NIC-ID}", reloaded.PreferredOutboundInterface);

            var req = new BridgeLaunchRequest
            {
                AppName = "Demo",
                ExePath = @"C:\Windows\System32\cmd.exe",
                BypassGlobalTun = false,
                PreferredOutboundInterface = "{TEST-NIC-ID}"
            };
            string b64 = BridgeIpcCodec.EncodeLaunchRequestBase64(req);
            BridgeLaunchRequest? decoded = BridgeIpcCodec.DecodeLaunchRequestBase64(b64);
            Assert.NotNull(decoded);
            Assert.False(decoded!.BypassGlobalTun);
            Assert.Equal("{TEST-NIC-ID}", decoded.PreferredOutboundInterface);
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
    public void PhysicalNetworkSelector_AutoDetectsPhysicalInterface_AndExcludesTun()
    {
        long epochBefore = PhysicalNetworkSelector.NetworkEpoch;
        PhysicalNetworkSelector.InvalidateCache();
        Assert.True(PhysicalNetworkSelector.NetworkEpoch > epochBefore);

        IReadOnlyList<OutboundInterfaceInfo> candidates = PhysicalNetworkSelector.ResolveOutboundCandidates();
        foreach (OutboundInterfaceInfo nic in candidates)
        {
            Assert.False(nic.IsVirtualOrTun);
            Assert.False(nic.IsTunOrVpn);
            Assert.True(nic.HasAnyUsableRoute);
        }
    }

    [Fact]
    public void PhysicalNetworkSelector_UnpluggedPreferredInterface_FailsOverToHealthyPhysicalCandidate()
    {
        IReadOnlyList<OutboundInterfaceInfo> autoCandidates = PhysicalNetworkSelector.ResolveOutboundCandidates();
        IReadOnlyList<OutboundInterfaceInfo> failoverCandidates =
            PhysicalNetworkSelector.ResolveOutboundCandidates("{DISCONNECTED-UNPLUGGED-NIC-GUID}");

        Assert.Equal(autoCandidates.Select(c => c.Id), failoverCandidates.Select(c => c.Id));
    }
}

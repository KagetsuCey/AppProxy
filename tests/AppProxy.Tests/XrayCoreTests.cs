using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using AppProxy.Core.Models;
using AppProxy.Core.Services;
using Xunit;

namespace AppProxy.Tests;

public class XrayCoreTests
{
    [Fact]
    public void Parse_VlessRealityUri_ParsesAllParametersAndRoundTrips()
    {
        const string realityUri =
            "vless://6611d690-5e50-403e-9a90-e1877a69e350@cat.vanitas.top:8443" +
            "?encryption=none&security=reality&sni=www.hsbc.hk&fp=chrome" +
            "&pbk=UunraCjhfc38MvRAjw_TdUlEL4_o_nYWxIkYbnMAIV8" +
            "&sid=7f86960c6a3cfc&spx=%2F150628bbe37dd65&type=tcp&headerType=none#CAT";

        const string visionWsTlsGrpcInput =
            realityUri + "\n" +
            "vless://11111111-2222-3333-4444-555555555555@ws.example.com:443?encryption=none&security=tls&sni=cdn.example.com&fp=firefox&alpn=h2%2Chttp%2F1.1&allowInsecure=1&type=ws&path=%2Fray&host=cdn.example.com#WSNode\n" +
            "vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@[2001:db8::1]:8443?encryption=none&security=reality&sni=www.apple.com&pbk=PUBKEY&type=grpc&serviceName=gun&mode=multi&flow=xtls-rprx-vision#GRPCNode";

        ProxyBatchParseResult parsed = ProxyBatchParser.Parse(visionWsTlsGrpcInput, ProxyProtocol.Socks5, allowXrayProtocols: true);

        Assert.Empty(parsed.Errors);
        Assert.Equal(3, parsed.Proxies.Count);

        ProxyProfile p0 = parsed.Proxies[0];
        Assert.Equal(ProxyProtocol.Vless, p0.Protocol);
        Assert.Equal("VLESS", p0.ProtocolDisplay);
        Assert.Equal("REALITY", p0.SecurityBadgeText);
        Assert.True(p0.RequiresXrayCore);
        Assert.Equal("CAT", p0.Name);
        Assert.Equal("cat.vanitas.top", p0.Host);
        Assert.Equal(8443, p0.Port);
        Assert.NotNull(p0.Vless);
        Assert.Equal("6611d690-5e50-403e-9a90-e1877a69e350", p0.Vless!.Uuid);
        Assert.Equal("none", p0.Vless.Encryption);
        Assert.Equal("reality", p0.Vless.Security);
        Assert.Equal("www.hsbc.hk", p0.Vless.Sni);
        Assert.Equal("chrome", p0.Vless.Fingerprint);
        Assert.Equal("UunraCjhfc38MvRAjw_TdUlEL4_o_nYWxIkYbnMAIV8", p0.Vless.PublicKey);
        Assert.Equal("7f86960c6a3cfc", p0.Vless.ShortId);
        Assert.Equal("/150628bbe37dd65", p0.Vless.SpiderX);
        Assert.Equal("tcp", p0.Vless.Network);
        Assert.Equal("none", p0.Vless.HeaderType);

        ProxyProfile p1 = parsed.Proxies[1];
        Assert.Equal("TLS", p1.SecurityBadgeText);
        Assert.Equal("ws", p1.Vless!.Network);
        Assert.Equal("/ray", p1.Vless.Path);
        Assert.Equal("cdn.example.com", p1.Vless.HostHeader);
        Assert.Equal("h2,http/1.1", p1.Vless.Alpn);
        Assert.True(p1.Vless.AllowInsecure);

        ProxyProfile p2 = parsed.Proxies[2];
        Assert.Equal("2001:db8::1", p2.Host);
        Assert.Equal("grpc", p2.Vless!.Network);
        Assert.Equal("gun", p2.Vless.ServiceName);
        Assert.Equal("multi", p2.Vless.Mode);
        Assert.Equal("xtls-rprx-vision", p2.Vless.Flow);

        string exportedUris = ProxyBatchParser.ExportToUriLines(parsed.Proxies);
        ProxyBatchParseResult reparsedUris = ProxyBatchParser.Parse(exportedUris, allowXrayProtocols: true);
        Assert.Empty(reparsedUris.Errors);
        Assert.Equal(3, reparsedUris.Proxies.Count);
        Assert.Equal(ProxyBatchParser.BuildDedupeKey(p0), ProxyBatchParser.BuildDedupeKey(reparsedUris.Proxies[0]));
        Assert.Equal(p0.Vless.SpiderX, reparsedUris.Proxies[0].Vless!.SpiderX);
        Assert.Equal(p0.Name, reparsedUris.Proxies[0].Name);

        string exportedJson = ProxyBatchParser.ExportToJson(parsed.Proxies);
        ProxyBatchParseResult reparsedJson = ProxyBatchParser.Parse(exportedJson, allowXrayProtocols: true);
        Assert.Empty(reparsedJson.Errors);
        Assert.Equal(3, reparsedJson.Proxies.Count);
        Assert.Equal(p0.Vless.PublicKey, reparsedJson.Proxies[0].Vless!.PublicKey);
        Assert.Equal(p1.Vless.AllowInsecure, reparsedJson.Proxies[1].Vless!.AllowInsecure);
    }

    [Fact]
    public void Parse_VlessDisallowedWhenXrayUnconfigured_RejectsWithHint()
    {
        const string input =
            "vless://6611d690-5e50-403e-9a90-e1877a69e350@cat.vanitas.top:8443?security=reality&sni=www.hsbc.hk&pbk=ABC#CAT\n" +
            "socks5://127.0.0.1:1080#LocalSocks\n" +
            "http://127.0.0.1:7890#LocalHttp";

        ProxyBatchParseResult result = ProxyBatchParser.Parse(input, ProxyProtocol.Socks5, allowXrayProtocols: false);

        Assert.Equal(2, result.Proxies.Count);
        Assert.Single(result.Errors);
        Assert.Contains("Xray-core", result.Errors[0].Reason);

        const string jsonInput = """
            [
              {
                "Name": "VlessNode",
                "Protocol": "Vless",
                "Host": "cat.vanitas.top",
                "Port": 8443,
                "Vless": {
                  "Uuid": "6611d690-5e50-403e-9a90-e1877a69e350",
                  "Security": "reality",
                  "Sni": "www.hsbc.hk",
                  "PublicKey": "ABC"
                }
              }
            ]
            """;
        ProxyBatchParseResult jsonResult = ProxyBatchParser.Parse(jsonInput, allowXrayProtocols: false);
        Assert.Empty(jsonResult.Proxies);
        Assert.Single(jsonResult.Errors);
        Assert.Contains("Xray-core", jsonResult.Errors[0].Reason);
    }

    [Fact]
    public void XrayConfigBuilder_SingleAndMulti_GeneratesValidRealityAndDialerProxyJson()
    {
        var proxy = new ProxyProfile
        {
            Name = "CAT",
            Protocol = ProxyProtocol.Vless,
            Host = "cat.vanitas.top",
            Port = 8443,
            Vless = new VlessSettings
            {
                Uuid = "6611d690-5e50-403e-9a90-e1877a69e350",
                Encryption = "none",
                Flow = "xtls-rprx-vision",
                Network = "tcp",
                Security = "reality",
                Sni = "www.hsbc.hk",
                Fingerprint = "chrome",
                PublicKey = "UunraCjhfc38MvRAjw_TdUlEL4_o_nYWxIkYbnMAIV8",
                ShortId = "7f86960c6a3cfc",
                SpiderX = "/150628bbe37dd65"
            }
        };

        string json = XrayConfigBuilder.BuildSingleProxyConfigJson(
            localSocksPort: 20808,
            socksUser: "u1",
            socksPass: "p1",
            proxy: proxy,
            physicalDialerPort: 20999,
            physicalDialerUser: "du",
            physicalDialerPass: "dp");

        using JsonDocument doc = JsonDocument.Parse(json);
        JsonElement root = doc.RootElement;

        JsonElement inbound = root.GetProperty("inbounds")[0];
        Assert.Equal("socks", inbound.GetProperty("protocol").GetString());
        Assert.Equal(20808, inbound.GetProperty("port").GetInt32());
        Assert.Equal("u1", inbound.GetProperty("settings").GetProperty("accounts")[0].GetProperty("user").GetString());

        JsonElement vlessOutbound = root.GetProperty("outbounds")[0];
        Assert.Equal("vless", vlessOutbound.GetProperty("protocol").GetString());
        JsonElement vnext = vlessOutbound.GetProperty("settings").GetProperty("vnext")[0];
        Assert.Equal("cat.vanitas.top", vnext.GetProperty("address").GetString());
        Assert.Equal(8443, vnext.GetProperty("port").GetInt32());
        Assert.Equal("xtls-rprx-vision", vnext.GetProperty("users")[0].GetProperty("flow").GetString());

        JsonElement stream = vlessOutbound.GetProperty("streamSettings");
        Assert.Equal("reality", stream.GetProperty("security").GetString());
        JsonElement reality = stream.GetProperty("realitySettings");
        Assert.Equal("www.hsbc.hk", reality.GetProperty("serverName").GetString());
        Assert.Equal("chrome", reality.GetProperty("fingerprint").GetString());
        Assert.Equal("UunraCjhfc38MvRAjw_TdUlEL4_o_nYWxIkYbnMAIV8", reality.GetProperty("publicKey").GetString());
        Assert.Equal("7f86960c6a3cfc", reality.GetProperty("shortId").GetString());
        Assert.Equal("/150628bbe37dd65", reality.GetProperty("spiderX").GetString());
        Assert.Equal("physical-direct", stream.GetProperty("sockopt").GetProperty("dialerProxy").GetString());

        JsonElement dialerOutbound = root.GetProperty("outbounds")[1];
        Assert.Equal("physical-direct", dialerOutbound.GetProperty("tag").GetString());
        Assert.Equal("socks", dialerOutbound.GetProperty("protocol").GetString());
        Assert.Equal(20999, dialerOutbound.GetProperty("settings").GetProperty("servers")[0].GetProperty("port").GetInt32());

        JsonElement rule = root.GetProperty("routing").GetProperty("rules")[0];
        Assert.Equal("socks-in-0", rule.GetProperty("inboundTag")[0].GetString());
        Assert.Equal("vless-out-0", rule.GetProperty("outboundTag").GetString());
    }

    [Fact]
    public void AppPaths_ResolveXrayExePath_HandlesCustomDefaultAndMissing()
    {
        string tempRoot = Path.Combine(Path.GetTempPath(), "AppProxyXrayPathTests_" + Guid.NewGuid().ToString("N"));
        try
        {
            string coresDir = AppPaths.GetCoresDirectory(tempRoot);
            Directory.CreateDirectory(coresDir);
            string defaultXray = AppPaths.GetDefaultXrayExePath(tempRoot);
            string customXray = Path.Combine(tempRoot, "custom", "xray.exe");
            Directory.CreateDirectory(Path.GetDirectoryName(customXray)!);

            Assert.Null(AppPaths.ResolveXrayExePath(null, tempRoot));

            File.WriteAllText(defaultXray, "stub");
            Assert.Equal(defaultXray, AppPaths.ResolveXrayExePath(null, tempRoot));

            Assert.Null(AppPaths.ResolveXrayExePath(Path.Combine(tempRoot, "missing.exe"), tempRoot));

            File.WriteAllText(customXray, "stub");
            Assert.Equal(customXray, AppPaths.ResolveXrayExePath($"\"{customXray}\"", tempRoot));
            Assert.Equal(customXray, AppPaths.ResolveXrayExePath("custom\\xray.exe", tempRoot));
        }
        finally
        {
            if (Directory.Exists(tempRoot))
            {
                Directory.Delete(tempRoot, recursive: true);
            }
        }
    }

    [Fact]
    public async Task PhysicalDirectSocksProxy_EndToEndConnectWithAuth_RelaysTrafficAndRejectsBadAuth()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var echoListener = new TcpListener(IPAddress.Loopback, 0);
        echoListener.Start();
        int echoPort = ((IPEndPoint)echoListener.LocalEndpoint).Port;

        Task echoTask = Task.Run(async () =>
        {
            using TcpClient conn = await echoListener.AcceptTcpClientAsync(cts.Token);
            using NetworkStream ns = conn.GetStream();
            byte[] buf = new byte[64];
            int n = await ns.ReadAsync(buf, cts.Token);
            await ns.WriteAsync(buf.AsMemory(0, n), cts.Token);
        }, cts.Token);

        using var dialer = new PhysicalDirectSocksProxy(bypassGlobalTun: false);

        // Bad credentials must be rejected
        var badCredProxy = new ProxyProfile
        {
            Protocol = ProxyProtocol.Socks5,
            Host = "127.0.0.1",
            Port = dialer.Port,
            Username = dialer.Username,
            Password = "wrong-password"
        };
        using (var badClient = new TcpClient())
        {
            await badClient.ConnectAsync(IPAddress.Loopback, dialer.Port, cts.Token);
            await Assert.ThrowsAsync<IOException>(() =>
                Socks5TunnelClient.ConnectAsync(badClient.GetStream(), badCredProxy, "127.0.0.1", echoPort, IPAddress.Loopback, cts.Token));
        }

        // Valid credentials must relay payload end-to-end
        var goodCredProxy = new ProxyProfile
        {
            Protocol = ProxyProtocol.Socks5,
            Host = "127.0.0.1",
            Port = dialer.Port,
            Username = dialer.Username,
            Password = dialer.Password
        };
        using (var goodClient = new TcpClient())
        {
            await goodClient.ConnectAsync(IPAddress.Loopback, dialer.Port, cts.Token);
            NetworkStream stream = goodClient.GetStream();
            await Socks5TunnelClient.ConnectAsync(stream, goodCredProxy, "127.0.0.1", echoPort, IPAddress.Loopback, cts.Token);

            byte[] msg = Encoding.UTF8.GetBytes("hello-physical-dialer");
            await stream.WriteAsync(msg, cts.Token);

            byte[] recv = new byte[msg.Length];
            int total = 0;
            while (total < recv.Length)
            {
                int r = await stream.ReadAsync(recv.AsMemory(total, recv.Length - total), cts.Token);
                if (r <= 0) break;
                total += r;
            }
            Assert.Equal("hello-physical-dialer", Encoding.UTF8.GetString(recv, 0, total));
        }

        await echoTask;
    }

    [Fact]
    public void ConfigService_PersistsXrayCorePathAndVlessSettings_OmitsVlessForSocks5()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "AppProxyXrayCfgTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        string cfgPath = Path.Combine(tempDir, "config.json");

        try
        {
            var svc = new ConfigService(cfgPath);
            var cfg = new AppConfig
            {
                XrayCorePath = @"D:\Tools\xray\xray.exe",
                Proxies =
                [
                    new ProxyProfile { Name = "S5", Protocol = ProxyProtocol.Socks5, Host = "127.0.0.1", Port = 1080 },
                    new ProxyProfile
                    {
                        Name = "CAT",
                        Protocol = ProxyProtocol.Vless,
                        Host = "cat.vanitas.top",
                        Port = 8443,
                        Vless = new VlessSettings
                        {
                            Uuid = "6611d690-5e50-403e-9a90-e1877a69e350",
                            Security = "reality",
                            Sni = "www.hsbc.hk",
                            Fingerprint = "chrome",
                            PublicKey = "PUBKEY",
                            ShortId = "7f86960c6a3cfc",
                            SpiderX = "/150628bbe37dd65"
                        }
                    }
                ]
            };

            svc.Save(cfg);
            string rawJson = File.ReadAllText(cfgPath);
            Assert.Contains("\"XrayCorePath\"", rawJson);

            AppConfig reloaded = svc.Load();
            Assert.Equal(@"D:\Tools\xray\xray.exe", reloaded.XrayCorePath);
            Assert.Equal(2, reloaded.Proxies.Count);
            Assert.Null(reloaded.Proxies[0].Vless);
            Assert.Equal(ProxyProtocol.Vless, reloaded.Proxies[1].Protocol);
            Assert.NotNull(reloaded.Proxies[1].Vless);
            Assert.Equal("www.hsbc.hk", reloaded.Proxies[1].Vless!.Sni);
            Assert.Equal("PUBKEY", reloaded.Proxies[1].Vless!.PublicKey);
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
    public async Task ProxyTester_VlessSidecarOverride_MeasuresRealEndToEndHttpLatency_NotEarlySocksAck()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var mockSocksListener = new TcpListener(IPAddress.Loopback, 0);
        mockSocksListener.Start();
        int socksPort = ((IPEndPoint)mockSocksListener.LocalEndpoint).Port;

        Task serverTask = Task.Run(async () =>
        {
            using TcpClient conn = await mockSocksListener.AcceptTcpClientAsync(cts.Token);
            using NetworkStream ns = conn.GetStream();

            // Greeting (VER, NMETHODS, METHOD)
            byte[] greet = new byte[3];
            await ReadExactBytesAsync(ns, greet, cts.Token);
            await ns.WriteAsync(new byte[] { 0x05, 0x00 }, cts.Token);

            // CONNECT request (ATYP=0x03 domain)
            byte[] hdr = new byte[4];
            await ReadExactBytesAsync(ns, hdr, cts.Token);
            Assert.Equal(0x03, hdr[3]);
            byte[] lenBuf = new byte[1];
            await ReadExactBytesAsync(ns, lenBuf, cts.Token);
            byte[] domainBuf = new byte[lenBuf[0]];
            await ReadExactBytesAsync(ns, domainBuf, cts.Token);
            byte[] portBuf = new byte[2];
            await ReadExactBytesAsync(ns, portBuf, cts.Token);

            // Xray-core local SOCKS5 inbound immediately replies 0x05 0x00 (0-RTT early ACK)
            await ns.WriteAsync(new byte[] { 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0 }, cts.Token);

            // Wait for end-to-end HTTP probe from ProxyTester
            byte[] reqBuf = new byte[512];
            int n = await ns.ReadAsync(reqBuf, cts.Token);
            string reqText = Encoding.ASCII.GetString(reqBuf, 0, n);
            Assert.StartsWith("GET /generate_204 HTTP/1.1", reqText);

            // Simulate genuine remote VLESS + REALITY + target RTT
            await Task.Delay(90, cts.Token);

            byte[] resp = Encoding.ASCII.GetBytes("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            await ns.WriteAsync(resp, cts.Token);
        }, cts.Token);

        var vlessProxy = new ProxyProfile
        {
            Name = "VLESS EarlyAck Test",
            Protocol = ProxyProtocol.Vless,
            Host = "remote.example.com",
            Port = 443,
            Vless = new VlessSettings
            {
                Uuid = "6611d690-5e50-403e-9a90-e1877a69e350",
                Security = "reality",
                Sni = "www.hsbc.hk",
                PublicKey = "PUBKEY"
            }
        };

        var sidecarOverride = new ProxyProfile
        {
            Id = vlessProxy.Id,
            Name = vlessProxy.Name,
            Protocol = ProxyProtocol.Socks5,
            Host = "127.0.0.1",
            Port = socksPort
        };

        await ProxyTester.TestProxyAsync(
            vlessProxy,
            probeHost: "www.gstatic.com",
            probePort: 80,
            ct: cts.Token,
            bypassGlobalTun: true,
            resolvedTransportOverride: sidecarOverride);
        await serverTask;

        Assert.Equal("OK", vlessProxy.LastTestStatus);
        Assert.NotNull(vlessProxy.LastLatencyMs);
        Assert.True(vlessProxy.LastLatencyMs >= 70, $"Expected genuine >=70ms RTT, got {vlessProxy.LastLatencyMs}ms");
    }

    [Fact]
    public async Task ProxyTester_VlessSidecarOverride_FailsWhenRemoteClosesAfterEarlySocksAck()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var mockSocksListener = new TcpListener(IPAddress.Loopback, 0);
        mockSocksListener.Start();
        int socksPort = ((IPEndPoint)mockSocksListener.LocalEndpoint).Port;

        Task serverTask = Task.Run(async () =>
        {
            using TcpClient conn = await mockSocksListener.AcceptTcpClientAsync(cts.Token);
            using NetworkStream ns = conn.GetStream();

            byte[] greet = new byte[3];
            await ReadExactBytesAsync(ns, greet, cts.Token);
            await ns.WriteAsync(new byte[] { 0x05, 0x00 }, cts.Token);

            byte[] hdr = new byte[4];
            await ReadExactBytesAsync(ns, hdr, cts.Token);
            byte[] lenBuf = new byte[1];
            await ReadExactBytesAsync(ns, lenBuf, cts.Token);
            byte[] domainBuf = new byte[lenBuf[0]];
            await ReadExactBytesAsync(ns, domainBuf, cts.Token);
            byte[] portBuf = new byte[2];
            await ReadExactBytesAsync(ns, portBuf, cts.Token);

            // Immediate early ACK followed by immediate remote disconnect (no HTTP response bytes)
            await ns.WriteAsync(new byte[] { 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0 }, cts.Token);
        }, cts.Token);

        var vlessProxy = new ProxyProfile
        {
            Name = "VLESS Unreachable Test",
            Protocol = ProxyProtocol.Vless,
            Host = "unreachable.example.com",
            Port = 443,
            Vless = new VlessSettings
            {
                Uuid = "6611d690-5e50-403e-9a90-e1877a69e350",
                Security = "reality",
                Sni = "www.hsbc.hk",
                PublicKey = "PUBKEY"
            }
        };

        var sidecarOverride = new ProxyProfile
        {
            Id = vlessProxy.Id,
            Name = vlessProxy.Name,
            Protocol = ProxyProtocol.Socks5,
            Host = "127.0.0.1",
            Port = socksPort
        };

        await ProxyTester.TestProxyAsync(
            vlessProxy,
            probeHost: "www.gstatic.com",
            probePort: 80,
            ct: cts.Token,
            bypassGlobalTun: true,
            resolvedTransportOverride: sidecarOverride);
        await serverTask;

        Assert.Null(vlessProxy.LastLatencyMs);
        Assert.StartsWith("Error:", vlessProxy.LastTestStatus);
    }

    private static async Task ReadExactBytesAsync(Stream s, byte[] buf, CancellationToken ct)
    {
        int read = 0;
        while (read < buf.Length)
        {
            int n = await s.ReadAsync(buf.AsMemory(read, buf.Length - read), ct);
            if (n <= 0) throw new EndOfStreamException();
            read += n;
        }
    }
}

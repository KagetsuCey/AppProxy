using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using AppProxy.Core.Models;
using AppProxy.Core.Services;
using Xunit;

namespace AppProxy.Tests;

public class ProxyBatchAndExitIpTests
{
    [Fact]
    public void Parse_SupportsUrisHostPortUserPassIpv6Base64AndCollectsErrors()
    {
        string b64UserPass = Convert.ToBase64String(Encoding.UTF8.GetBytes("b64user:b64pass"));
        string input = $"""
            # Comment line should be ignored
            // Another comment line

            socks5://alice:p%40ss@1.2.3.4:1080#Node%20Alpha
            socks5h://{b64UserPass}@[2001:db8::1]:1081#IPv6Node
            http://proxy.example.com:8080
            https://bob:secret@tls.example.com:443#TLS-Node
            198.51.100.10:9000:resUser:pa:ss#123 #Residential 1
            plainUser:plainPass@203.0.113.5:3128#AtFormat
            [2001:db8::2]:1088:v6user:v6pass
            203.0.113.8:7890
            bad_missing_port
            1.2.3.4:99999
            1.2.3.4:1080:onlyUserNoPass
            """;

        ProxyBatchParseResult result = ProxyBatchParser.Parse(input, ProxyProtocol.Socks5);

        Assert.Equal(8, result.Proxies.Count);
        Assert.Equal(3, result.Errors.Count);

        Assert.Equal(ProxyProtocol.Socks5, result.Proxies[0].Protocol);
        Assert.Equal("1.2.3.4", result.Proxies[0].Host);
        Assert.Equal(1080, result.Proxies[0].Port);
        Assert.Equal("alice", result.Proxies[0].Username);
        Assert.Equal("p@ss", result.Proxies[0].Password);
        Assert.Equal("Node Alpha", result.Proxies[0].Name);

        Assert.Equal("2001:db8::1", result.Proxies[1].Host);
        Assert.Equal(1081, result.Proxies[1].Port);
        Assert.Equal("b64user", result.Proxies[1].Username);
        Assert.Equal("b64pass", result.Proxies[1].Password);
        Assert.Equal("IPv6Node", result.Proxies[1].Name);

        Assert.Equal(ProxyProtocol.Http, result.Proxies[2].Protocol);
        Assert.Equal(ProxyProtocol.Https, result.Proxies[3].Protocol);
        Assert.Equal("TLS-Node", result.Proxies[3].Name);

        Assert.Equal("198.51.100.10", result.Proxies[4].Host);
        Assert.Equal(9000, result.Proxies[4].Port);
        Assert.Equal("resUser", result.Proxies[4].Username);
        Assert.Equal("pa:ss#123", result.Proxies[4].Password);
        Assert.Equal("Residential 1", result.Proxies[4].Name);

        Assert.Equal("plainUser", result.Proxies[5].Username);
        Assert.Equal("plainPass", result.Proxies[5].Password);
        Assert.Equal("203.0.113.5", result.Proxies[5].Host);
        Assert.Equal("AtFormat", result.Proxies[5].Name);

        Assert.Equal("2001:db8::2", result.Proxies[6].Host);
        Assert.Equal(1088, result.Proxies[6].Port);
        Assert.Equal("v6user", result.Proxies[6].Username);
        Assert.Equal("v6pass", result.Proxies[6].Password);

        Assert.Equal("203.0.113.8", result.Proxies[7].Host);
        Assert.Equal(7890, result.Proxies[7].Port);

        Assert.Equal(12, result.Errors[0].LineNumber);
        Assert.Equal(13, result.Errors[1].LineNumber);
        Assert.Equal(14, result.Errors[2].LineNumber);
    }

    [Fact]
    public void Parse_SupportsJsonArrayAndAppConfigObject_GeneratesFreshGuids()
    {
        Guid origId = Guid.Parse("11111111-1111-1111-1111-111111111111");
        string jsonArray = """
            [
              {
                "Id": "11111111-1111-1111-1111-111111111111",
                "Name": "HK Node",
                "Protocol": "Socks5",
                "Host": "10.0.0.2",
                "Port": 1080,
                "Username": "u1",
                "Password": "p1"
              },
              {
                "Name": "Invalid Port",
                "Protocol": "Http",
                "Host": "10.0.0.3",
                "Port": 0
              }
            ]
            """;

        ProxyBatchParseResult arrayRes = ProxyBatchParser.Parse(jsonArray);
        Assert.Single(arrayRes.Proxies);
        Assert.Single(arrayRes.Errors);
        Assert.NotEqual(origId, arrayRes.Proxies[0].Id);
        Assert.Equal("HK Node", arrayRes.Proxies[0].Name);
        Assert.Equal("u1", arrayRes.Proxies[0].Username);

        string configJson = """
            {
              "Proxies": [
                { "Name": "FromCfg", "Protocol": "Https", "Host": "proxy.test", "Port": 8443 }
              ],
              "Apps": []
            }
            """;

        ProxyBatchParseResult cfgRes = ProxyBatchParser.Parse(configJson);
        Assert.Single(cfgRes.Proxies);
        Assert.Empty(cfgRes.Errors);
        Assert.Equal(ProxyProtocol.Https, cfgRes.Proxies[0].Protocol);
        Assert.Equal("FromCfg", cfgRes.Proxies[0].Name);
    }

    [Fact]
    public void ExportToUriLines_RoundTripsCleanlyThroughParser()
    {
        var list = new List<ProxyProfile>
        {
            new() { Name = "Node A", Protocol = ProxyProtocol.Socks5, Host = "1.2.3.4", Port = 1080, Username = "u", Password = "p@#" },
            new() { Name = "Node B", Protocol = ProxyProtocol.Http, Host = "example.com", Port = 8080 },
            new() { Name = "Node V6", Protocol = ProxyProtocol.Https, Host = "2001:db8::9", Port = 443 }
        };

        string exported = ProxyBatchParser.ExportToUriLines(list);
        ProxyBatchParseResult reparsed = ProxyBatchParser.Parse(exported);

        Assert.Empty(reparsed.Errors);
        Assert.Equal(3, reparsed.Proxies.Count);
        for (int i = 0; i < list.Count; i++)
        {
            Assert.Equal(list[i].Protocol, reparsed.Proxies[i].Protocol);
            Assert.Equal(list[i].Host, reparsed.Proxies[i].Host);
            Assert.Equal(list[i].Port, reparsed.Proxies[i].Port);
            Assert.Equal(list[i].Username, reparsed.Proxies[i].Username);
            Assert.Equal(list[i].Password, reparsed.Proxies[i].Password);
            Assert.Equal(list[i].Name, reparsed.Proxies[i].Name);
        }
    }

    [Fact]
    public void ExportToJson_RoundTripsCleanlyThroughParser()
    {
        Assert.Equal("[]", ProxyBatchParser.ExportToJson([]));

        var list = new List<ProxyProfile>
        {
            new() { Name = "Node A", Protocol = ProxyProtocol.Socks5, Host = "1.2.3.4", Port = 1080, Username = "u", Password = "p@#:" },
            new() { Name = "Node B", Protocol = ProxyProtocol.Http, Host = "example.com", Port = 8080 },
            new() { Name = "Node V6", Protocol = ProxyProtocol.Https, Host = "2001:db8::9", Port = 443 }
        };

        string json = ProxyBatchParser.ExportToJson(list);
        using (JsonDocument doc = JsonDocument.Parse(json))
        {
            Assert.Equal(JsonValueKind.Array, doc.RootElement.ValueKind);
            Assert.Equal(3, doc.RootElement.GetArrayLength());
        }

        ProxyBatchParseResult reparsed = ProxyBatchParser.Parse(json);
        Assert.Empty(reparsed.Errors);
        Assert.Equal(3, reparsed.Proxies.Count);
        for (int i = 0; i < list.Count; i++)
        {
            Assert.Equal(list[i].Protocol, reparsed.Proxies[i].Protocol);
            Assert.Equal(list[i].Host, reparsed.Proxies[i].Host);
            Assert.Equal(list[i].Port, reparsed.Proxies[i].Port);
            Assert.Equal(list[i].Username, reparsed.Proxies[i].Username);
            Assert.Equal(list[i].Password, reparsed.Proxies[i].Password);
            Assert.Equal(list[i].Name, reparsed.Proxies[i].Name);
        }
    }

    [Fact]
    public void ParseGeoJson_HandlesIpApi_IpWhoIs_And_IpInfo()
    {
        ProxyExitIpInfo? ipApi = ProxyExitIpDetector.ParseGeoJson("ip-api", """
            {"status":"success","country":"日本","countryCode":"JP","regionName":"Tokyo","city":"东京","isp":"NTT","query":"203.0.113.42"}
            """);
        Assert.NotNull(ipApi);
        Assert.Equal("203.0.113.42", ipApi!.Ip);
        Assert.Equal("JP", ipApi.CountryCode);
        Assert.Equal("日本 · 东京", ipApi.LocationDisplay);
        Assert.Equal("NTT", ipApi.Isp);

        ProxyExitIpInfo? ipWho = ProxyExitIpDetector.ParseGeoJson("ipwho", """
            {"ip":"198.51.100.7","success":true,"country":"Singapore","country_code":"SG","region":"Singapore","city":"Singapore","connection":{"isp":"DigitalOcean"}}
            """);
        Assert.NotNull(ipWho);
        Assert.Equal("198.51.100.7", ipWho!.Ip);
        Assert.Equal("SG", ipWho.CountryCode);
        Assert.Equal("Singapore", ipWho.LocationDisplay);
        Assert.Equal("DigitalOcean", ipWho.Isp);

        ProxyExitIpInfo? ipInfo = ProxyExitIpDetector.ParseGeoJson("ipinfo", """
            {"ip":"8.8.4.4","city":"Los Angeles","region":"California","country":"US","org":"AS15169 Google LLC"}
            """);
        Assert.NotNull(ipInfo);
        Assert.Equal("8.8.4.4", ipInfo!.Ip);
        Assert.Equal("US", ipInfo.CountryCode);
        Assert.Equal("US · Los Angeles", ipInfo.LocationDisplay);
        Assert.Equal("AS15169 Google LLC", ipInfo.Isp);

        Assert.Null(ProxyExitIpDetector.ParseGeoJson("ip-api", """{"status":"fail","message":"reserved range"}"""));
        Assert.Null(ProxyExitIpDetector.ParseGeoJson("ipwho", """{"success":false}"""));
    }

    [Fact]
    public async Task DetectAsync_EndToEndOverMockSocks5AndHttpGeoServer_PopulatesProfile()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var socksListener = new TcpListener(IPAddress.Loopback, 0);
        socksListener.Start();
        int socksPort = ((IPEndPoint)socksListener.LocalEndpoint).Port;

        Task serverTask = Task.Run(async () =>
        {
            using TcpClient conn = await socksListener.AcceptTcpClientAsync(cts.Token);
            using NetworkStream ns = conn.GetStream();

            // Greeting
            byte[] greet = new byte[3];
            await ReadExactAsync(ns, greet, cts.Token);
            await ns.WriteAsync(new byte[] { 0x05, 0x00 }, cts.Token);

            // CONNECT request (ATYP=0x03 domain)
            byte[] hdr = new byte[4];
            await ReadExactAsync(ns, hdr, cts.Token);
            Assert.Equal(0x03, hdr[3]);
            byte[] lenBuf = new byte[1];
            await ReadExactAsync(ns, lenBuf, cts.Token);
            byte[] domainBuf = new byte[lenBuf[0]];
            await ReadExactAsync(ns, domainBuf, cts.Token);
            byte[] portBuf = new byte[2];
            await ReadExactAsync(ns, portBuf, cts.Token);

            await ns.WriteAsync(new byte[] { 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0 }, cts.Token);

            // Read HTTP GET headers
            byte[] reqBuf = new byte[1024];
            int n = await ns.ReadAsync(reqBuf, cts.Token);
            string reqText = Encoding.ASCII.GetString(reqBuf, 0, n);
            Assert.Contains("GET /geo", reqText);

            string body = """{"status":"success","country":"美国","countryCode":"US","regionName":"CA","city":"洛杉矶","isp":"Cloudflare","query":"104.16.0.1"}""";
            byte[] bodyBytes = Encoding.UTF8.GetBytes(body);
            string respHeader =
                "HTTP/1.1 200 OK\r\n" +
                "Content-Type: application/json\r\n" +
                $"Content-Length: {bodyBytes.Length}\r\n" +
                "Connection: close\r\n\r\n";
            await ns.WriteAsync(Encoding.ASCII.GetBytes(respHeader), cts.Token);
            await ns.WriteAsync(bodyBytes, cts.Token);
        }, cts.Token);

        var proxy = new ProxyProfile
        {
            Name = "MockSocks",
            Protocol = ProxyProtocol.Socks5,
            Host = "127.0.0.1",
            Port = socksPort
        };

        var endpoints = new[]
        {
            new GeoProbeEndpoint("ip-api", "mock.geo.local", 80, false, "/geo")
        };

        ProxyExitIpInfo? info = await ProxyExitIpDetector.DetectAsync(proxy, endpoints, bypassGlobalTun: true, ct: cts.Token);
        await serverTask;

        Assert.NotNull(info);
        Assert.Equal("104.16.0.1", proxy.ExitIp);
        Assert.Equal("US", proxy.ExitCountryCode);
        Assert.Equal("美国 · 洛杉矶", proxy.ExitLocation);
        Assert.Equal("Cloudflare", proxy.ExitIsp);
        Assert.True(proxy.HasExitInfo);
        Assert.Equal("Ok", proxy.ExitBadgeState);
        Assert.Equal("US · 美国 · 洛杉矶 · 104.16.0.1", proxy.ExitBadgeText);
        Assert.False(proxy.IsDetectingExitIp);
    }

    [Fact]
    public void ProxyProfile_ExitInfo_PersistsToJsonAndClearsOnDuplicate()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "AppProxyExitTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        string cfgPath = Path.Combine(tempDir, "config.json");

        try
        {
            var svc = new ConfigService(cfgPath);
            var proxy = new ProxyProfile
            {
                Name = "Tokyo",
                Protocol = ProxyProtocol.Socks5,
                Host = "203.0.113.10",
                Port = 1080,
                ExitIp = "203.0.113.10",
                ExitCountryCode = "JP",
                ExitLocation = "日本 · 东京",
                ExitIsp = "KDDI"
            };

            svc.Save(new AppConfig { Proxies = [proxy] });
            AppConfig reloaded = svc.Load();
            Assert.Single(reloaded.Proxies);
            Assert.Equal("203.0.113.10", reloaded.Proxies[0].ExitIp);
            Assert.Equal("JP", reloaded.Proxies[0].ExitCountryCode);
            Assert.Equal("日本 · 东京", reloaded.Proxies[0].ExitLocation);
            Assert.Equal("KDDI", reloaded.Proxies[0].ExitIsp);

            ProxyProfile dup = reloaded.Proxies[0].CreateDuplicate(["Tokyo"]);
            Assert.Equal(string.Empty, dup.ExitIp);
            Assert.Equal(string.Empty, dup.ExitCountryCode);
            Assert.Equal(string.Empty, dup.ExitLocation);
            Assert.Equal(string.Empty, dup.ExitIsp);
            Assert.False(dup.HasExitInfo);
            Assert.False(dup.IsExitIpCopied);
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
    public void ProxyProfile_ExitIpCopiedState_TransitionsCleanlyAndIsNotPersisted()
    {
        string tempDir = Path.Combine(Path.GetTempPath(), "AppProxyCopyStateTests_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        string cfgPath = Path.Combine(tempDir, "config.json");

        try
        {
            var proxy = new ProxyProfile
            {
                Name = "SG Node",
                Protocol = ProxyProtocol.Socks5,
                Host = "198.51.100.1",
                Port = 1080,
                ExitIp = "203.0.113.88",
                ExitCountryCode = "SG",
                ExitLocation = "新加坡"
            };

            Assert.Equal("Ok", proxy.ExitBadgeState);
            Assert.Equal("SG · 新加坡 · 203.0.113.88", proxy.ExitBadgeText);

            proxy.IsExitIpCopied = true;
            Assert.Equal("Copied", proxy.ExitBadgeState);
            Assert.Equal("✓ 已复制 203.0.113.88", proxy.ExitBadgeText);

            proxy.IsDetectingExitIp = true;
            Assert.Equal("Detecting", proxy.ExitBadgeState);
            Assert.Equal("检测出口中...", proxy.ExitBadgeText);

            proxy.IsDetectingExitIp = false;
            proxy.IsExitIpCopied = false;
            Assert.Equal("Ok", proxy.ExitBadgeState);
            Assert.Equal("SG · 新加坡 · 203.0.113.88", proxy.ExitBadgeText);

            proxy.IsExitIpCopied = true;
            ProxyProfile dup = proxy.CreateDuplicate(["SG Node"]);
            Assert.False(dup.IsExitIpCopied);

            var svc = new ConfigService(cfgPath);
            svc.Save(new AppConfig { Proxies = [proxy] });
            AppConfig reloaded = svc.Load();
            Assert.Single(reloaded.Proxies);
            Assert.False(reloaded.Proxies[0].IsExitIpCopied);
        }
        finally
        {
            if (Directory.Exists(tempDir))
            {
                Directory.Delete(tempDir, recursive: true);
            }
        }
    }

    private static async Task ReadExactAsync(Stream s, byte[] buf, CancellationToken ct)
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

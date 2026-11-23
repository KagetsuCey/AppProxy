using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using AppProxy.Core.Models;

namespace AppProxy.Core.Services;

public sealed record GeoProbeEndpoint(
    string Source,
    string Host,
    int Port,
    bool UseTls,
    string Path);

public sealed record ProxyExitIpInfo(
    string Ip,
    string CountryCode,
    string Country,
    string Region,
    string City,
    string Isp,
    string Source)
{
    public string LocationDisplay
    {
        get
        {
            string c = Country.Trim();
            string city = City.Trim();
            string region = Region.Trim();

            if (!string.IsNullOrEmpty(c) && !string.IsNullOrEmpty(city) &&
                !string.Equals(c, city, StringComparison.OrdinalIgnoreCase))
            {
                return $"{c} · {city}";
            }

            if (!string.IsNullOrEmpty(c) && !string.IsNullOrEmpty(region) &&
                !string.Equals(c, region, StringComparison.OrdinalIgnoreCase))
            {
                return $"{c} · {region}";
            }

            return !string.IsNullOrEmpty(c)
                ? c
                : (!string.IsNullOrEmpty(city) ? city : region);
        }
    }
}

/// <summary>
/// Detects a proxy node's real egress IP address and geolocation by tunneling HTTP/HTTPS
/// probes directly through the proxy (inheriting global TUN bypass via OutboundSocketConnector).
/// </summary>
public static class ProxyExitIpDetector
{
    private static readonly GeoProbeEndpoint[] DefaultEndpoints =
    [
        new("ip-api", "ip-api.com", 80, false, "/json/?fields=status,country,countryCode,regionName,city,isp,query&lang=zh-CN"),
        new("ipwho", "ipwho.is", 443, true, "/"),
        new("ipinfo", "ipinfo.io", 443, true, "/json")
    ];

    public static Task<ProxyExitIpInfo?> DetectAsync(
        ProxyProfile proxy,
        bool bypassGlobalTun = true,
        string? preferredOutboundInterface = null,
        CancellationToken ct = default) =>
        DetectAsync(proxy, DefaultEndpoints, bypassGlobalTun, preferredOutboundInterface, ct);

    public static async Task<ProxyExitIpInfo?> DetectAsync(
        ProxyProfile proxy,
        IReadOnlyList<GeoProbeEndpoint> endpoints,
        bool bypassGlobalTun = true,
        string? preferredOutboundInterface = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(proxy);
        ArgumentNullException.ThrowIfNull(endpoints);

        proxy.IsDetectingExitIp = true;
        proxy.ExitDetectError = string.Empty;

        string? lastFailure = null;
        try
        {
            foreach (GeoProbeEndpoint endpoint in endpoints)
            {
                if (ct.IsCancellationRequested) break;

                try
                {
                    using var providerCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    providerCts.CancelAfter(TimeSpan.FromSeconds(8));

                    ProxyExitIpInfo? info = await ProbeSingleEndpointAsync(
                        proxy,
                        endpoint,
                        bypassGlobalTun,
                        preferredOutboundInterface,
                        providerCts.Token);

                    if (info is not null)
                    {
                        proxy.ExitIp = info.Ip;
                        proxy.ExitCountryCode = info.CountryCode;
                        proxy.ExitLocation = info.LocationDisplay;
                        proxy.ExitIsp = info.Isp;
                        proxy.ExitDetectError = string.Empty;
                        return info;
                    }

                    lastFailure = $"{endpoint.Source}: 响应解析失败";
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (OperationCanceledException)
                {
                    lastFailure = "请求超时";
                }
                catch (Exception ex)
                {
                    lastFailure = ex.Message;
                }
            }

            proxy.ExitDetectError = string.IsNullOrWhiteSpace(lastFailure)
                ? "出口检测失败"
                : (lastFailure.Length > 42 ? "出口检测失败" : lastFailure);
            return null;
        }
        finally
        {
            proxy.IsDetectingExitIp = false;
        }
    }

    public static ProxyExitIpInfo? ParseGeoJson(string source, string json)
    {
        if (string.IsNullOrWhiteSpace(json)) return null;

        try
        {
            using JsonDocument doc = JsonDocument.Parse(json);
            JsonElement root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object) return null;

            return source.ToLowerInvariant() switch
            {
                "ip-api" => ParseIpApi(root),
                "ipwho" => ParseIpWho(root),
                "ipinfo" => ParseIpInfo(root),
                _ => ParseGeneric(source, root)
            };
        }
        catch
        {
            return null;
        }
    }

    private static ProxyExitIpInfo? ParseIpApi(JsonElement root)
    {
        string status = GetString(root, "status");
        if (!string.IsNullOrEmpty(status) &&
            !string.Equals(status, "success", StringComparison.OrdinalIgnoreCase))
        {
            return null;
        }

        string ip = GetString(root, "query");
        if (string.IsNullOrWhiteSpace(ip)) return null;

        return new ProxyExitIpInfo(
            ip,
            GetString(root, "countryCode").ToUpperInvariant(),
            GetString(root, "country"),
            GetString(root, "regionName"),
            GetString(root, "city"),
            GetString(root, "isp"),
            "ip-api");
    }

    private static ProxyExitIpInfo? ParseIpWho(JsonElement root)
    {
        if (root.TryGetProperty("success", out JsonElement okElem) &&
            okElem.ValueKind == JsonValueKind.False)
        {
            return null;
        }

        string ip = GetString(root, "ip");
        if (string.IsNullOrWhiteSpace(ip)) return null;

        string isp = string.Empty;
        if (root.TryGetProperty("connection", out JsonElement connElem) &&
            connElem.ValueKind == JsonValueKind.Object)
        {
            isp = GetString(connElem, "isp");
            if (string.IsNullOrEmpty(isp)) isp = GetString(connElem, "org");
        }

        return new ProxyExitIpInfo(
            ip,
            GetString(root, "country_code").ToUpperInvariant(),
            GetString(root, "country"),
            GetString(root, "region"),
            GetString(root, "city"),
            isp,
            "ipwho");
    }

    private static ProxyExitIpInfo? ParseIpInfo(JsonElement root)
    {
        string ip = GetString(root, "ip");
        if (string.IsNullOrWhiteSpace(ip)) return null;

        string cc = GetString(root, "country").ToUpperInvariant();
        return new ProxyExitIpInfo(
            ip,
            cc,
            cc,
            GetString(root, "region"),
            GetString(root, "city"),
            GetString(root, "org"),
            "ipinfo");
    }

    private static ProxyExitIpInfo? ParseGeneric(string source, JsonElement root)
    {
        string ip = GetString(root, "ip");
        if (string.IsNullOrEmpty(ip)) ip = GetString(root, "query");
        if (string.IsNullOrWhiteSpace(ip)) return null;

        string cc = GetString(root, "countryCode");
        if (string.IsNullOrEmpty(cc)) cc = GetString(root, "country_code");

        return new ProxyExitIpInfo(
            ip,
            cc.ToUpperInvariant(),
            GetString(root, "country"),
            GetString(root, "region"),
            GetString(root, "city"),
            GetString(root, "isp"),
            source);
    }

    private static async Task<ProxyExitIpInfo?> ProbeSingleEndpointAsync(
        ProxyProfile proxy,
        GeoProbeEndpoint endpoint,
        bool bypassGlobalTun,
        string? preferredOutboundInterface,
        CancellationToken ct)
    {
        using TcpClient tcp = await OutboundSocketConnector.ConnectAsync(
            proxy.Host,
            proxy.Port,
            null,
            bypassGlobalTun,
            preferredOutboundInterface,
            ct);

        Stream tunnelStream = tcp.GetStream();
        if (proxy.Protocol == ProxyProtocol.Socks5)
        {
            await Socks5TunnelClient.ConnectAsync(tunnelStream, proxy, endpoint.Host, endpoint.Port, null, ct);
        }
        else
        {
            tunnelStream = await HttpConnectTunnelClient.ConnectAsync(tunnelStream, proxy, endpoint.Host, endpoint.Port, ct);
        }

        Stream appStream = tunnelStream;
        SslStream? targetSsl = null;
        try
        {
            if (endpoint.UseTls)
            {
                targetSsl = new SslStream(tunnelStream, leaveInnerStreamOpen: false);
                await targetSsl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = endpoint.Host
                }, ct);
                appStream = targetSsl;
            }

            string req =
                $"GET {endpoint.Path} HTTP/1.1\r\n" +
                $"Host: {endpoint.Host}\r\n" +
                $"User-Agent: AppProxy/1.0\r\n" +
                $"Accept: application/json\r\n" +
                $"Connection: close\r\n\r\n";

            byte[] reqBytes = Encoding.ASCII.GetBytes(req);
            await appStream.WriteAsync(reqBytes, ct);
            await appStream.FlushAsync(ct);

            byte[] rawResponse = await ReadAllBytesCappedAsync(appStream, maxBytes: 64 * 1024, ct);
            byte[] body = ExtractHttpBody(rawResponse);
            if (body.Length == 0)
            {
                return null;
            }

            string json = Encoding.UTF8.GetString(body);
            return ParseGeoJson(endpoint.Source, json);
        }
        finally
        {
            if (targetSsl is not null)
            {
                await targetSsl.DisposeAsync();
            }
            else if (!ReferenceEquals(tunnelStream, tcp.GetStream()))
            {
                await tunnelStream.DisposeAsync();
            }
        }
    }

    private static async Task<byte[]> ReadAllBytesCappedAsync(Stream stream, int maxBytes, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        byte[] buf = new byte[4096];
        while (ms.Length < maxBytes)
        {
            int n = await stream.ReadAsync(buf.AsMemory(0, Math.Min(buf.Length, maxBytes - (int)ms.Length)), ct);
            if (n <= 0) break;
            ms.Write(buf, 0, n);
        }
        return ms.ToArray();
    }

    private static byte[] ExtractHttpBody(byte[] rawResponse)
    {
        ReadOnlySpan<byte> span = rawResponse;
        int sepIdx = span.IndexOf("\r\n\r\n"u8);
        if (sepIdx < 0) return [];

        string headerText = Encoding.ASCII.GetString(span[..sepIdx]);
        int lineEnd = headerText.IndexOf('\n');
        string statusLine = lineEnd > 0 ? headerText[..lineEnd].Trim() : headerText.Trim();
        string[] parts = statusLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2 || !int.TryParse(parts[1], out int statusCode) || statusCode < 200 || statusCode >= 300)
        {
            return [];
        }

        ReadOnlySpan<byte> bodySpan = span[(sepIdx + 4)..];
        if (headerText.Contains("Transfer-Encoding: chunked", StringComparison.OrdinalIgnoreCase))
        {
            return DecodeChunkedBody(bodySpan);
        }

        return bodySpan.ToArray();
    }

    private static byte[] DecodeChunkedBody(ReadOnlySpan<byte> data)
    {
        using var ms = new MemoryStream();
        int offset = 0;
        while (offset < data.Length)
        {
            int crlf = data[offset..].IndexOf("\r\n"u8);
            if (crlf < 0) break;
            string sizeLine = Encoding.ASCII.GetString(data.Slice(offset, crlf)).Split(';')[0].Trim();
            if (!int.TryParse(sizeLine, System.Globalization.NumberStyles.HexNumber, null, out int chunkSize) || chunkSize <= 0)
            {
                break;
            }
            offset += crlf + 2;
            if (offset + chunkSize > data.Length) break;
            ms.Write(data.Slice(offset, chunkSize));
            offset += chunkSize + 2;
        }
        return ms.ToArray();
    }

    private static string GetString(JsonElement obj, string propName)
    {
        if (obj.TryGetProperty(propName, out JsonElement val) && val.ValueKind == JsonValueKind.String)
        {
            return val.GetString()?.Trim() ?? string.Empty;
        }
        return string.Empty;
    }
}

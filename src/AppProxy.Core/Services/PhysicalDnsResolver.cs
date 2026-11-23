using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace AppProxy.Core.Services;

/// <summary>
/// Resolves upstream proxy hostnames directly through a chosen physical network interface
/// using DoH over IP:443 (immune to strict_route WFP UDP/TCP:53 blocks) and physical-NIC UDP:53,
/// with automatic cache invalidation when the network topology or IP changes.
/// </summary>
public static class PhysicalDnsResolver
{
    private sealed record CachedDnsEntry(IPAddress[] Addresses, DateTime ExpiresUtc, long NetworkEpoch);

    private static readonly (IPAddress ServerIp, string SniHost)[] BootstrapDohEndpoints =
    [
        (IPAddress.Parse("223.5.5.5"), "dns.alidns.com"),
        (IPAddress.Parse("1.12.12.12"), "doh.pub"),
        (IPAddress.Parse("1.1.1.1"), "cloudflare-dns.com"),
        (IPAddress.Parse("8.8.8.8"), "dns.google")
    ];

    private static readonly ConcurrentDictionary<(string Host, int IfV4, int IfV6), CachedDnsEntry> Cache = new();

    public static bool IsFakeIp(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6)
        {
            ip = ip.MapToIPv4();
        }

        byte[] bytes = ip.GetAddressBytes();
        if (ip.AddressFamily == AddressFamily.InterNetwork && bytes.Length == 4)
        {
            // 198.18.0.0/15
            return bytes[0] == 198 && (bytes[1] & 0xFE) == 18;
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6 && bytes.Length == 16)
        {
            // fd98:0018::/96
            return bytes[0] == 0xFD && bytes[1] == 0x98 && bytes[2] == 0x00 && bytes[3] == 0x18;
        }

        return false;
    }

    public static void ClearCache() => Cache.Clear();

    public static async Task<IPAddress[]> ResolveAsync(
        string host,
        OutboundInterfaceInfo? outboundInterface,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(host))
        {
            throw new ArgumentException("Host cannot be empty.", nameof(host));
        }

        string trimmed = host.Trim();
        if (IPAddress.TryParse(trimmed, out IPAddress? literalIp))
        {
            return [literalIp];
        }

        if (string.Equals(trimmed, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            return [IPAddress.Loopback];
        }

        if (outboundInterface is null)
        {
            return await Dns.GetHostAddressesAsync(trimmed, ct);
        }

        string normalized = trimmed.TrimEnd('.').ToLowerInvariant();
        int ifV4 = outboundInterface.IPv4Index ?? 0;
        int ifV6 = outboundInterface.IPv6Index ?? 0;
        long epoch = PhysicalNetworkSelector.NetworkEpoch;
        var cacheKey = (normalized, ifV4, ifV6);

        if (Cache.TryGetValue(cacheKey, out CachedDnsEntry? cached) &&
            cached.NetworkEpoch == epoch &&
            DateTime.UtcNow < cached.ExpiresUtc)
        {
            return cached.Addresses;
        }

        bool isLocalName = !normalized.Contains('.')
            || normalized.EndsWith(".local", StringComparison.Ordinal)
            || normalized.EndsWith(".localhost", StringComparison.Ordinal)
            || normalized.EndsWith(".lan", StringComparison.Ordinal)
            || normalized.EndsWith(".home", StringComparison.Ordinal);

        var collected = new List<IPAddress>();
        int minTtl = 60;

        if (!isLocalName)
        {
            // Tier 1: DoH over IP:443 bound to physical NIC (bypasses strict_route port-53 blocks)
            if (outboundInterface.HasUsableIPv4)
            {
                var (dohAddrs, dohTtl) = await TryResolveViaDohAsync(normalized, outboundInterface, ct);
                if (dohAddrs.Count > 0)
                {
                    collected.AddRange(dohAddrs);
                    minTtl = dohTtl;
                }
            }
        }

        // Tier 2: Physical NIC's own UDP:53 DNS servers (works for private/LAN domains or when DoH unavailable)
        if (collected.Count == 0 && outboundInterface.HasUsableIPv4)
        {
            var (udpAddrs, udpTtl) = await TryResolveViaInterfaceUdpAsync(normalized, outboundInterface, ct);
            if (udpAddrs.Count > 0)
            {
                collected.AddRange(udpAddrs);
                minTtl = udpTtl;
            }
        }

        // Tier 3: System DNS fallback, stripping Fake-IPs
        if (collected.Count == 0)
        {
            try
            {
                IPAddress[] sysAddrs = await Dns.GetHostAddressesAsync(normalized, ct);
                foreach (IPAddress addr in sysAddrs)
                {
                    if (!IsFakeIp(addr))
                    {
                        collected.Add(addr);
                    }
                }
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch
            {
            }
        }

        IPAddress[] filtered = FilterForOutboundCapabilities(collected, outboundInterface);
        if (filtered.Length > 0)
        {
            int clampedTtl = Math.Clamp(minTtl, 30, 300);
            Cache[cacheKey] = new CachedDnsEntry(filtered, DateTime.UtcNow.AddSeconds(clampedTtl), epoch);
            return filtered;
        }

        throw new SocketException((int)SocketError.HostNotFound);
    }

    private static IPAddress[] FilterForOutboundCapabilities(
        List<IPAddress> candidates,
        OutboundInterfaceInfo outbound)
    {
        var dedup = new List<IPAddress>();
        var seen = new HashSet<IPAddress>();

        foreach (IPAddress ip in candidates)
        {
            if (IsFakeIp(ip)) continue;
            if (ip.AddressFamily == AddressFamily.InterNetwork && !outbound.HasUsableIPv4) continue;
            if (ip.AddressFamily == AddressFamily.InterNetworkV6 && !outbound.HasUsableIPv6) continue;
            if (seen.Add(ip))
            {
                dedup.Add(ip);
            }
        }

        // Prefer IPv4 first when both are available
        return dedup
            .OrderBy(ip => ip.AddressFamily == AddressFamily.InterNetwork ? 0 : 1)
            .ToArray();
    }

    private static async Task<(List<IPAddress> Addresses, int MinTtl)> TryResolveViaDohAsync(
        string domain,
        OutboundInterfaceInfo outbound,
        CancellationToken ct)
    {
        var results = new List<IPAddress>();
        int minTtl = 120;

        foreach (var (serverIp, sniHost) in BootstrapDohEndpoints)
        {
            if (ct.IsCancellationRequested) break;

            try
            {
                using var endpointCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                endpointCts.CancelAfter(TimeSpan.FromMilliseconds(2500));

                var (v4Addrs, v4Ttl) = await QueryDohSingleRecordAsync(
                    serverIp, sniHost, domain, qtype: 1, outbound, endpointCts.Token);
                if (v4Addrs.Count > 0)
                {
                    results.AddRange(v4Addrs);
                    minTtl = Math.Min(minTtl, v4Ttl);
                }

                if (outbound.HasUsableIPv6)
                {
                    var (v6Addrs, v6Ttl) = await QueryDohSingleRecordAsync(
                        serverIp, sniHost, domain, qtype: 28, outbound, endpointCts.Token);
                    if (v6Addrs.Count > 0)
                    {
                        results.AddRange(v6Addrs);
                        minTtl = Math.Min(minTtl, v6Ttl);
                    }
                }

                if (results.Count > 0)
                {
                    return (results, minTtl);
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                // Try next bootstrap DoH endpoint
            }
        }

        return (results, minTtl);
    }

    private static async Task<(IReadOnlyList<IPAddress> Addresses, int MinTtl)> QueryDohSingleRecordAsync(
        IPAddress serverIp,
        string sniHost,
        string domain,
        ushort qtype,
        OutboundInterfaceInfo outbound,
        CancellationToken ct)
    {
        ushort txId = (ushort)RandomNumberGenerator.GetInt32(1, ushort.MaxValue);
        byte[] dnsQuery = BuildDnsQueryPacket(domain, qtype, txId);

        using var tcp = new TcpClient(serverIp.AddressFamily) { NoDelay = true };
        OutboundSocketConnector.ApplyUnicastInterface(tcp.Client, serverIp.AddressFamily, outbound);
        await tcp.ConnectAsync(serverIp, 443, ct);

        await using NetworkStream netStream = tcp.GetStream();
        await using var ssl = new SslStream(netStream, leaveInnerStreamOpen: false);
        await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = sniHost
        }, ct);

        string header =
            $"POST /dns-query HTTP/1.1\r\n" +
            $"Host: {sniHost}\r\n" +
            $"Content-Type: application/dns-message\r\n" +
            $"Accept: application/dns-message\r\n" +
            $"Content-Length: {dnsQuery.Length}\r\n" +
            $"Connection: close\r\n\r\n";

        byte[] headerBytes = Encoding.ASCII.GetBytes(header);
        await ssl.WriteAsync(headerBytes, ct);
        await ssl.WriteAsync(dnsQuery, ct);
        await ssl.FlushAsync(ct);

        byte[] rawResponse = await ReadAllBytesCappedAsync(ssl, maxBytes: 64 * 1024, ct);
        byte[] body = ExtractHttpBody(rawResponse);
        if (body.Length == 0)
        {
            return ([], 60);
        }

        return ParseDnsResponsePacket(body, txId);
    }

    private static async Task<(List<IPAddress> Addresses, int MinTtl)> TryResolveViaInterfaceUdpAsync(
        string domain,
        OutboundInterfaceInfo outbound,
        CancellationToken ct)
    {
        var results = new List<IPAddress>();
        int minTtl = 120;

        foreach (IPAddress dnsServer in outbound.IPv4DnsServers)
        {
            if (ct.IsCancellationRequested) break;
            if (IPAddress.IsLoopback(dnsServer) || IsFakeIp(dnsServer)) continue;

            try
            {
                using var udpCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                udpCts.CancelAfter(TimeSpan.FromMilliseconds(1200));

                ushort txId = (ushort)RandomNumberGenerator.GetInt32(1, ushort.MaxValue);
                byte[] query = BuildDnsQueryPacket(domain, qtype: 1, txId);

                using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                OutboundSocketConnector.ApplyUnicastInterface(socket, AddressFamily.InterNetwork, outbound);
                await socket.ConnectAsync(new IPEndPoint(dnsServer, 53), udpCts.Token);
                await socket.SendAsync(query, SocketFlags.None, udpCts.Token);

                byte[] recvBuf = new byte[4096];
                int n = await socket.ReceiveAsync(recvBuf, SocketFlags.None, udpCts.Token);
                if (n >= 12)
                {
                    var (addrs, ttl) = ParseDnsResponsePacket(recvBuf.AsSpan(0, n), txId);
                    if (addrs.Count > 0)
                    {
                        results.AddRange(addrs);
                        minTtl = Math.Min(minTtl, ttl);
                        return (results, minTtl);
                    }
                }
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested)
            {
                throw;
            }
            catch
            {
                // May hit WSAEACCES when strict_route WFP blocks UDP:53; fall through cleanly
            }
        }

        return (results, minTtl);
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
        ReadOnlySpan<byte> separator = "\r\n\r\n"u8;
        int sepIdx = span.IndexOf(separator);
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

    public static byte[] BuildDnsQueryPacket(string domain, ushort qtype, ushort txId)
    {
        string clean = domain.Trim().TrimEnd('.');
        using var ms = new MemoryStream(64);
        Span<byte> header = stackalloc byte[12];
        BinaryPrimitives.WriteUInt16BigEndian(header[0..2], txId);
        BinaryPrimitives.WriteUInt16BigEndian(header[2..4], 0x0100); // Standard query, RD=1
        BinaryPrimitives.WriteUInt16BigEndian(header[4..6], 1);      // QDCOUNT = 1
        BinaryPrimitives.WriteUInt16BigEndian(header[6..8], 0);
        BinaryPrimitives.WriteUInt16BigEndian(header[8..10], 0);
        BinaryPrimitives.WriteUInt16BigEndian(header[10..12], 0);
        ms.Write(header);

        foreach (string label in clean.Split('.', StringSplitOptions.RemoveEmptyEntries))
        {
            byte[] labelBytes = Encoding.ASCII.GetBytes(label);
            if (labelBytes.Length == 0 || labelBytes.Length > 63)
            {
                throw new ArgumentException($"Invalid DNS label '{label}' in '{domain}'.", nameof(domain));
            }
            ms.WriteByte((byte)labelBytes.Length);
            ms.Write(labelBytes);
        }
        ms.WriteByte(0); // Root label

        Span<byte> qtail = stackalloc byte[4];
        BinaryPrimitives.WriteUInt16BigEndian(qtail[0..2], qtype);
        BinaryPrimitives.WriteUInt16BigEndian(qtail[2..4], 1); // IN class
        ms.Write(qtail);

        return ms.ToArray();
    }

    public static (IReadOnlyList<IPAddress> Addresses, int MinTtlSeconds) ParseDnsResponsePacket(
        ReadOnlySpan<byte> packet,
        ushort expectedTxId)
    {
        if (packet.Length < 12)
        {
            return ([], 60);
        }

        ushort txId = BinaryPrimitives.ReadUInt16BigEndian(packet[0..2]);
        if (txId != expectedTxId)
        {
            return ([], 60);
        }

        ushort flags = BinaryPrimitives.ReadUInt16BigEndian(packet[2..4]);
        int rcode = flags & 0x0F;
        if (rcode != 0)
        {
            return ([], 60);
        }

        ushort qdCount = BinaryPrimitives.ReadUInt16BigEndian(packet[4..6]);
        ushort anCount = BinaryPrimitives.ReadUInt16BigEndian(packet[6..8]);

        int offset = 12;
        for (int q = 0; q < qdCount; q++)
        {
            if (!TrySkipDnsName(packet, ref offset) || offset + 4 > packet.Length)
            {
                return ([], 60);
            }
            offset += 4; // QTYPE + QCLASS
        }

        var addresses = new List<IPAddress>();
        int minTtl = int.MaxValue;

        for (int a = 0; a < anCount; a++)
        {
            if (!TrySkipDnsName(packet, ref offset) || offset + 10 > packet.Length)
            {
                break;
            }

            ushort rtype = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(offset, 2));
            ushort rclass = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(offset + 2, 2));
            uint ttl = BinaryPrimitives.ReadUInt32BigEndian(packet.Slice(offset + 4, 4));
            ushort rdLength = BinaryPrimitives.ReadUInt16BigEndian(packet.Slice(offset + 8, 2));
            offset += 10;

            if (offset + rdLength > packet.Length)
            {
                break;
            }

            if (rclass == 1)
            {
                if (rtype == 1 && rdLength == 4)
                {
                    var ip = new IPAddress(packet.Slice(offset, 4));
                    if (!IsFakeIp(ip))
                    {
                        addresses.Add(ip);
                        minTtl = Math.Min(minTtl, (int)Math.Min(ttl, int.MaxValue));
                    }
                }
                else if (rtype == 28 && rdLength == 16)
                {
                    var ip = new IPAddress(packet.Slice(offset, 16));
                    if (!IsFakeIp(ip))
                    {
                        addresses.Add(ip);
                        minTtl = Math.Min(minTtl, (int)Math.Min(ttl, int.MaxValue));
                    }
                }
            }

            offset += rdLength;
        }

        return (addresses, minTtl == int.MaxValue ? 60 : minTtl);
    }

    private static bool TrySkipDnsName(ReadOnlySpan<byte> packet, ref int offset)
    {
        int jumps = 0;
        while (offset < packet.Length)
        {
            byte len = packet[offset];
            if (len == 0)
            {
                offset += 1;
                return true;
            }
            if ((len & 0xC0) == 0xC0)
            {
                if (offset + 1 >= packet.Length || ++jumps > 16)
                {
                    return false;
                }
                offset += 2;
                return true;
            }
            if ((len & 0xC0) != 0)
            {
                return false;
            }
            offset += 1 + len;
        }
        return false;
    }
}

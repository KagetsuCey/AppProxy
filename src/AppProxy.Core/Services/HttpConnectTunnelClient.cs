using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using AppProxy.UI.Models;

namespace AppProxy.UI.Services;

public static class HttpConnectTunnelClient
{
    public static async Task<Stream> ConnectAsync(
        Stream baseStream,
        ProxyProfile proxy,
        string targetHost,
        int targetPort,
        CancellationToken ct)
    {
        Stream activeStream = baseStream;
        if (proxy.Protocol == ProxyProtocol.Https)
        {
            var ssl = new SslStream(baseStream, leaveInnerStreamOpen: false);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = proxy.Host
            }, ct);
            activeStream = ssl;
        }

        string formattedHost = IPAddress.TryParse(targetHost, out var ip) && ip.AddressFamily == AddressFamily.InterNetworkV6
            ? $"[{targetHost}]"
            : targetHost;
        string authority = $"{formattedHost}:{targetPort}";

        var sb = new StringBuilder();
        sb.Append($"CONNECT {authority} HTTP/1.1\r\n");
        sb.Append($"Host: {authority}\r\n");
        sb.Append("Proxy-Connection: Keep-Alive\r\n");

        if (!string.IsNullOrEmpty(proxy.Username))
        {
            string rawCreds = $"{proxy.Username}:{proxy.Password}";
            string b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(rawCreds));
            sb.Append($"Proxy-Authorization: Basic {b64}\r\n");
        }
        sb.Append("\r\n");

        byte[] reqBytes = Encoding.ASCII.GetBytes(sb.ToString());
        await activeStream.WriteAsync(reqBytes, ct);
        await activeStream.FlushAsync(ct);

        string headerText = await ReadHttpResponseHeadersAsync(activeStream, ct);
        int firstLineEnd = headerText.IndexOf('\n');
        string statusLine = firstLineEnd > 0 ? headerText[..firstLineEnd].Trim() : headerText.Trim();

        string[] parts = statusLine.Split(' ', 3, StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2 || !int.TryParse(parts[1], out int statusCode))
        {
            throw new IOException($"Malformed HTTP CONNECT response: {statusLine}");
        }

        if (statusCode is < 200 or >= 300)
        {
            throw new IOException($"HTTP CONNECT rejected with {statusLine}");
        }

        return activeStream;
    }

    private static async Task<string> ReadHttpResponseHeadersAsync(Stream stream, CancellationToken ct)
    {
        byte[] buf = new byte[1];
        var bytes = new List<byte>(256);
        while (bytes.Count < 16384)
        {
            int n = await stream.ReadAsync(buf.AsMemory(0, 1), ct);
            if (n <= 0)
            {
                throw new EndOfStreamException("Unexpected EOF reading HTTP CONNECT response.");
            }
            bytes.Add(buf[0]);
            int len = bytes.Count;
            if (len >= 4 &&
                bytes[len - 4] == '\r' &&
                bytes[len - 3] == '\n' &&
                bytes[len - 2] == '\r' &&
                bytes[len - 1] == '\n')
            {
                return Encoding.ASCII.GetString(bytes.ToArray());
            }
        }
        throw new IOException("HTTP CONNECT response headers exceeded 16 KB limit.");
    }
}

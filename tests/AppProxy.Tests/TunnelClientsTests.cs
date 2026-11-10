using System.Buffers.Binary;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using AppProxy.UI.Models;
using AppProxy.UI.Services;
using Xunit;

namespace AppProxy.Tests;

public class TunnelClientsTests
{
    [Fact]
    public async Task Socks5TunnelClient_WithAuthAndDomain_RelaysDataCorrectly()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var echoListener = new TcpListener(IPAddress.Loopback, 0);
        echoListener.Start();
        int echoPort = ((IPEndPoint)echoListener.LocalEndpoint).Port;

        Task echoTask = RunEchoServerOnceAsync(echoListener, cts.Token);

        string? capturedTargetHost = null;
        int capturedTargetPort = 0;

        using var socksListener = new TcpListener(IPAddress.Loopback, 0);
        socksListener.Start();
        int socksPort = ((IPEndPoint)socksListener.LocalEndpoint).Port;

        Task socksTask = Task.Run(async () =>
        {
            using TcpClient client = await socksListener.AcceptTcpClientAsync(cts.Token);
            using NetworkStream ns = client.GetStream();

            // Greeting
            byte[] hdr = new byte[2];
            await ReadExactAsync(ns, hdr, cts.Token);
            byte[] methods = new byte[hdr[1]];
            await ReadExactAsync(ns, methods, cts.Token);
            await ns.WriteAsync(new byte[] { 0x05, 0x02 }, cts.Token);

            // RFC 1929 Auth
            byte[] authHdr = new byte[2];
            await ReadExactAsync(ns, authHdr, cts.Token);
            byte[] uBytes = new byte[authHdr[1]];
            await ReadExactAsync(ns, uBytes, cts.Token);
            byte[] pLen = new byte[1];
            await ReadExactAsync(ns, pLen, cts.Token);
            byte[] pBytes = new byte[pLen[0]];
            await ReadExactAsync(ns, pBytes, cts.Token);

            Assert.Equal("alice", Encoding.UTF8.GetString(uBytes));
            Assert.Equal("s3cr3t", Encoding.UTF8.GetString(pBytes));
            await ns.WriteAsync(new byte[] { 0x01, 0x00 }, cts.Token);

            // CONNECT request
            byte[] req = new byte[4];
            await ReadExactAsync(ns, req, cts.Token);
            Assert.Equal(0x03, req[3]); // Domain ATYP
            byte[] dLen = new byte[1];
            await ReadExactAsync(ns, dLen, cts.Token);
            byte[] dBytes = new byte[dLen[0]];
            await ReadExactAsync(ns, dBytes, cts.Token);
            capturedTargetHost = Encoding.UTF8.GetString(dBytes);
            byte[] portBytes = new byte[2];
            await ReadExactAsync(ns, portBytes, cts.Token);
            capturedTargetPort = BinaryPrimitives.ReadUInt16BigEndian(portBytes);

            await ns.WriteAsync(new byte[] { 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0 }, cts.Token);

            using var target = new TcpClient();
            await target.ConnectAsync(IPAddress.Loopback, echoPort, cts.Token);
            using var targetNs = target.GetStream();
            await Task.WhenAny(ns.CopyToAsync(targetNs, cts.Token), targetNs.CopyToAsync(ns, cts.Token));
        }, cts.Token);

        var proxy = new ProxyProfile
        {
            Name = "MockSocks5",
            Protocol = ProxyProtocol.Socks5,
            Host = "127.0.0.1",
            Port = socksPort,
            Username = "alice",
            Password = "s3cr3t"
        };

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, socksPort, cts.Token);
        using NetworkStream stream = client.GetStream();
        await Socks5TunnelClient.ConnectAsync(stream, proxy, "mock.domain.test", echoPort, null, cts.Token);

        byte[] payload = Encoding.UTF8.GetBytes("ping-socks5");
        await stream.WriteAsync(payload, cts.Token);
        byte[] recv = new byte[payload.Length];
        await ReadExactAsync(stream, recv, cts.Token);

        Assert.Equal("mock.domain.test", capturedTargetHost);
        Assert.Equal(echoPort, capturedTargetPort);
        Assert.Equal("ping-socks5", Encoding.UTF8.GetString(recv));

        client.Close();
        await Task.WhenAll(echoTask, socksTask);
    }

    [Fact]
    public async Task HttpConnectTunnelClient_WithBasicAuth_RelaysDataCorrectly()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        using var echoListener = new TcpListener(IPAddress.Loopback, 0);
        echoListener.Start();
        int echoPort = ((IPEndPoint)echoListener.LocalEndpoint).Port;

        Task echoTask = RunEchoServerOnceAsync(echoListener, cts.Token);

        string? receivedHeaders = null;
        using var httpProxyListener = new TcpListener(IPAddress.Loopback, 0);
        httpProxyListener.Start();
        int proxyPort = ((IPEndPoint)httpProxyListener.LocalEndpoint).Port;

        Task proxyTask = Task.Run(async () =>
        {
            using TcpClient client = await httpProxyListener.AcceptTcpClientAsync(cts.Token);
            using NetworkStream ns = client.GetStream();

            var raw = new List<byte>();
            byte[] b = new byte[1];
            while (true)
            {
                int n = await ns.ReadAsync(b, cts.Token);
                if (n <= 0) break;
                raw.Add(b[0]);
                int c = raw.Count;
                if (c >= 4 && raw[c - 4] == '\r' && raw[c - 3] == '\n' && raw[c - 2] == '\r' && raw[c - 1] == '\n')
                    break;
            }
            receivedHeaders = Encoding.ASCII.GetString(raw.ToArray());

            byte[] okResp = Encoding.ASCII.GetBytes("HTTP/1.1 200 Connection Established\r\n\r\n");
            await ns.WriteAsync(okResp, cts.Token);

            using var target = new TcpClient();
            await target.ConnectAsync(IPAddress.Loopback, echoPort, cts.Token);
            using var targetNs = target.GetStream();
            await Task.WhenAny(ns.CopyToAsync(targetNs, cts.Token), targetNs.CopyToAsync(ns, cts.Token));
        }, cts.Token);

        var proxy = new ProxyProfile
        {
            Name = "MockHttp",
            Protocol = ProxyProtocol.Http,
            Host = "127.0.0.1",
            Port = proxyPort,
            Username = "bob",
            Password = "pw"
        };

        using var client = new TcpClient();
        await client.ConnectAsync(IPAddress.Loopback, proxyPort, cts.Token);
        using Stream stream = await HttpConnectTunnelClient.ConnectAsync(client.GetStream(), proxy, "example.org", echoPort, cts.Token);

        byte[] payload = Encoding.UTF8.GetBytes("ping-http");
        await stream.WriteAsync(payload, cts.Token);
        byte[] recv = new byte[payload.Length];
        await ReadExactAsync(stream, recv, cts.Token);

        Assert.NotNull(receivedHeaders);
        Assert.Contains($"CONNECT example.org:{echoPort} HTTP/1.1", receivedHeaders);
        Assert.Contains("Proxy-Authorization: Basic Ym9iOnB3", receivedHeaders);
        Assert.Equal("ping-http", Encoding.UTF8.GetString(recv));

        client.Close();
        await Task.WhenAll(echoTask, proxyTask);
    }

    private static async Task RunEchoServerOnceAsync(TcpListener listener, CancellationToken ct)
    {
        using TcpClient client = await listener.AcceptTcpClientAsync(ct);
        using NetworkStream ns = client.GetStream();
        byte[] buf = new byte[1024];
        int n = await ns.ReadAsync(buf, ct);
        if (n > 0)
        {
            await ns.WriteAsync(buf.AsMemory(0, n), ct);
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

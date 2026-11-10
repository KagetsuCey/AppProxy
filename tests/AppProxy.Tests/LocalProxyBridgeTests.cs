using System.Buffers.Binary;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using AppProxy.UI.Models;
using AppProxy.UI.Services;
using Xunit;

namespace AppProxy.Tests;

public class LocalProxyBridgeTests
{
    [Fact]
    public void IsLanOrLoopback_ClassifiesAddressesCorrectly()
    {
        Assert.True(LocalProxyBridge.IsLanOrLoopback(IPAddress.Loopback));
        Assert.True(LocalProxyBridge.IsLanOrLoopback(IPAddress.IPv6Loopback));
        Assert.True(LocalProxyBridge.IsLanOrLoopback(IPAddress.Parse("192.168.1.10")));
        Assert.True(LocalProxyBridge.IsLanOrLoopback(IPAddress.Parse("10.20.30.40")));
        Assert.True(LocalProxyBridge.IsLanOrLoopback(IPAddress.Parse("172.16.0.1")));
        Assert.True(LocalProxyBridge.IsLanOrLoopback(IPAddress.Parse("fe80::1")));

        // Fake-IPs must NEVER be treated as LAN
        Assert.False(LocalProxyBridge.IsLanOrLoopback(IPAddress.Parse("198.18.0.1")));
        Assert.False(LocalProxyBridge.IsLanOrLoopback(IPAddress.Parse("198.19.255.254")));
        Assert.False(LocalProxyBridge.IsLanOrLoopback(IPAddress.Parse("fd98:18::c612:1")));

        // Public IPs
        Assert.False(LocalProxyBridge.IsLanOrLoopback(IPAddress.Parse("1.1.1.1")));
        Assert.False(LocalProxyBridge.IsLanOrLoopback(IPAddress.Parse("8.8.8.8")));
    }

    [Fact]
    public async Task LocalProxyBridge_ResolvesFakeIpAndForwardsOverSocks5()
    {
        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        uint testBridgeId = (uint)(Random.Shared.Next(100000, 999999));
        using var shm = new SharedMemoryService(testBridgeId);
        using var bridge = new LocalProxyBridge(shm);

        using var socksListener = new TcpListener(IPAddress.Loopback, 0);
        socksListener.Start();
        int socksPort = ((IPEndPoint)socksListener.LocalEndpoint).Port;

        string? resolvedDomainFromProxy = null;
        Task socksServerTask = Task.Run(async () =>
        {
            using TcpClient proxyConn = await socksListener.AcceptTcpClientAsync(cts.Token);
            using NetworkStream ns = proxyConn.GetStream();

            byte[] greet = new byte[3];
            await ReadExactAsync(ns, greet, cts.Token);
            await ns.WriteAsync(new byte[] { 0x05, 0x00 }, cts.Token);

            byte[] req = new byte[4];
            await ReadExactAsync(ns, req, cts.Token);
            Assert.Equal(0x03, req[3]);
            byte[] lenBuf = new byte[1];
            await ReadExactAsync(ns, lenBuf, cts.Token);
            byte[] domainBuf = new byte[lenBuf[0]];
            await ReadExactAsync(ns, domainBuf, cts.Token);
            resolvedDomainFromProxy = Encoding.UTF8.GetString(domainBuf);
            byte[] portBuf = new byte[2];
            await ReadExactAsync(ns, portBuf, cts.Token);

            await ns.WriteAsync(new byte[] { 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0 }, cts.Token);

            byte[] msg = new byte[64];
            int n = await ns.ReadAsync(msg, cts.Token);
            await ns.WriteAsync(msg.AsMemory(0, n), cts.Token);
        }, cts.Token);

        var proxy = new ProxyProfile
        {
            Name = "TestSocks5",
            Protocol = ProxyProtocol.Socks5,
            Host = "127.0.0.1",
            Port = socksPort
        };

        const uint sessionId = 42;
        shm.RegisterSession(sessionId, NativeSessionFlags.RemoteDns | NativeSessionFlags.BypassLan);
        bridge.RegisterSession(new SessionContext
        {
            SessionId = sessionId,
            AppName = "test.exe",
            Proxy = proxy,
            BypassLan = true,
            RemoteDns = true
        });

        uint fakeIpHostOrder = shm.WriteFakeIpForTest("echo.fake.local");
        byte[] fakeIpBytes = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(fakeIpBytes, fakeIpHostOrder);

        using var appSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        appSocket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        ushort localPort = (ushort)((IPEndPoint)appSocket.LocalEndPoint!).Port;

        shm.WriteNatEntryForTest(localPort, 4, NativeTargetAddrType.FakeIp, sessionId, 1234, fakeIpBytes, 443);

        await appSocket.ConnectAsync(IPAddress.Loopback, bridge.PortV4, cts.Token);
        using var appStream = new NetworkStream(appSocket, ownsSocket: false);

        byte[] outBytes = Encoding.UTF8.GetBytes("hello-bridge");
        await appStream.WriteAsync(outBytes, cts.Token);
        byte[] inBytes = new byte[outBytes.Length];
        await ReadExactAsync(appStream, inBytes, cts.Token);

        Assert.Equal("echo.fake.local", resolvedDomainFromProxy);
        Assert.Equal("hello-bridge", Encoding.UTF8.GetString(inBytes));

        appSocket.Close();
        await socksServerTask;
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

using System.Buffers;
using System.Buffers.Binary;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace AppProxy.Core.Services;

/// <summary>
/// Loopback-only RFC 1928 / RFC 1929 SOCKS5 proxy that forwards outbound TCP connections
/// through OutboundSocketConnector, allowing managed sidecar processes (such as xray.exe)
/// to inherit AppProxy's physical NIC selection, DoH resolution, and global TUN bypass.
/// </summary>
public sealed class PhysicalDirectSocksProxy : IDisposable
{
    private readonly TcpListener _listener;
    private readonly bool _bypassGlobalTun;
    private readonly string? _preferredOutboundInterface;
    private readonly CancellationTokenSource _cts = new();
    private bool _disposed;

    public int Port { get; }
    public string Username { get; }
    public string Password { get; }

    public PhysicalDirectSocksProxy(bool bypassGlobalTun, string? preferredOutboundInterface = null)
    {
        _bypassGlobalTun = bypassGlobalTun;
        _preferredOutboundInterface = preferredOutboundInterface;
        Username = Guid.NewGuid().ToString("N")[..16];
        Password = Guid.NewGuid().ToString("N")[..16];

        _listener = new TcpListener(IPAddress.Loopback, 0);
        _listener.Start(128);
        Port = ((IPEndPoint)_listener.LocalEndpoint).Port;

        _ = AcceptLoopAsync(_cts.Token);
    }

    private async Task AcceptLoopAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await _listener.AcceptTcpClientAsync(ct);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch
            {
                continue;
            }

            _ = Task.Run(() => HandleClientAsync(client, ct), ct);
        }
    }

    private async Task HandleClientAsync(TcpClient localClient, CancellationToken ct)
    {
        TcpClient? upstreamClient = null;
        try
        {
            localClient.NoDelay = true;
            using NetworkStream localStream = localClient.GetStream();

            // 1. Greeting: VER (1) + NMETHODS (1)
            byte[] header = new byte[2];
            await ReadExactAsync(localStream, header, ct);
            if (header[0] != 0x05 || header[1] == 0)
            {
                return;
            }

            byte[] methods = new byte[header[1]];
            await ReadExactAsync(localStream, methods, ct);
            if (Array.IndexOf(methods, (byte)0x02) < 0)
            {
                await localStream.WriteAsync(new byte[] { 0x05, 0xFF }, ct);
                return;
            }

            await localStream.WriteAsync(new byte[] { 0x05, 0x02 }, ct);

            // 2. RFC 1929 Username/Password authentication
            byte[] authVer = new byte[2];
            await ReadExactAsync(localStream, authVer, ct);
            if (authVer[0] != 0x01)
            {
                await localStream.WriteAsync(new byte[] { 0x01, 0x01 }, ct);
                return;
            }

            byte[] userBuf = new byte[authVer[1]];
            if (userBuf.Length > 0)
            {
                await ReadExactAsync(localStream, userBuf, ct);
            }

            byte[] passLenBuf = new byte[1];
            await ReadExactAsync(localStream, passLenBuf, ct);
            byte[] passBuf = new byte[passLenBuf[0]];
            if (passBuf.Length > 0)
            {
                await ReadExactAsync(localStream, passBuf, ct);
            }

            string user = Encoding.UTF8.GetString(userBuf);
            string pass = Encoding.UTF8.GetString(passBuf);
            if (!string.Equals(user, Username, StringComparison.Ordinal) ||
                !string.Equals(pass, Password, StringComparison.Ordinal))
            {
                await localStream.WriteAsync(new byte[] { 0x01, 0x01 }, ct);
                return;
            }

            await localStream.WriteAsync(new byte[] { 0x01, 0x00 }, ct);

            // 3. Request: VER (1) + CMD (1) + RSV (1) + ATYP (1)
            byte[] req = new byte[4];
            await ReadExactAsync(localStream, req, ct);
            if (req[0] != 0x05)
            {
                return;
            }

            if (req[1] != 0x01) // CONNECT only
            {
                await SendReplyAsync(localStream, 0x07, ct);
                return;
            }

            string targetHost;
            IPAddress? preResolvedIp = null;
            switch (req[3])
            {
                case 0x01: // IPv4
                {
                    byte[] addr = new byte[4];
                    await ReadExactAsync(localStream, addr, ct);
                    preResolvedIp = new IPAddress(addr);
                    targetHost = preResolvedIp.ToString();
                    break;
                }
                case 0x03: // Domain
                {
                    byte[] lenBuf = new byte[1];
                    await ReadExactAsync(localStream, lenBuf, ct);
                    byte[] domainBuf = new byte[lenBuf[0]];
                    if (domainBuf.Length > 0)
                    {
                        await ReadExactAsync(localStream, domainBuf, ct);
                    }
                    targetHost = Encoding.UTF8.GetString(domainBuf);
                    if (IPAddress.TryParse(targetHost, out var parsed))
                    {
                        preResolvedIp = parsed;
                    }
                    break;
                }
                case 0x04: // IPv6
                {
                    byte[] addr = new byte[16];
                    await ReadExactAsync(localStream, addr, ct);
                    preResolvedIp = new IPAddress(addr);
                    targetHost = preResolvedIp.ToString();
                    break;
                }
                default:
                    await SendReplyAsync(localStream, 0x08, ct);
                    return;
            }

            byte[] portBuf = new byte[2];
            await ReadExactAsync(localStream, portBuf, ct);
            int targetPort = BinaryPrimitives.ReadUInt16BigEndian(portBuf);

            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            connectCts.CancelAfter(TimeSpan.FromSeconds(15));

            try
            {
                upstreamClient = await OutboundSocketConnector.ConnectAsync(
                    targetHost,
                    targetPort,
                    preResolvedIp,
                    _bypassGlobalTun,
                    _preferredOutboundInterface,
                    connectCts.Token);
            }
            catch (SocketException sex)
            {
                byte rep = sex.SocketErrorCode switch
                {
                    SocketError.ConnectionRefused => 0x05,
                    SocketError.NetworkUnreachable => 0x03,
                    SocketError.HostUnreachable => 0x04,
                    _ => 0x01
                };
                await SendReplyAsync(localStream, rep, ct);
                return;
            }
            catch
            {
                await SendReplyAsync(localStream, 0x01, ct);
                return;
            }

            await SendReplyAsync(localStream, 0x00, ct);

            using NetworkStream upstreamStream = upstreamClient.GetStream();
            Task upTask = RelayAsync(localStream, upstreamStream, localClient.Client, upstreamClient.Client, ct);
            Task downTask = RelayAsync(upstreamStream, localStream, upstreamClient.Client, localClient.Client, ct);
            await Task.WhenAll(upTask, downTask);
        }
        catch
        {
        }
        finally
        {
            upstreamClient?.Dispose();
            localClient.Dispose();
        }
    }

    private static Task SendReplyAsync(Stream stream, byte rep, CancellationToken ct)
    {
        byte[] reply = { 0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0 };
        return stream.WriteAsync(reply, ct).AsTask();
    }

    private static async Task ReadExactAsync(Stream stream, byte[] buffer, CancellationToken ct)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            int n = await stream.ReadAsync(buffer.AsMemory(read, buffer.Length - read), ct);
            if (n <= 0)
            {
                throw new EndOfStreamException();
            }
            read += n;
        }
    }

    private static async Task RelayAsync(
        NetworkStream source,
        NetworkStream destination,
        Socket sourceSocket,
        Socket destSocket,
        CancellationToken ct)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(32768);
        try
        {
            while (!ct.IsCancellationRequested)
            {
                int read = await source.ReadAsync(buffer.AsMemory(0, buffer.Length), ct);
                if (read <= 0) break;
                await destination.WriteAsync(buffer.AsMemory(0, read), ct);
            }
            try { destSocket.Shutdown(SocketShutdown.Send); } catch { }
        }
        catch
        {
            try { sourceSocket.Shutdown(SocketShutdown.Both); } catch { }
            try { destSocket.Shutdown(SocketShutdown.Both); } catch { }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cts.Cancel();
        try { _listener.Stop(); } catch { }
        _cts.Dispose();
    }
}

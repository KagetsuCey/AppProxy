using System.Buffers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using AppProxy.UI.Models;

namespace AppProxy.UI.Services;

public sealed class SessionContext
{
    public uint SessionId { get; init; }
    public string AppName { get; init; } = string.Empty;
    public ProxyProfile? Proxy { get; set; }
    public bool BypassLan { get; set; } = true;
    public bool RemoteDns { get; set; } = true;
}

public sealed class LocalProxyBridge : IDisposable
{
    private readonly SharedMemoryService _shm;
    private readonly TcpListener _listenerV4;
    private readonly TcpListener _listenerV6;
    private readonly CancellationTokenSource _cts = new();
    private readonly ConcurrentDictionary<uint, SessionContext> _sessions = new();
    private long _nextConnId;
    private int _activeConnections;
    private bool _disposed;

    public ushort PortV4 { get; }
    public ushort PortV6 { get; }
    public int ActiveConnections => Volatile.Read(ref _activeConnections);

    public event Action<ConnectionRecord>? ConnectionCreated;

    public LocalProxyBridge(SharedMemoryService shm)
    {
        _shm = shm;

        _listenerV4 = new TcpListener(IPAddress.Loopback, 0);
        _listenerV4.Start(256);
        PortV4 = (ushort)((IPEndPoint)_listenerV4.LocalEndpoint).Port;

        ushort v6Port = 0;
        _listenerV6 = new TcpListener(IPAddress.IPv6Loopback, 0);
        try
        {
            _listenerV6.Start(256);
            v6Port = (ushort)((IPEndPoint)_listenerV6.LocalEndpoint).Port;
        }
        catch
        {
            // IPv6 loopback may be disabled on some systems; IPv4 bridge still operates
        }
        PortV6 = v6Port;

        _shm.SetBridgePorts(PortV4, PortV6);

        _ = AcceptLoopAsync(_listenerV4, ipFamily: 4, _cts.Token);
        if (PortV6 != 0)
        {
            _ = AcceptLoopAsync(_listenerV6, ipFamily: 6, _cts.Token);
        }
    }

    public void RegisterSession(SessionContext context)
    {
        _sessions[context.SessionId] = context;
    }

    public void UnregisterSession(uint sessionId)
    {
        _sessions.TryRemove(sessionId, out _);
    }

    private async Task AcceptLoopAsync(TcpListener listener, byte ipFamily, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            TcpClient client;
            try
            {
                client = await listener.AcceptTcpClientAsync(ct);
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

            _ = Task.Run(() => HandleClientAsync(client, ipFamily, ct), ct);
        }
    }

    private async Task HandleClientAsync(TcpClient localClient, byte ipFamily, CancellationToken ct)
    {
        Interlocked.Increment(ref _activeConnections);
        ConnectionRecord? record = null;
        TcpClient? upstreamClient = null;
        Stream? upstreamStream = null;

        try
        {
            localClient.NoDelay = true;
            if (localClient.Client.RemoteEndPoint is not IPEndPoint remoteEp)
            {
                return;
            }

            ushort localPort = (ushort)remoteEp.Port;
            NatLookupResult? nat = _shm.LookupNatAndResolveTarget(localPort, ipFamily);
            if (nat is null)
            {
                return;
            }

            _sessions.TryGetValue(nat.SessionId, out SessionContext? session);
            ProxyProfile? proxy = session?.Proxy;
            bool bypassLan = session?.BypassLan ?? true;

            bool shouldDirect = proxy is null || (bypassLan && nat.TargetIp is not null && IsLanOrLoopback(nat.TargetIp));
            string processLabel = session is not null && !string.IsNullOrEmpty(session.AppName)
                ? session.AppName
                : ResolveProcessName(nat.Pid);

            string targetDisplay = IPAddress.TryParse(nat.TargetHost, out var parsed) && parsed.AddressFamily == AddressFamily.InterNetworkV6
                ? $"[{nat.TargetHost}]:{nat.TargetPort}"
                : $"{nat.TargetHost}:{nat.TargetPort}";

            record = new ConnectionRecord
            {
                Id = Interlocked.Increment(ref _nextConnId),
                StartTime = DateTime.Now,
                ProcessName = processLabel,
                Pid = nat.Pid,
                TargetDisplay = targetDisplay,
                FakeIp = nat.FakeIpString ?? string.Empty,
                ProxyName = shouldDirect ? "Direct" : proxy!.Name,
                Protocol = shouldDirect ? "Direct" : proxy!.ProtocolDisplay,
                Status = "Connecting"
            };
            ConnectionCreated?.Invoke(record);

            var sw = Stopwatch.StartNew();
            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            connectCts.CancelAfter(TimeSpan.FromSeconds(15));

            upstreamClient = new TcpClient { NoDelay = true };
            if (shouldDirect)
            {
                if (nat.TargetIp is not null)
                {
                    await upstreamClient.ConnectAsync(nat.TargetIp, nat.TargetPort, connectCts.Token);
                }
                else
                {
                    await upstreamClient.ConnectAsync(nat.TargetHost, nat.TargetPort, connectCts.Token);
                }
                upstreamStream = upstreamClient.GetStream();
            }
            else
            {
                await upstreamClient.ConnectAsync(proxy!.Host, proxy.Port, connectCts.Token);
                NetworkStream baseStream = upstreamClient.GetStream();
                if (proxy.Protocol == ProxyProtocol.Socks5)
                {
                    await Socks5TunnelClient.ConnectAsync(
                        baseStream,
                        proxy,
                        nat.TargetHost,
                        nat.TargetPort,
                        nat.TargetIp,
                        connectCts.Token);
                    upstreamStream = baseStream;
                }
                else
                {
                    upstreamStream = await HttpConnectTunnelClient.ConnectAsync(
                        baseStream,
                        proxy,
                        nat.TargetHost,
                        nat.TargetPort,
                        connectCts.Token);
                }
            }

            sw.Stop();
            record.UpdateState("Active", (int)sw.ElapsedMilliseconds);

            using NetworkStream localStream = localClient.GetStream();
            Task upTask = RelayAsync(
                localStream,
                upstreamStream,
                localClient.Client,
                upstreamClient.Client,
                bytes => record.AddBytesUp(bytes),
                ct);
            Task downTask = RelayAsync(
                upstreamStream,
                localStream,
                upstreamClient.Client,
                localClient.Client,
                bytes => record.AddBytesDown(bytes),
                ct);

            await Task.WhenAll(upTask, downTask);
            record.UpdateState("Closed");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            record?.UpdateState("Error", error: ex.Message);
        }
        finally
        {
            Interlocked.Decrement(ref _activeConnections);
            upstreamStream?.Dispose();
            upstreamClient?.Dispose();
            localClient.Dispose();
        }
    }

    private static async Task RelayAsync(
        Stream source,
        Stream destination,
        Socket sourceSocket,
        Socket destSocket,
        Action<long> onBytes,
        CancellationToken ct)
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(32768);
        try
        {
            while (!ct.IsCancellationRequested)
            {
                int read = await source.ReadAsync(buffer.AsMemory(0, buffer.Length), ct);
                if (read <= 0)
                {
                    break;
                }
                await destination.WriteAsync(buffer.AsMemory(0, read), ct);
                onBytes(read);
            }

            if (destination is NetworkStream)
            {
                try { destSocket.Shutdown(SocketShutdown.Send); } catch { }
            }
            else if (destination is SslStream ssl)
            {
                try { await ssl.ShutdownAsync(); } catch { }
            }
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

    public static bool IsLanOrLoopback(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return true;

        if (ip.IsIPv4MappedToIPv6)
        {
            ip = ip.MapToIPv4();
        }

        byte[] b = ip.GetAddressBytes();
        if (ip.AddressFamily == AddressFamily.InterNetwork && b.Length == 4)
        {
            // Never bypass Fake-IP (198.18.0.0/15)
            if (b[0] == 198 && (b[1] & 0xFE) == 18) return false;

            if (b[0] == 127 || b[0] == 10 || b[0] == 0) return true;
            if (b[0] == 172 && b[1] >= 16 && b[1] <= 31) return true;
            if (b[0] == 192 && b[1] == 168) return true;
            if (b[0] == 169 && b[1] == 254) return true;
            if (b[0] == 100 && b[1] >= 64 && b[1] <= 127) return true;
            if (b[0] >= 224) return true;
            return false;
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6 && b.Length == 16)
        {
            // Never bypass Fake-IPv6 (fd98:0018::/96)
            if (b[0] == 0xFD && b[1] == 0x98 && b[2] == 0x00 && b[3] == 0x18) return false;

            if (ip.IsIPv6LinkLocal || ip.IsIPv6Multicast || ip.IsIPv6SiteLocal) return true;
            if ((b[0] & 0xFE) == 0xFC) return true;
            return false;
        }

        return false;
    }

    private static string ResolveProcessName(uint pid)
    {
        try
        {
            using var p = Process.GetProcessById((int)pid);
            return p.ProcessName + ".exe";
        }
        catch
        {
            return $"PID:{pid}";
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cts.Cancel();
        try { _listenerV4.Stop(); } catch { }
        try { _listenerV6.Stop(); } catch { }
        _cts.Dispose();
    }
}

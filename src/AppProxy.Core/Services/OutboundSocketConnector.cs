using System.Net;
using System.Net.Sockets;

namespace AppProxy.Core.Services;

/// <summary>
/// Establishes outbound TCP connections bound to a healthy physical interface via IP_UNICAST_IF /
/// IPV6_UNICAST_IF so traffic bypasses global TUN virtual adapters, while failing over cleanly across
/// multiple NICs when cables are unplugged or DHCP IPs change.
/// </summary>
public static class OutboundSocketConnector
{
    private const int IP_UNICAST_IF = 31;
    private const int IPV6_UNICAST_IF = 31;

    public static bool IsLoopbackHostOrIp(string host, IPAddress? resolvedIp = null)
    {
        if (resolvedIp is not null)
        {
            if (IPAddress.IsLoopback(resolvedIp)) return true;
            if (resolvedIp.IsIPv4MappedToIPv6 && IPAddress.IsLoopback(resolvedIp.MapToIPv4())) return true;
        }

        if (string.IsNullOrWhiteSpace(host)) return false;
        string trimmed = host.Trim();
        if (string.Equals(trimmed, "localhost", StringComparison.OrdinalIgnoreCase) ||
            trimmed.EndsWith(".localhost", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (IPAddress.TryParse(trimmed, out IPAddress? parsed))
        {
            if (IPAddress.IsLoopback(parsed)) return true;
            if (parsed.IsIPv4MappedToIPv6 && IPAddress.IsLoopback(parsed.MapToIPv4())) return true;
        }

        return false;
    }

    public static void ApplyUnicastInterface(Socket socket, AddressFamily targetFamily, OutboundInterfaceInfo outbound)
    {
        if (targetFamily == AddressFamily.InterNetwork && outbound.IPv4Index is > 0 and int ifV4)
        {
            // IP_UNICAST_IF requires network byte order (big-endian) on Windows
            int bigEndianIf = IPAddress.HostToNetworkOrder(ifV4);
            socket.SetSocketOption(SocketOptionLevel.IP, (SocketOptionName)IP_UNICAST_IF, bigEndianIf);
        }
        else if (targetFamily == AddressFamily.InterNetworkV6 && outbound.IPv6Index is > 0 and int ifV6)
        {
            // IPV6_UNICAST_IF requires host byte order on Windows
            socket.SetSocketOption(SocketOptionLevel.IPv6, (SocketOptionName)IPV6_UNICAST_IF, ifV6);
        }
    }

    public static async Task<TcpClient> ConnectAsync(
        string host,
        int port,
        IPAddress? preResolvedIp,
        bool bypassGlobalTun,
        string? preferredInterface,
        CancellationToken ct)
    {
        if (!bypassGlobalTun || IsLoopbackHostOrIp(host, preResolvedIp))
        {
            return await ConnectDefaultAsync(host, port, preResolvedIp, ct);
        }

        IReadOnlyList<OutboundInterfaceInfo> candidates =
            PhysicalNetworkSelector.ResolveOutboundCandidates(preferredInterface);
        if (candidates.Count == 0)
        {
            return await ConnectDefaultAsync(host, port, preResolvedIp, ct);
        }

        Exception? lastException = null;
        var triedInterfaceIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        // Allow up to 2 passes across distinct physical interfaces (2nd pass catches mid-flight NIC/IP change)
        for (int pass = 0; pass < 2; pass++)
        {
            foreach (OutboundInterfaceInfo candidate in candidates)
            {
                if (ct.IsCancellationRequested) break;
                if (!triedInterfaceIds.Add(candidate.Id)) continue;

                try
                {
                    IPAddress[] targetIps = preResolvedIp is not null
                        ? [preResolvedIp]
                        : await PhysicalDnsResolver.ResolveAsync(host, candidate, ct);

                    bool attemptedAnyIp = false;
                    foreach (IPAddress ip in targetIps)
                    {
                        if (ct.IsCancellationRequested) break;
                        if (ip.AddressFamily == AddressFamily.InterNetwork && !candidate.HasUsableIPv4) continue;
                        if (ip.AddressFamily == AddressFamily.InterNetworkV6 && !candidate.HasUsableIPv6) continue;

                        attemptedAnyIp = true;
                        var tcp = new TcpClient(ip.AddressFamily) { NoDelay = true };
                        try
                        {
                            ApplyUnicastInterface(tcp.Client, ip.AddressFamily, candidate);
                            await tcp.ConnectAsync(ip, port, ct);
                            return tcp;
                        }
                        catch (OperationCanceledException) when (ct.IsCancellationRequested)
                        {
                            tcp.Dispose();
                            throw;
                        }
                        catch (SocketException sex)
                        {
                            tcp.Dispose();
                            lastException = sex;
                            if (sex.SocketErrorCode == SocketError.ConnectionRefused && targetIps.Length == 1)
                            {
                                throw;
                            }
                            if (IsRecoverableLinkError(sex.SocketErrorCode))
                            {
                                PhysicalNetworkSelector.InvalidateCache();
                            }
                        }
                        catch (Exception ex)
                        {
                            tcp.Dispose();
                            lastException = ex;
                        }
                    }

                    if (!attemptedAnyIp)
                    {
                        lastException ??= new SocketException((int)SocketError.AddressFamilyNotSupported);
                    }
                }
                catch (OperationCanceledException) when (ct.IsCancellationRequested)
                {
                    throw;
                }
                catch (SocketException sex) when (sex.SocketErrorCode == SocketError.ConnectionRefused)
                {
                    // Target host actually responded with RST; do not fail over to other NICs or TUN
                    throw;
                }
                catch (SocketException sex) when (IsRecoverableLinkError(sex.SocketErrorCode))
                {
                    lastException = sex;
                    PhysicalNetworkSelector.InvalidateCache();
                }
                catch (Exception ex)
                {
                    lastException = ex;
                }
            }

            // Re-probe OS interfaces once in case cable was unplugged or DHCP lease renewed during pass 0
            if (pass == 0 && !ct.IsCancellationRequested)
            {
                PhysicalNetworkSelector.InvalidateCache();
                candidates = PhysicalNetworkSelector.ResolveOutboundCandidates(preferredInterface);
            }
        }

        // If no global TUN adapter is active, allow OS default route fallback;
        // if TUN IS active, surface the physical error instead of silently looping back into TUN.
        if (!PhysicalNetworkSelector.HasActiveTunAdapter())
        {
            return await ConnectDefaultAsync(host, port, preResolvedIp, ct);
        }

        throw lastException ?? new SocketException((int)SocketError.NetworkUnreachable);
    }

    private static async Task<TcpClient> ConnectDefaultAsync(
        string host,
        int port,
        IPAddress? preResolvedIp,
        CancellationToken ct)
    {
        var tcp = new TcpClient { NoDelay = true };
        try
        {
            if (preResolvedIp is not null)
            {
                await tcp.ConnectAsync(preResolvedIp, port, ct);
            }
            else
            {
                await tcp.ConnectAsync(host, port, ct);
            }
            return tcp;
        }
        catch
        {
            tcp.Dispose();
            throw;
        }
    }

    private static bool IsRecoverableLinkError(SocketError error) => error is
        SocketError.NetworkUnreachable or
        SocketError.HostUnreachable or
        SocketError.NetworkDown or
        SocketError.HostDown or
        SocketError.AddressNotAvailable or
        SocketError.NetworkReset or
        SocketError.AccessDenied or
        SocketError.TimedOut;
}

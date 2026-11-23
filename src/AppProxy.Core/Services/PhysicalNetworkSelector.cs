using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace AppProxy.Core.Services;

public sealed record OutboundInterfaceInfo
{
    public required string Id { get; init; }
    public required string Name { get; init; }
    public required string Description { get; init; }
    public NetworkInterfaceType InterfaceType { get; init; }
    public int? IPv4Index { get; init; }
    public int? IPv6Index { get; init; }
    public IPAddress? IPv4Address { get; init; }
    public IPAddress? IPv6Address { get; init; }
    public IReadOnlyList<IPAddress> IPv4DnsServers { get; init; } = [];
    public IReadOnlyList<IPAddress> IPv6DnsServers { get; init; } = [];
    public bool IsVirtualOrTun { get; init; }
    public bool IsTunOrVpn { get; init; }
    public bool HasDefaultGatewayV4 { get; init; }
    public bool HasDefaultGatewayV6 { get; init; }
    public int EffectiveMetricV4 { get; init; } = int.MaxValue;
    public int EffectiveMetricV6 { get; init; } = int.MaxValue;

    public bool HasUsableIPv4 => IPv4Index is > 0 && IPv4Address is not null && HasDefaultGatewayV4;
    public bool HasUsableIPv6 => IPv6Index is > 0 && IPv6Address is not null && HasDefaultGatewayV6;
    public bool HasAnyUsableRoute => HasUsableIPv4 || HasUsableIPv6;

    public string DisplayIp =>
        IPv4Address?.ToString()
        ?? IPv6Address?.ToString()
        ?? "无有效 IP";

    public string DisplaySummary => $"{Name} ({DisplayIp})";
}

/// <summary>
/// Discovers healthy physical outbound network interfaces and filters out TUN/VPN/virtual adapters,
/// reacting immediately to cable unplugs, Wi-Fi switches, and DHCP IP changes.
/// </summary>
public static class PhysicalNetworkSelector
{
    private const int IfTypePropVirtual = 53;
    private const int ErrorInsufficientBuffer = 122;
    private static readonly TimeSpan CacheTtl = TimeSpan.FromSeconds(3);

    private static readonly string[] VirtualOrTunKeywords =
    [
        "wintun",
        "sing-tun",
        "singbox",
        "xray_tun",
        "mihomo",
        "clash",
        "tap-windows",
        "openvpn",
        "wireguard",
        "tailscale",
        "zerotier",
        "hyper-v",
        "vethernet",
        "wsl",
        "docker",
        "vmware",
        "virtualbox",
        "vbox",
        "bluetooth",
        "wi-fi direct",
        "wan miniport",
        "kernel debug",
        "teredo",
        "6to4",
        "isatap",
        "ip-https",
        "loopback",
        "utun",
        "tunnel"
    ];

    private static readonly string[] TunOrVpnKeywords =
    [
        "wintun",
        "sing-tun",
        "singbox",
        "xray_tun",
        "mihomo",
        "clash",
        "tap-windows",
        "openvpn",
        "wireguard",
        "tailscale",
        "zerotier",
        "utun",
        "tun"
    ];

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_IPFORWARDROW
    {
        public uint dwForwardDest;
        public uint dwForwardMask;
        public uint dwForwardPolicy;
        public uint dwForwardNextHop;
        public uint dwForwardIfIndex;
        public uint dwForwardType;
        public uint dwForwardProto;
        public uint dwForwardAge;
        public uint dwForwardNextHopAS;
        public int dwForwardMetric1;
        public int dwForwardMetric2;
        public int dwForwardMetric3;
        public int dwForwardMetric4;
        public int dwForwardMetric5;
    }

    [DllImport("iphlpapi.dll")]
    private static extern uint GetIpForwardTable(IntPtr pIpForwardTable, ref int pdwSize, bool bOrder);

    private sealed record NetworkSnapshot(
        long Epoch,
        DateTime CapturedUtc,
        IReadOnlyList<OutboundInterfaceInfo> AllUpInterfaces,
        IReadOnlyList<OutboundInterfaceInfo> HealthyPhysicalInterfaces,
        IReadOnlyList<string> ActiveTunAdapterNames);

    private static readonly object CacheLock = new();
    private static long _networkEpoch = 1;
    private static NetworkSnapshot? _cachedSnapshot;

    public static long NetworkEpoch => Volatile.Read(ref _networkEpoch);

    public static event Action? NetworkChanged;

    static PhysicalNetworkSelector()
    {
        try
        {
            NetworkChange.NetworkAddressChanged += OnOsNetworkChanged;
            NetworkChange.NetworkAvailabilityChanged += OnOsNetworkChanged;
        }
        catch
        {
            // Ignore in restricted environments
        }
    }

    private static void OnOsNetworkChanged(object? sender, EventArgs e)
    {
        InvalidateCache();
        Action? handlers = NetworkChanged;
        if (handlers is not null)
        {
            _ = Task.Run(() =>
            {
                try
                {
                    handlers.Invoke();
                }
                catch
                {
                }
            });
        }
    }

    public static void InvalidateCache()
    {
        Interlocked.Increment(ref _networkEpoch);
        lock (CacheLock)
        {
            _cachedSnapshot = null;
        }
    }

    public static bool IsVirtualOrTunAdapter(NetworkInterfaceType type, string? name, string? description)
    {
        int rawType = (int)type;
        if (type is NetworkInterfaceType.Loopback
            or NetworkInterfaceType.Tunnel
            or NetworkInterfaceType.Unknown
            || rawType == IfTypePropVirtual)
        {
            return true;
        }

        return ContainsAnyKeyword(name, VirtualOrTunKeywords)
            || ContainsAnyKeyword(description, VirtualOrTunKeywords);
    }

    public static bool IsTunOrVpnAdapter(NetworkInterfaceType type, string? name, string? description)
    {
        int rawType = (int)type;
        if (type == NetworkInterfaceType.Tunnel || rawType == IfTypePropVirtual)
        {
            return true;
        }

        return ContainsAnyKeyword(name, TunOrVpnKeywords)
            || ContainsAnyKeyword(description, TunOrVpnKeywords);
    }

    public static IReadOnlyList<OutboundInterfaceInfo> ResolveOutboundCandidates(string? preferredInterfaceIdOrName = null)
    {
        NetworkSnapshot snapshot = GetSnapshot();
        var result = new List<OutboundInterfaceInfo>(snapshot.HealthyPhysicalInterfaces.Count + 1);

        if (!string.IsNullOrWhiteSpace(preferredInterfaceIdOrName))
        {
            string trimmed = preferredInterfaceIdOrName.Trim();
            OutboundInterfaceInfo? preferred = snapshot.AllUpInterfaces.FirstOrDefault(iface =>
                string.Equals(iface.Id, trimmed, StringComparison.OrdinalIgnoreCase) ||
                string.Equals(iface.Name, trimmed, StringComparison.OrdinalIgnoreCase));

            if (preferred is not null && preferred.HasAnyUsableRoute)
            {
                result.Add(preferred);
            }
        }

        foreach (OutboundInterfaceInfo iface in snapshot.HealthyPhysicalInterfaces)
        {
            if (!result.Any(existing => string.Equals(existing.Id, iface.Id, StringComparison.OrdinalIgnoreCase)))
            {
                result.Add(iface);
            }
        }

        return result;
    }

    public static OutboundInterfaceInfo? ResolveBestOutboundInterface(string? preferredInterfaceIdOrName = null)
    {
        IReadOnlyList<OutboundInterfaceInfo> candidates = ResolveOutboundCandidates(preferredInterfaceIdOrName);
        return candidates.Count > 0 ? candidates[0] : null;
    }

    public static IReadOnlyList<OutboundInterfaceInfo> GetSelectableInterfaces()
    {
        NetworkSnapshot snapshot = GetSnapshot();
        return snapshot.AllUpInterfaces
            .OrderBy(i => i.IsVirtualOrTun ? 1 : 0)
            .ThenBy(i => i.HasAnyUsableRoute ? 0 : 1)
            .ThenBy(i => Math.Min(i.EffectiveMetricV4, i.EffectiveMetricV6))
            .ThenBy(i => GetMediumPriority(i.InterfaceType))
            .ThenBy(i => i.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();
    }

    public static IReadOnlyList<string> GetActiveTunAdapterNames() =>
        GetSnapshot().ActiveTunAdapterNames;

    public static bool HasActiveTunAdapter() =>
        GetSnapshot().ActiveTunAdapterNames.Count > 0;

    private static NetworkSnapshot GetSnapshot()
    {
        long currentEpoch = Volatile.Read(ref _networkEpoch);
        DateTime nowUtc = DateTime.UtcNow;

        lock (CacheLock)
        {
            if (_cachedSnapshot is not null &&
                _cachedSnapshot.Epoch == currentEpoch &&
                (nowUtc - _cachedSnapshot.CapturedUtc) < CacheTtl)
            {
                return _cachedSnapshot;
            }
        }

        NetworkSnapshot fresh = CaptureSnapshot(currentEpoch, nowUtc);
        lock (CacheLock)
        {
            if (Volatile.Read(ref _networkEpoch) == fresh.Epoch)
            {
                _cachedSnapshot = fresh;
            }
        }
        return fresh;
    }

    private static NetworkSnapshot CaptureSnapshot(long epoch, DateTime capturedUtc)
    {
        Dictionary<int, int> ipv4DefaultMetrics = ReadIpv4DefaultRouteMetrics();
        var allUp = new List<OutboundInterfaceInfo>();
        var activeTuns = new List<string>();

        NetworkInterface[] adapters;
        try
        {
            adapters = NetworkInterface.GetAllNetworkInterfaces();
        }
        catch
        {
            return new NetworkSnapshot(epoch, capturedUtc, [], [], []);
        }

        foreach (NetworkInterface nic in adapters)
        {
            try
            {
                if (nic.OperationalStatus != OperationalStatus.Up)
                {
                    continue;
                }

                if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                {
                    continue;
                }

                // Skip NDIS lightweight filter / QoS / scheduler pseudo entries if any leak through
                if (IsFilterPseudoAdapter(nic.Name, nic.Description))
                {
                    continue;
                }

                bool isVirtualOrTun = IsVirtualOrTunAdapter(nic.NetworkInterfaceType, nic.Name, nic.Description);
                bool isTunOrVpn = IsTunOrVpnAdapter(nic.NetworkInterfaceType, nic.Name, nic.Description);

                IPInterfaceProperties ipProps;
                try
                {
                    ipProps = nic.GetIPProperties();
                }
                catch
                {
                    continue;
                }

                int? ipv4Idx = null;
                int? ipv6Idx = null;
                try
                {
                    IPv4InterfaceProperties v4Props = ipProps.GetIPv4Properties();
                    if (v4Props.Index > 0) ipv4Idx = v4Props.Index;
                }
                catch
                {
                }

                try
                {
                    IPv6InterfaceProperties v6Props = ipProps.GetIPv6Properties();
                    if (v6Props.Index > 0) ipv6Idx = v6Props.Index;
                }
                catch
                {
                }

                IPAddress? bestV4 = null;
                IPAddress? bestV6 = null;
                foreach (UnicastIPAddressInformation uni in ipProps.UnicastAddresses)
                {
                    IPAddress addr = uni.Address;
                    if (addr.AddressFamily == AddressFamily.InterNetwork)
                    {
                        if (!IPAddress.IsLoopback(addr) && !IsApipaV4(addr))
                        {
                            bestV4 ??= addr;
                        }
                    }
                    else if (addr.AddressFamily == AddressFamily.InterNetworkV6)
                    {
                        if (!IPAddress.IsLoopback(addr) && !addr.IsIPv6LinkLocal && !addr.IsIPv6Multicast)
                        {
                            bestV6 ??= addr;
                        }
                    }
                }

                bool hasGwV4 = false;
                bool hasGwV6 = false;
                foreach (GatewayIPAddressInformation gw in ipProps.GatewayAddresses)
                {
                    if (gw.Address.AddressFamily == AddressFamily.InterNetwork &&
                        !IPAddress.Any.Equals(gw.Address) &&
                        !IPAddress.IsLoopback(gw.Address))
                    {
                        hasGwV4 = true;
                    }
                    else if (gw.Address.AddressFamily == AddressFamily.InterNetworkV6 &&
                             !IPAddress.IPv6Any.Equals(gw.Address) &&
                             !IPAddress.IPv6Loopback.Equals(gw.Address))
                    {
                        hasGwV6 = true;
                    }
                }

                int metricV4 = int.MaxValue;
                if (ipv4Idx.HasValue && ipv4DefaultMetrics.TryGetValue(ipv4Idx.Value, out int routeMetric))
                {
                    hasGwV4 = true;
                    metricV4 = routeMetric;
                }
                else if (hasGwV4)
                {
                    metricV4 = 1000;
                }

                int metricV6 = hasGwV6 ? 1000 : int.MaxValue;

                var v4Dns = new List<IPAddress>();
                var v6Dns = new List<IPAddress>();
                foreach (IPAddress dns in ipProps.DnsAddresses)
                {
                    if (IPAddress.IsLoopback(dns)) continue;
                    if (dns.AddressFamily == AddressFamily.InterNetwork && !IsApipaV4(dns))
                    {
                        v4Dns.Add(dns);
                    }
                    else if (dns.AddressFamily == AddressFamily.InterNetworkV6 && !dns.IsIPv6LinkLocal)
                    {
                        v6Dns.Add(dns);
                    }
                }

                var info = new OutboundInterfaceInfo
                {
                    Id = nic.Id,
                    Name = nic.Name,
                    Description = nic.Description,
                    InterfaceType = nic.NetworkInterfaceType,
                    IPv4Index = ipv4Idx,
                    IPv6Index = ipv6Idx,
                    IPv4Address = bestV4,
                    IPv6Address = bestV6,
                    IPv4DnsServers = v4Dns,
                    IPv6DnsServers = v6Dns,
                    IsVirtualOrTun = isVirtualOrTun,
                    IsTunOrVpn = isTunOrVpn,
                    HasDefaultGatewayV4 = hasGwV4,
                    HasDefaultGatewayV6 = hasGwV6,
                    EffectiveMetricV4 = metricV4,
                    EffectiveMetricV6 = metricV6
                };

                allUp.Add(info);

                if (isTunOrVpn && (hasGwV4 || hasGwV6 || bestV4 is not null || bestV6 is not null))
                {
                    activeTuns.Add(nic.Name);
                }
            }
            catch
            {
                // Transient NIC state change while enumerating
            }
        }

        OutboundInterfaceInfo[] healthyPhysical = allUp
            .Where(i => !i.IsVirtualOrTun && i.HasAnyUsableRoute)
            .OrderBy(i => i.HasUsableIPv4 ? 0 : 1)
            .ThenBy(i => i.HasUsableIPv4 ? i.EffectiveMetricV4 : i.EffectiveMetricV6)
            .ThenBy(i => GetMediumPriority(i.InterfaceType))
            .ThenBy(i => i.Name, StringComparer.OrdinalIgnoreCase)
            .ToArray();

        return new NetworkSnapshot(epoch, capturedUtc, allUp, healthyPhysical, activeTuns);
    }

    private static Dictionary<int, int> ReadIpv4DefaultRouteMetrics()
    {
        var metrics = new Dictionary<int, int>();
        try
        {
            int size = 0;
            uint probe = GetIpForwardTable(IntPtr.Zero, ref size, bOrder: false);
            if (probe != ErrorInsufficientBuffer && probe != 0)
            {
                return metrics;
            }
            if (size <= 4)
            {
                return metrics;
            }

            IntPtr buffer = Marshal.AllocHGlobal(size);
            try
            {
                uint status = GetIpForwardTable(buffer, ref size, bOrder: false);
                if (status != 0)
                {
                    return metrics;
                }

                int count = Marshal.ReadInt32(buffer);
                int rowSize = Marshal.SizeOf<MIB_IPFORWARDROW>();
                if (count < 0 || 4 + ((long)count * rowSize) > size)
                {
                    return metrics;
                }

                for (int i = 0; i < count; i++)
                {
                    MIB_IPFORWARDROW row = Marshal.PtrToStructure<MIB_IPFORWARDROW>(
                        IntPtr.Add(buffer, 4 + (i * rowSize)));

                    // Default route 0.0.0.0/0
                    if (row.dwForwardDest == 0 && row.dwForwardMask == 0 && row.dwForwardIfIndex > 0)
                    {
                        int ifIdx = unchecked((int)row.dwForwardIfIndex);
                        int metric = row.dwForwardMetric1 >= 0 ? row.dwForwardMetric1 : int.MaxValue;
                        if (!metrics.TryGetValue(ifIdx, out int existing) || metric < existing)
                        {
                            metrics[ifIdx] = metric;
                        }
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch
        {
        }

        return metrics;
    }

    private static int GetMediumPriority(NetworkInterfaceType type) => type switch
    {
        NetworkInterfaceType.Ethernet
            or NetworkInterfaceType.Ethernet3Megabit
            or NetworkInterfaceType.FastEthernetT
            or NetworkInterfaceType.FastEthernetFx
            or NetworkInterfaceType.GigabitEthernet => 0,
        NetworkInterfaceType.Wireless80211 => 1,
        NetworkInterfaceType.Wwanpp
            or NetworkInterfaceType.Wwanpp2
            or NetworkInterfaceType.Ppp => 2,
        _ => 3
    };

    private static bool IsApipaV4(IPAddress addr)
    {
        byte[] bytes = addr.GetAddressBytes();
        return bytes.Length == 4 && bytes[0] == 169 && bytes[1] == 254;
    }

    private static bool IsFilterPseudoAdapter(string? name, string? description)
    {
        return ContainsAnyKeyword(
            name,
            ["-wfp ", "-qos packet scheduler", "-ndis ", "lightweight filter"])
            || ContainsAnyKeyword(
                description,
                ["lightweight filter", "qos packet scheduler", "ndis filter"]);
    }

    private static bool ContainsAnyKeyword(string? text, string[] keywords)
    {
        if (string.IsNullOrWhiteSpace(text)) return false;
        foreach (string kw in keywords)
        {
            if (text.Contains(kw, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }
        return false;
    }
}

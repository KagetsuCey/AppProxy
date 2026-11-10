using System.IO.MemoryMappedFiles;
using System.Net;
using System.Text;

namespace AppProxy.UI.Services;

[Flags]
public enum NativeSessionFlags : uint
{
    None = 0,
    RemoteDns = 1u << 0,
    BypassLan = 1u << 1,
    InjectChildren = 1u << 2,
    DirectMode = 1u << 3
}

public enum NativeTargetAddrType : byte
{
    Ipv4 = 1,
    Ipv6 = 2,
    FakeIp = 3
}

public sealed record NatLookupResult(
    uint SessionId,
    uint Pid,
    byte IpFamily,
    NativeTargetAddrType TargetType,
    string TargetHost,
    ushort TargetPort,
    string? FakeIpString,
    IPAddress? TargetIp);

public sealed class SharedMemoryService : IDisposable
{
    public const uint SharedMagic = 0x41505831; // "APX1"
    public const uint SharedVersion = 1;
    public const int MaxSessions = 256;
    public const int MaxFakeIps = 16384;
    public const int MaxNatSlots = 4096;
    public const uint FakeIpBase = 0xC6120001u; // 198.18.0.1

    private const int HeaderSize = 24;
    private const int SessionEntrySize = 12;
    private const int FakeIpEntrySize = 264;
    private const int NatEntrySize = 40;

    private const int SessionsOffset = HeaderSize;
    private const int FakeIpsOffset = SessionsOffset + (MaxSessions * SessionEntrySize);
    private const int NatTableOffset = FakeIpsOffset + (MaxFakeIps * FakeIpEntrySize);
    public const int TotalSharedBytes = NatTableOffset + (MaxNatSlots * NatEntrySize);

    private readonly uint _bridgeId;
    private readonly MemoryMappedFile _mmf;
    private readonly MemoryMappedViewAccessor _view;
    private readonly Mutex _mutex;
    private bool _disposed;

    public uint BridgeId => _bridgeId;

    public SharedMemoryService(uint? bridgeIdOverride = null)
    {
        _bridgeId = bridgeIdOverride ?? (uint)Environment.ProcessId;
        _mutex = new Mutex(false, $"Local\\AppProxy_Mutex_{_bridgeId}");
        _mmf = MemoryMappedFile.CreateNew($"Local\\AppProxy_Shared_{_bridgeId}", TotalSharedBytes);
        _view = _mmf.CreateViewAccessor(0, TotalSharedBytes, MemoryMappedFileAccess.ReadWrite);

        InitializeHeader();
    }

    private void InitializeHeader()
    {
        WithMutex(() =>
        {
            _view.Write(0, SharedMagic);
            _view.Write(4, SharedVersion);
            _view.Write(8, _bridgeId);
            _view.Write(12, (ushort)0);
            _view.Write(14, (ushort)0);
            _view.Write(16, (uint)0);
            _view.Write(20, (uint)0);
        });
    }

    public void SetBridgePorts(ushort portV4, ushort portV6)
    {
        WithMutex(() =>
        {
            _view.Write(12, portV4);
            _view.Write(14, portV6);
        });
    }

    public void RegisterSession(uint sessionId, NativeSessionFlags flags)
    {
        WithMutex(() =>
        {
            int freeSlot = -1;
            for (int i = 0; i < MaxSessions; i++)
            {
                int off = SessionsOffset + (i * SessionEntrySize);
                byte active = _view.ReadByte(off + 8);
                uint existingId = _view.ReadUInt32(off);
                if (active != 0 && existingId == sessionId)
                {
                    _view.Write(off + 4, (uint)flags);
                    return;
                }
                if (active == 0 && freeSlot == -1)
                {
                    freeSlot = i;
                }
            }

            int slot = freeSlot >= 0 ? freeSlot : (int)(sessionId % MaxSessions);
            int targetOff = SessionsOffset + (slot * SessionEntrySize);
            _view.Write(targetOff, sessionId);
            _view.Write(targetOff + 4, (uint)flags);
            _view.Write(targetOff + 8, (byte)1);
        });
    }

    public void UnregisterSession(uint sessionId)
    {
        WithMutex(() =>
        {
            for (int i = 0; i < MaxSessions; i++)
            {
                int off = SessionsOffset + (i * SessionEntrySize);
                if (_view.ReadByte(off + 8) != 0 && _view.ReadUInt32(off) == sessionId)
                {
                    _view.Write(off + 8, (byte)0);
                    return;
                }
            }
        });
    }

    public uint WriteFakeIpForTest(string domain)
    {
        uint assigned = 0;
        byte[] domainBytes = Encoding.UTF8.GetBytes(domain.TrimEnd('.').ToLowerInvariant());
        WithMutex(() =>
        {
            uint offset = _view.ReadUInt32(16) % MaxFakeIps;
            _view.Write(16, (offset + 1) % MaxFakeIps);
            assigned = FakeIpBase + offset;

            int entryOff = FakeIpsOffset + ((int)offset * FakeIpEntrySize);
            _view.Write(entryOff, assigned);
            _view.Write(entryOff + 4, (uint)Environment.TickCount);
            byte[] buf = new byte[256];
            Array.Copy(domainBytes, buf, Math.Min(domainBytes.Length, 255));
            _view.WriteArray(entryOff + 8, buf, 0, 256);
        });
        return assigned;
    }

    public void WriteNatEntryForTest(ushort localPort, byte ipFamily, NativeTargetAddrType targetType, uint sessionId, uint pid, byte[] addrBytes, ushort targetPort)
    {
        WithMutex(() =>
        {
            uint slot = _view.ReadUInt32(20) % MaxNatSlots;
            _view.Write(20, (slot + 1) % MaxNatSlots);
            int off = NatTableOffset + ((int)slot * NatEntrySize);

            _view.Write(off + 0, localPort);
            _view.Write(off + 2, ipFamily);
            _view.Write(off + 3, (byte)targetType);
            _view.Write(off + 4, sessionId);
            _view.Write(off + 8, pid);
            _view.Write(off + 12, targetPort);
            _view.Write(off + 14, (ushort)0);

            byte[] padded = new byte[16];
            Array.Copy(addrBytes, padded, Math.Min(addrBytes.Length, 16));
            _view.WriteArray(off + 16, padded, 0, 16);
            _view.Write(off + 32, (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        });
    }

    public NatLookupResult? LookupNatAndResolveTarget(ushort localPort, byte ipFamily)
    {
        NatLookupResult? result = null;
        ulong nowMs = (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        WithMutex(() =>
        {
            uint head = _view.ReadUInt32(20) % MaxNatSlots;
            for (int i = 1; i <= MaxNatSlots; i++)
            {
                int idx = (int)((head + MaxNatSlots - (uint)i) % MaxNatSlots);
                int off = NatTableOffset + (idx * NatEntrySize);

                ushort entryPort = _view.ReadUInt16(off);
                if (entryPort == 0) break;

                byte entryFamily = _view.ReadByte(off + 2);
                if (entryPort != localPort || entryFamily != ipFamily) continue;

                ulong ts = _view.ReadUInt64(off + 32);
                if (nowMs > ts && (nowMs - ts) > 60_000) continue;

                var targetType = (NativeTargetAddrType)_view.ReadByte(off + 3);
                uint sessionId = _view.ReadUInt32(off + 4);
                uint pid = _view.ReadUInt32(off + 8);
                ushort targetPort = _view.ReadUInt16(off + 12);
                byte[] addrBytes = new byte[16];
                _view.ReadArray(off + 16, addrBytes, 0, 16);

                result = ResolveTarget(sessionId, pid, ipFamily, targetType, addrBytes, targetPort);
                return;
            }
        });

        return result;
    }

    private NatLookupResult ResolveTarget(
        uint sessionId,
        uint pid,
        byte ipFamily,
        NativeTargetAddrType targetType,
        byte[] addrBytes,
        ushort targetPort)
    {
        if (targetType == NativeTargetAddrType.FakeIp)
        {
            uint fakeIpHostOrder;
            string fakeIpDisplay;
            if (ipFamily == 4)
            {
                fakeIpHostOrder = ((uint)addrBytes[0] << 24) |
                                  ((uint)addrBytes[1] << 16) |
                                  ((uint)addrBytes[2] << 8) |
                                  addrBytes[3];
                fakeIpDisplay = new IPAddress(addrBytes[..4]).ToString();
            }
            else
            {
                fakeIpHostOrder = ((uint)addrBytes[12] << 24) |
                                  ((uint)addrBytes[13] << 16) |
                                  ((uint)addrBytes[14] << 8) |
                                  addrBytes[15];
                fakeIpDisplay = new IPAddress(addrBytes).ToString();
            }

            string? domain = LookupFakeDomainUnlocked(fakeIpHostOrder);
            if (!string.IsNullOrEmpty(domain))
            {
                return new NatLookupResult(sessionId, pid, ipFamily, targetType, domain, targetPort, fakeIpDisplay, null);
            }
        }

        IPAddress ip = ipFamily == 4 ? new IPAddress(addrBytes[..4]) : new IPAddress(addrBytes);
        return new NatLookupResult(sessionId, pid, ipFamily, targetType, ip.ToString(), targetPort, null, ip);
    }

    private string? LookupFakeDomainUnlocked(uint fakeIpHostOrder)
    {
        if (fakeIpHostOrder < FakeIpBase) return null;
        uint slot = fakeIpHostOrder - FakeIpBase;
        if (slot >= MaxFakeIps) return null;

        int entryOff = FakeIpsOffset + ((int)slot * FakeIpEntrySize);
        uint storedIp = _view.ReadUInt32(entryOff);
        if (storedIp != fakeIpHostOrder) return null;

        byte[] buf = new byte[256];
        _view.ReadArray(entryOff + 8, buf, 0, 256);
        int len = Array.IndexOf(buf, (byte)0);
        if (len < 0) len = 256;
        return len == 0 ? null : Encoding.UTF8.GetString(buf, 0, len);
    }

    private void WithMutex(Action action)
    {
        bool acquired = false;
        try
        {
            acquired = _mutex.WaitOne(500);
        }
        catch (AbandonedMutexException)
        {
            acquired = true;
        }

        if (!acquired) return;
        try
        {
            action();
        }
        finally
        {
            _mutex.ReleaseMutex();
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _view.Dispose();
        _mmf.Dispose();
        _mutex.Dispose();
    }
}

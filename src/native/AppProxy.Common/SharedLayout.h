#pragma once

#include <cstddef>
#include <cstdint>

namespace AppProxy::IPC {

constexpr uint32_t kSharedMagic      = 0x41505831; // "APX1"
constexpr uint32_t kSharedVersion    = 1;
constexpr uint32_t kMaxSessions      = 256;
constexpr uint32_t kMaxFakeIps       = 16384;      // 198.18.0.1 .. 198.18.64.0 (within 198.18.0.0/15)
constexpr uint32_t kMaxNatSlots      = 4096;
constexpr uint32_t kFakeIpBase       = 0xC6120001u; // 198.18.0.1 in host byte order
constexpr uint32_t kFakeIpMaskPrefix = 0xC6120000u; // 198.18.0.0/15 mask = 0xFFFE0000

enum SessionFlags : uint32_t {
    FLAG_NONE            = 0,
    FLAG_REMOTE_DNS      = 1u << 0,
    FLAG_BYPASS_LAN      = 1u << 1,
    FLAG_INJECT_CHILDREN = 1u << 2,
    FLAG_DIRECT_MODE     = 1u << 3,
};

enum TargetAddrType : uint8_t {
    ADDR_IPV4   = 1,
    ADDR_IPV6   = 2,
    ADDR_FAKEIP = 3,
};

#pragma pack(push, 1)
struct SessionEntry {
    uint32_t sessionId;
    uint32_t flags;
    uint8_t  active;
    uint8_t  reserved[3];
};

struct FakeIpEntry {
    uint32_t fakeIpHostOrder;
    uint32_t lastUsedTick;
    char     domain[256];
};

struct NatEntry {
    uint16_t localPortHostOrder;
    uint8_t  ipFamily;            // 4 or 6
    uint8_t  targetType;          // TargetAddrType
    uint32_t sessionId;
    uint32_t pid;
    uint16_t targetPortHostOrder;
    uint16_t reserved;
    uint8_t  targetAddr[16];      // IPv4 in [0..3], IPv6 in [0..15]
    uint64_t timestampMs;
};

struct SharedState {
    uint32_t magic;
    uint32_t version;
    uint32_t bridgePid;
    uint16_t bridgePortV4;
    uint16_t bridgePortV6;
    uint32_t nextFakeIpOffset;
    uint32_t nextNatSlot;
    SessionEntry sessions[kMaxSessions];
    FakeIpEntry  fakeIps[kMaxFakeIps];
    NatEntry     natTable[kMaxNatSlots];
};
#pragma pack(pop)

static_assert(sizeof(SessionEntry) == 12, "SessionEntry layout mismatch");
static_assert(sizeof(FakeIpEntry) == 264, "FakeIpEntry layout mismatch");
static_assert(sizeof(NatEntry) == 40, "NatEntry layout mismatch");
static_assert(offsetof(SharedState, sessions) == 24, "SharedState header size mismatch");

inline bool IsFakeIpv4HostOrder(uint32_t ipHostOrder) {
    return (ipHostOrder & 0xFFFE0000u) == kFakeIpMaskPrefix;
}

inline bool IsFakeIpv6Bytes(const uint8_t addr16[16], uint32_t* outFakeIpHostOrder = nullptr) {
    // Prefix: fd98:0018:0000:0000:0000:0000:<32-bit fakeIpHostOrder>
    static constexpr uint8_t kPrefix[12] = {
        0xFD, 0x98, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    for (int i = 0; i < 12; ++i) {
        if (addr16[i] != kPrefix[i]) {
            return false;
        }
    }
    uint32_t ipHost = (static_cast<uint32_t>(addr16[12]) << 24) |
                      (static_cast<uint32_t>(addr16[13]) << 16) |
                      (static_cast<uint32_t>(addr16[14]) << 8) |
                      static_cast<uint32_t>(addr16[15]);
    if (!IsFakeIpv4HostOrder(ipHost)) {
        return false;
    }
    if (outFakeIpHostOrder) {
        *outFakeIpHostOrder = ipHost;
    }
    return true;
}

} // namespace AppProxy::IPC

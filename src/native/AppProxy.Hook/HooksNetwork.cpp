#include "HookContext.h"
#include "SharedBridgeClient.h"
#include <MinHook.h>

#include <algorithm>
#include <cstring>
#include <mutex>
#include <unordered_map>

namespace AppProxy::Hook {

namespace {

struct RedirectedSocketInfo {
    sockaddr_storage origAddr{};
    int origLen = 0;
    sockaddr_storage bridgeAddr{};
    int bridgeLen = 0;
};

std::mutex g_sockMapMutex;
std::unordered_map<SOCKET, RedirectedSocketInfo> g_redirectedSockets;

using FnConnect = int(WSAAPI*)(SOCKET, const struct sockaddr*, int);
using FnWSAConnect = int(WSAAPI*)(SOCKET, const struct sockaddr*, int, LPWSABUF, LPWSABUF, LPQOS, LPQOS);
using FnWSAConnectByNameW = BOOL(WSAAPI*)(SOCKET, LPWSTR, LPWSTR, LPDWORD, LPSOCKADDR, LPDWORD, LPSOCKADDR, const struct timeval*, LPWSAOVERLAPPED);
using FnWSAConnectByNameA = BOOL(WSAAPI*)(SOCKET, LPCSTR, LPCSTR, LPDWORD, LPSOCKADDR, LPDWORD, LPSOCKADDR, const struct timeval*, LPWSAOVERLAPPED);
using FnWSAIoctl = int(WSAAPI*)(SOCKET, DWORD, LPVOID, DWORD, LPVOID, DWORD, LPDWORD, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);
using FnGetPeerName = int(WSAAPI*)(SOCKET, struct sockaddr*, int*);
using FnCloseSocket = int(WSAAPI*)(SOCKET);
using FnSendTo = int(WSAAPI*)(SOCKET, const char*, int, int, const struct sockaddr*, int);
using FnWSASendTo = int(WSAAPI*)(SOCKET, LPWSABUF, DWORD, LPDWORD, DWORD, const struct sockaddr*, int, LPWSAOVERLAPPED, LPWSAOVERLAPPED_COMPLETION_ROUTINE);

FnConnect g_TrueConnect = nullptr;
FnWSAConnect g_TrueWSAConnect = nullptr;
FnWSAConnectByNameW g_TrueWSAConnectByNameW = nullptr;
FnWSAConnectByNameA g_TrueWSAConnectByNameA = nullptr;
FnWSAIoctl g_TrueWSAIoctl = nullptr;
FnGetPeerName g_TrueGetPeerName = nullptr;
FnCloseSocket g_TrueCloseSocket = nullptr;
FnSendTo g_TrueSendTo = nullptr;
FnWSASendTo g_TrueWSASendTo = nullptr;
std::atomic<LPFN_CONNECTEX> g_TrueConnectEx{nullptr};

bool IsLoopbackOrZeroV4(uint32_t ipHostOrder) {
    if (ipHostOrder == 0) return true; // 0.0.0.0
    if ((ipHostOrder & 0xFF000000u) == 0x7F000000u) return true; // 127.0.0.0/8
    return false;
}

bool IsPrivateOrSpecialV4(uint32_t ipHostOrder) {
    if (IPC::IsFakeIpv4HostOrder(ipHostOrder)) return false; // Never bypass Fake-IP
    if (IsLoopbackOrZeroV4(ipHostOrder)) return true;
    if ((ipHostOrder & 0xFF000000u) == 0x0A000000u) return true; // 10.0.0.0/8
    if ((ipHostOrder & 0xFFF00000u) == 0xAC100000u) return true; // 172.16.0.0/12
    if ((ipHostOrder & 0xFFFF0000u) == 0xC0A80000u) return true; // 192.168.0.0/16
    if ((ipHostOrder & 0xFFFF0000u) == 0xA9FE0000u) return true; // 169.254.0.0/16
    if ((ipHostOrder & 0xFFC00000u) == 0x64400000u) return true; // 100.64.0.0/10
    if ((ipHostOrder & 0xF0000000u) == 0xE0000000u) return true; // 224.0.0.0/4 multicast/broadcast
    return false;
}

bool IsLoopbackOrZeroV6(const in6_addr& addr) {
    if (IN6_IS_ADDR_LOOPBACK(&addr) || IN6_IS_ADDR_UNSPECIFIED(&addr)) return true;
    return false;
}

bool IsPrivateOrSpecialV6(const in6_addr& addr) {
    if (IPC::IsFakeIpv6Bytes(addr.s6_addr)) return false;
    if (IsLoopbackOrZeroV6(addr)) return true;
    if (IN6_IS_ADDR_LINKLOCAL(&addr) || IN6_IS_ADDR_MULTICAST(&addr)) return true;
    // fc00::/7 Unique Local Address
    if ((addr.s6_addr[0] & 0xFE) == 0xFC) return true;
    return false;
}

bool IsFakeIpTarget(const sockaddr* name, int namelen) {
    if (!name) return false;
    if (name->sa_family == AF_INET && namelen >= static_cast<int>(sizeof(sockaddr_in))) {
        const auto* sa4 = reinterpret_cast<const sockaddr_in*>(name);
        return IPC::IsFakeIpv4HostOrder(ntohl(sa4->sin_addr.s_addr));
    }
    if (name->sa_family == AF_INET6 && namelen >= static_cast<int>(sizeof(sockaddr_in6))) {
        const auto* sa6 = reinterpret_cast<const sockaddr_in6*>(name);
        if (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
            const uint8_t* b = sa6->sin6_addr.s6_addr + 12;
            uint32_t ipHost = (static_cast<uint32_t>(b[0]) << 24) |
                              (static_cast<uint32_t>(b[1]) << 16) |
                              (static_cast<uint32_t>(b[2]) << 8) |
                              static_cast<uint32_t>(b[3]);
            return IPC::IsFakeIpv4HostOrder(ipHost);
        }
        return IPC::IsFakeIpv6Bytes(sa6->sin6_addr.s6_addr);
    }
    return false;
}

bool ShouldBlockUdpTarget(const sockaddr* name, int namelen) {
    if (!name) return false;
    if (IsFakeIpTarget(name, namelen)) return true;

    uint32_t flags = SharedBridgeClient::GetEffectiveFlags();
    if ((flags & IPC::FLAG_DIRECT_MODE) == 0 && (flags & IPC::FLAG_REMOTE_DNS) != 0) {
        if (name->sa_family == AF_INET && namelen >= static_cast<int>(sizeof(sockaddr_in))) {
            const auto* sa4 = reinterpret_cast<const sockaddr_in*>(name);
            if (ntohs(sa4->sin_port) == 53) return true;
        } else if (name->sa_family == AF_INET6 && namelen >= static_cast<int>(sizeof(sockaddr_in6))) {
            const auto* sa6 = reinterpret_cast<const sockaddr_in6*>(name);
            if (ntohs(sa6->sin6_port) == 53) return true;
        }
    }
    return false;
}

bool IsUdpSocket(SOCKET s) {
    int sockType = 0;
    int optLen = sizeof(sockType);
    return getsockopt(s, SOL_SOCKET, SO_TYPE, reinterpret_cast<char*>(&sockType), &optLen) == 0 &&
           sockType == SOCK_DGRAM;
}

bool ShouldBypassTarget(const sockaddr* name, int namelen, uint32_t flags) {
    if (!name) return true;
    if (flags & IPC::FLAG_DIRECT_MODE) return true;

    bool bypassLan = (flags & IPC::FLAG_BYPASS_LAN) != 0;

    if (name->sa_family == AF_INET && namelen >= static_cast<int>(sizeof(sockaddr_in))) {
        const auto* sa4 = reinterpret_cast<const sockaddr_in*>(name);
        if (ntohs(sa4->sin_port) == 0) return true;
        uint32_t ipHost = ntohl(sa4->sin_addr.s_addr);
        if (IPC::IsFakeIpv4HostOrder(ipHost)) return false;
        if (IsLoopbackOrZeroV4(ipHost)) return true;
        return bypassLan && IsPrivateOrSpecialV4(ipHost);
    }

    if (name->sa_family == AF_INET6 && namelen >= static_cast<int>(sizeof(sockaddr_in6))) {
        const auto* sa6 = reinterpret_cast<const sockaddr_in6*>(name);
        if (ntohs(sa6->sin6_port) == 0) return true;
        if (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
            const uint8_t* b = sa6->sin6_addr.s6_addr + 12;
            uint32_t ipHost = (static_cast<uint32_t>(b[0]) << 24) |
                              (static_cast<uint32_t>(b[1]) << 16) |
                              (static_cast<uint32_t>(b[2]) << 8) |
                              static_cast<uint32_t>(b[3]);
            if (IPC::IsFakeIpv4HostOrder(ipHost)) return false;
            if (IsLoopbackOrZeroV4(ipHost)) return true;
            return bypassLan && IsPrivateOrSpecialV4(ipHost);
        }
        if (IPC::IsFakeIpv6Bytes(sa6->sin6_addr.s6_addr)) return false;
        if (IsLoopbackOrZeroV6(sa6->sin6_addr)) return true;
        return bypassLan && IsPrivateOrSpecialV6(sa6->sin6_addr);
    }

    return true;
}

bool EnsureSocketBoundAndGetLocalPort(SOCKET s, int bindFamily, bool bindAnyV6, uint16_t& outPortHostOrder) {
    sockaddr_storage localAddr{};
    int localLen = sizeof(localAddr);
    if (getsockname(s, reinterpret_cast<sockaddr*>(&localAddr), &localLen) == SOCKET_ERROR) {
        if (WSAGetLastError() != WSAEINVAL) {
            return false;
        }
        if (bindFamily == AF_INET) {
            sockaddr_in sa4{};
            sa4.sin_family = AF_INET;
            sa4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            sa4.sin_port = 0;
            if (bind(s, reinterpret_cast<const sockaddr*>(&sa4), sizeof(sa4)) == SOCKET_ERROR) {
                return false;
            }
        } else if (bindFamily == AF_INET6) {
            sockaddr_in6 sa6{};
            sa6.sin6_family = AF_INET6;
            sa6.sin6_addr = bindAnyV6 ? in6addr_any : in6addr_loopback;
            sa6.sin6_port = 0;
            if (bind(s, reinterpret_cast<const sockaddr*>(&sa6), sizeof(sa6)) == SOCKET_ERROR) {
                return false;
            }
        } else {
            return false;
        }

        localLen = sizeof(localAddr);
        if (getsockname(s, reinterpret_cast<sockaddr*>(&localAddr), &localLen) == SOCKET_ERROR) {
            return false;
        }
    }

    if (localAddr.ss_family == AF_INET) {
        outPortHostOrder = ntohs(reinterpret_cast<const sockaddr_in*>(&localAddr)->sin_port);
    } else if (localAddr.ss_family == AF_INET6) {
        outPortHostOrder = ntohs(reinterpret_cast<const sockaddr_in6*>(&localAddr)->sin6_port);
    } else {
        return false;
    }

    return outPortHostOrder != 0;
}

bool TryPrepareRedirect(
    SOCKET s,
    const sockaddr* name,
    int namelen,
    sockaddr_storage& outBridgeAddr,
    int& outBridgeLen) {
    if (!name || namelen <= 0) return false;

    // Handle repeated non-blocking connect() polling calls cleanly
    {
        std::lock_guard<std::mutex> lock(g_sockMapMutex);
        auto it = g_redirectedSockets.find(s);
        if (it != g_redirectedSockets.end()) {
            outBridgeAddr = it->second.bridgeAddr;
            outBridgeLen = it->second.bridgeLen;
            return true;
        }
    }

    // Only redirect TCP (SOCK_STREAM) sockets
    int sockType = 0;
    int optLen = sizeof(sockType);
    if (getsockopt(s, SOL_SOCKET, SO_TYPE, reinterpret_cast<char*>(&sockType), &optLen) == SOCKET_ERROR ||
        sockType != SOCK_STREAM) {
        return false;
    }

    uint32_t flags = SharedBridgeClient::GetEffectiveFlags();
    if (ShouldBypassTarget(name, namelen, flags)) {
        return false;
    }

    uint16_t portV4 = 0;
    uint16_t portV6 = 0;
    if (!SharedBridgeClient::GetBridgePorts(portV4, portV6)) {
        return false;
    }

    std::memset(&outBridgeAddr, 0, sizeof(outBridgeAddr));
    uint8_t natFamily = 4;
    bool bindAnyV6 = false;

    if (name->sa_family == AF_INET && namelen >= static_cast<int>(sizeof(sockaddr_in))) {
        if (portV4 == 0) return false;
        natFamily = 4;
        auto* b4 = reinterpret_cast<sockaddr_in*>(&outBridgeAddr);
        b4->sin_family = AF_INET;
        b4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        b4->sin_port = htons(portV4);
        outBridgeLen = sizeof(sockaddr_in);
    } else if (name->sa_family == AF_INET6 && namelen >= static_cast<int>(sizeof(sockaddr_in6))) {
        const auto* target6 = reinterpret_cast<const sockaddr_in6*>(name);
        if (IN6_IS_ADDR_V4MAPPED(&target6->sin6_addr)) {
            if (portV4 == 0) return false;
            natFamily = 4;
            bindAnyV6 = true;
            auto* b6 = reinterpret_cast<sockaddr_in6*>(&outBridgeAddr);
            b6->sin6_family = AF_INET6;
            b6->sin6_port = htons(portV4);
            // ::ffff:127.0.0.1
            static constexpr uint8_t kV4MappedLoopback[16] = {
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 127, 0, 0, 1
            };
            std::memcpy(b6->sin6_addr.s6_addr, kV4MappedLoopback, 16);
            outBridgeLen = sizeof(sockaddr_in6);
        } else {
            if (portV6 == 0) return false;
            natFamily = 6;
            auto* b6 = reinterpret_cast<sockaddr_in6*>(&outBridgeAddr);
            b6->sin6_family = AF_INET6;
            b6->sin6_port = htons(portV6);
            b6->sin6_addr = in6addr_loopback;
            outBridgeLen = sizeof(sockaddr_in6);
        }
    } else {
        return false;
    }

    uint16_t localPort = 0;
    if (!EnsureSocketBoundAndGetLocalPort(s, name->sa_family, bindAnyV6, localPort)) {
        return false;
    }

    if (!SharedBridgeClient::RegisterNatMapping(localPort, natFamily, name)) {
        return false;
    }

    RedirectedSocketInfo info{};
    int copyLen = (std::min)(namelen, static_cast<int>(sizeof(sockaddr_storage)));
    std::memcpy(&info.origAddr, name, static_cast<size_t>(copyLen));
    info.origLen = copyLen;
    info.bridgeAddr = outBridgeAddr;
    info.bridgeLen = outBridgeLen;

    {
        std::lock_guard<std::mutex> lock(g_sockMapMutex);
        g_redirectedSockets[s] = info;
    }
    return true;
}

int WSAAPI HookedConnect(SOCKET s, const struct sockaddr* name, int namelen) {
    if (IsUdpSocket(s) && ShouldBlockUdpTarget(name, namelen)) {
        WSASetLastError(WSAECONNREFUSED);
        return SOCKET_ERROR;
    }
    sockaddr_storage bridgeAddr{};
    int bridgeLen = 0;
    if (TryPrepareRedirect(s, name, namelen, bridgeAddr, bridgeLen)) {
        return g_TrueConnect(s, reinterpret_cast<const sockaddr*>(&bridgeAddr), bridgeLen);
    }
    return g_TrueConnect(s, name, namelen);
}

int WSAAPI HookedWSAConnect(
    SOCKET s,
    const struct sockaddr* name,
    int namelen,
    LPWSABUF lpCallerData,
    LPWSABUF lpCalleeData,
    LPQOS lpSQOS,
    LPQOS lpGQOS) {
    if (IsUdpSocket(s) && ShouldBlockUdpTarget(name, namelen)) {
        WSASetLastError(WSAECONNREFUSED);
        return SOCKET_ERROR;
    }
    sockaddr_storage bridgeAddr{};
    int bridgeLen = 0;
    if (TryPrepareRedirect(s, name, namelen, bridgeAddr, bridgeLen)) {
        return g_TrueWSAConnect(
            s,
            reinterpret_cast<const sockaddr*>(&bridgeAddr),
            bridgeLen,
            lpCallerData,
            lpCalleeData,
            lpSQOS,
            lpGQOS);
    }
    return g_TrueWSAConnect(s, name, namelen, lpCallerData, lpCalleeData, lpSQOS, lpGQOS);
}

BOOL PASCAL HookedConnectEx(
    SOCKET s,
    const struct sockaddr* name,
    int namelen,
    PVOID lpSendBuffer,
    DWORD dwSendDataLength,
    LPDWORD lpdwBytesSent,
    LPOVERLAPPED lpOverlapped) {
    LPFN_CONNECTEX realFn = g_TrueConnectEx.load(std::memory_order_acquire);
    if (!realFn) {
        WSASetLastError(WSAEFAULT);
        return FALSE;
    }

    sockaddr_storage bridgeAddr{};
    int bridgeLen = 0;
    if (TryPrepareRedirect(s, name, namelen, bridgeAddr, bridgeLen)) {
        return realFn(
            s,
            reinterpret_cast<const sockaddr*>(&bridgeAddr),
            bridgeLen,
            lpSendBuffer,
            dwSendDataLength,
            lpdwBytesSent,
            lpOverlapped);
    }
    return realFn(s, name, namelen, lpSendBuffer, dwSendDataLength, lpdwBytesSent, lpOverlapped);
}

int WSAAPI HookedWSAIoctl(
    SOCKET s,
    DWORD dwIoControlCode,
    LPVOID lpvInBuffer,
    DWORD cbInBuffer,
    LPVOID lpvOutBuffer,
    DWORD cbOutBuffer,
    LPDWORD lpcbBytesReturned,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    int ret = g_TrueWSAIoctl(
        s,
        dwIoControlCode,
        lpvInBuffer,
        cbInBuffer,
        lpvOutBuffer,
        cbOutBuffer,
        lpcbBytesReturned,
        lpOverlapped,
        lpCompletionRoutine);

    if (ret == 0 &&
        dwIoControlCode == SIO_GET_EXTENSION_FUNCTION_POINTER &&
        lpvInBuffer && cbInBuffer >= sizeof(GUID) &&
        lpvOutBuffer && cbOutBuffer >= sizeof(LPFN_CONNECTEX)) {
        static const GUID kConnectExGuid = WSAID_CONNECTEX;
        if (std::memcmp(lpvInBuffer, &kConnectExGuid, sizeof(GUID)) == 0) {
            auto* outFn = reinterpret_cast<LPFN_CONNECTEX*>(lpvOutBuffer);
            if (*outFn && *outFn != HookedConnectEx) {
                g_TrueConnectEx.store(*outFn, std::memory_order_release);
                *outFn = HookedConnectEx;
            }
        }
    }
    return ret;
}

BOOL WSAAPI HookedWSAConnectByNameW(
    SOCKET s,
    LPWSTR nodename,
    LPWSTR servicename,
    LPDWORD LocalAddressLength,
    LPSOCKADDR LocalAddress,
    LPDWORD RemoteAddressLength,
    LPSOCKADDR RemoteAddress,
    const struct timeval* timeout,
    LPWSAOVERLAPPED Reserved) {
    BOOL ok = g_TrueWSAConnectByNameW(
        s,
        nodename,
        servicename,
        LocalAddressLength,
        LocalAddress,
        RemoteAddressLength,
        RemoteAddress,
        timeout,
        Reserved);
    if (ok && RemoteAddress && RemoteAddressLength) {
        std::lock_guard<std::mutex> lock(g_sockMapMutex);
        auto it = g_redirectedSockets.find(s);
        if (it != g_redirectedSockets.end()) {
            DWORD copyLen = (std::min)(*RemoteAddressLength, static_cast<DWORD>(it->second.origLen));
            std::memcpy(RemoteAddress, &it->second.origAddr, copyLen);
            *RemoteAddressLength = static_cast<DWORD>(it->second.origLen);
        }
    }
    return ok;
}

BOOL WSAAPI HookedWSAConnectByNameA(
    SOCKET s,
    LPCSTR nodename,
    LPCSTR servicename,
    LPDWORD LocalAddressLength,
    LPSOCKADDR LocalAddress,
    LPDWORD RemoteAddressLength,
    LPSOCKADDR RemoteAddress,
    const struct timeval* timeout,
    LPWSAOVERLAPPED Reserved) {
    BOOL ok = g_TrueWSAConnectByNameA(
        s,
        nodename,
        servicename,
        LocalAddressLength,
        LocalAddress,
        RemoteAddressLength,
        RemoteAddress,
        timeout,
        Reserved);
    if (ok && RemoteAddress && RemoteAddressLength) {
        std::lock_guard<std::mutex> lock(g_sockMapMutex);
        auto it = g_redirectedSockets.find(s);
        if (it != g_redirectedSockets.end()) {
            DWORD copyLen = (std::min)(*RemoteAddressLength, static_cast<DWORD>(it->second.origLen));
            std::memcpy(RemoteAddress, &it->second.origAddr, copyLen);
            *RemoteAddressLength = static_cast<DWORD>(it->second.origLen);
        }
    }
    return ok;
}

int WSAAPI HookedGetPeerName(SOCKET s, struct sockaddr* name, int* namelen) {
    int ret = g_TrueGetPeerName(s, name, namelen);
    if (ret == 0 && name && namelen) {
        std::lock_guard<std::mutex> lock(g_sockMapMutex);
        auto it = g_redirectedSockets.find(s);
        if (it != g_redirectedSockets.end()) {
            if (*namelen < it->second.origLen) {
                *namelen = it->second.origLen;
                WSASetLastError(WSAEFAULT);
                return SOCKET_ERROR;
            }
            std::memcpy(name, &it->second.origAddr, static_cast<size_t>(it->second.origLen));
            *namelen = it->second.origLen;
        }
    }
    return ret;
}

int WSAAPI HookedCloseSocket(SOCKET s) {
    {
        std::lock_guard<std::mutex> lock(g_sockMapMutex);
        g_redirectedSockets.erase(s);
    }
    return g_TrueCloseSocket(s);
}

int WSAAPI HookedSendTo(
    SOCKET s,
    const char* buf,
    int len,
    int flags,
    const struct sockaddr* to,
    int tolen) {
    if (ShouldBlockUdpTarget(to, tolen)) {
        // Fast-fail QUIC/UDP packets to Fake-IPs and UDP port 53 when RemoteDns is enabled
        WSASetLastError(WSAECONNREFUSED);
        return SOCKET_ERROR;
    }
    return g_TrueSendTo(s, buf, len, flags, to, tolen);
}

int WSAAPI HookedWSASendTo(
    SOCKET s,
    LPWSABUF lpBuffers,
    DWORD dwBufferCount,
    LPDWORD lpNumberOfBytesSent,
    DWORD dwFlags,
    const struct sockaddr* lpTo,
    int iTolen,
    LPWSAOVERLAPPED lpOverlapped,
    LPWSAOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine) {
    if (ShouldBlockUdpTarget(lpTo, iTolen)) {
        WSASetLastError(WSAECONNREFUSED);
        return SOCKET_ERROR;
    }
    return g_TrueWSASendTo(
        s,
        lpBuffers,
        dwBufferCount,
        lpNumberOfBytesSent,
        dwFlags,
        lpTo,
        iTolen,
        lpOverlapped,
        lpCompletionRoutine);
}

} // namespace

bool InstallNetworkHooks() {
    static bool s_installed = false;
    if (s_installed) return true;
    if (!GetModuleHandleW(L"ws2_32.dll")) return false;

    MH_CreateHookApi(L"ws2_32", "connect", &HookedConnect, reinterpret_cast<LPVOID*>(&g_TrueConnect));
    MH_CreateHookApi(L"ws2_32", "WSAConnect", &HookedWSAConnect, reinterpret_cast<LPVOID*>(&g_TrueWSAConnect));
    MH_CreateHookApi(L"ws2_32", "WSAConnectByNameW", &HookedWSAConnectByNameW, reinterpret_cast<LPVOID*>(&g_TrueWSAConnectByNameW));
    MH_CreateHookApi(L"ws2_32", "WSAConnectByNameA", &HookedWSAConnectByNameA, reinterpret_cast<LPVOID*>(&g_TrueWSAConnectByNameA));
    MH_CreateHookApi(L"ws2_32", "WSAIoctl", &HookedWSAIoctl, reinterpret_cast<LPVOID*>(&g_TrueWSAIoctl));
    MH_CreateHookApi(L"ws2_32", "getpeername", &HookedGetPeerName, reinterpret_cast<LPVOID*>(&g_TrueGetPeerName));
    MH_CreateHookApi(L"ws2_32", "closesocket", &HookedCloseSocket, reinterpret_cast<LPVOID*>(&g_TrueCloseSocket));
    MH_CreateHookApi(L"ws2_32", "sendto", &HookedSendTo, reinterpret_cast<LPVOID*>(&g_TrueSendTo));
    MH_CreateHookApi(L"ws2_32", "WSASendTo", &HookedWSASendTo, reinterpret_cast<LPVOID*>(&g_TrueWSASendTo));
    s_installed = true;
    return true;
}

} // namespace AppProxy::Hook

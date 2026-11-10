#include "HookContext.h"
#include "SharedBridgeClient.h"
#include <MinHook.h>

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <mutex>
#include <string>
#include <unordered_set>

namespace AppProxy::Hook {

namespace {

using FnGetAddrInfo = int(WSAAPI*)(PCSTR, PCSTR, const ADDRINFOA*, PADDRINFOA*);
using FnGetAddrInfoW = int(WSAAPI*)(PCWSTR, PCWSTR, const ADDRINFOW*, PADDRINFOW*);
using FnGetAddrInfoExW = int(WSAAPI*)(PCWSTR, PCWSTR, DWORD, LPGUID, const ADDRINFOEXW*, PADDRINFOEXW*, struct timeval*, LPOVERLAPPED, LPLOOKUPSERVICE_COMPLETION_ROUTINE, LPHANDLE);
using FnFreeAddrInfo = void(WSAAPI*)(PADDRINFOA);
using FnFreeAddrInfoW = void(WSAAPI*)(PADDRINFOW);
using FnFreeAddrInfoExW = void(WSAAPI*)(PADDRINFOEXW);
using FnGetHostByName = struct hostent*(WSAAPI*)(const char*);

FnGetAddrInfo g_TrueGetAddrInfo = nullptr;
FnGetAddrInfoW g_TrueGetAddrInfoW = nullptr;
FnGetAddrInfoExW g_TrueGetAddrInfoExW = nullptr;
FnFreeAddrInfo g_TrueFreeAddrInfo = nullptr;
FnFreeAddrInfoW g_TrueFreeAddrInfoW = nullptr;
FnFreeAddrInfoExW g_TrueFreeAddrInfoExW = nullptr;
FnGetHostByName g_TrueGetHostByName = nullptr;

std::mutex g_fakeDnsAllocMutex;
std::unordered_set<void*> g_fakeAddrInfoA;
std::unordered_set<void*> g_fakeAddrInfoW;
std::unordered_set<void*> g_fakeAddrInfoExW;

bool EndsWithNoCase(const std::string& s, const char* suffix) {
    size_t slen = std::strlen(suffix);
    if (s.size() < slen) return false;
    return _stricmp(s.c_str() + (s.size() - slen), suffix) == 0;
}

bool ShouldUseFakeDns(const char* nodeName, int aiFlags) {
    if (!nodeName || nodeName[0] == '\0') return false;
    uint32_t flags = SharedBridgeClient::GetEffectiveFlags();
    if (flags & IPC::FLAG_DIRECT_MODE) return false;
    if ((flags & IPC::FLAG_REMOTE_DNS) == 0) return false;
    if (aiFlags & AI_NUMERICHOST) return false;

    in_addr v4{};
    in6_addr v6{};
    if (inet_pton(AF_INET, nodeName, &v4) == 1) return false;
    if (inet_pton(AF_INET6, nodeName, &v6) == 1) return false;

    std::string host(nodeName);
    if (_stricmp(host.c_str(), "localhost") == 0 ||
        _stricmp(host.c_str(), "localhost.localdomain") == 0 ||
        EndsWithNoCase(host, ".local") ||
        EndsWithNoCase(host, ".localhost")) {
        return false;
    }

    // Single-label NetBIOS/local hostnames without dots can bypass if local
    if (host.find('.') == std::string::npos) {
        return false;
    }

    return true;
}

uint16_t ResolveServicePortNetworkOrder(const char* serviceName) {
    if (!serviceName || serviceName[0] == '\0') return 0;
    char* endPtr = nullptr;
    unsigned long portNum = std::strtoul(serviceName, &endPtr, 10);
    if (endPtr != serviceName && *endPtr == '\0' && portNum <= 65535) {
        return htons(static_cast<uint16_t>(portNum));
    }
    if (_stricmp(serviceName, "http") == 0 || _stricmp(serviceName, "ws") == 0) return htons(80);
    if (_stricmp(serviceName, "https") == 0 || _stricmp(serviceName, "wss") == 0) return htons(443);
    if (_stricmp(serviceName, "ftp") == 0) return htons(21);
    if (_stricmp(serviceName, "ssh") == 0) return htons(22);

    servent* sv = getservbyname(serviceName, "tcp");
    if (sv) return static_cast<uint16_t>(sv->s_port);
    return 0;
}

void BuildFakeSockaddr(
    uint32_t fakeIpHostOrder,
    uint16_t portNetOrder,
    int requestedFamily,
    int requestedFlags,
    sockaddr_storage& outAddr,
    size_t& outAddrLen,
    int& outFamily) {
    std::memset(&outAddr, 0, sizeof(outAddr));
    if (requestedFamily == AF_INET6) {
        outFamily = AF_INET6;
        outAddrLen = sizeof(sockaddr_in6);
        auto* sa6 = reinterpret_cast<sockaddr_in6*>(&outAddr);
        sa6->sin6_family = AF_INET6;
        sa6->sin6_port = portNetOrder;
        if (requestedFlags & AI_V4MAPPED) {
            // ::ffff:<FakeIPv4>
            sa6->sin6_addr.s6_addr[10] = 0xFF;
            sa6->sin6_addr.s6_addr[11] = 0xFF;
            sa6->sin6_addr.s6_addr[12] = static_cast<uint8_t>((fakeIpHostOrder >> 24) & 0xFF);
            sa6->sin6_addr.s6_addr[13] = static_cast<uint8_t>((fakeIpHostOrder >> 16) & 0xFF);
            sa6->sin6_addr.s6_addr[14] = static_cast<uint8_t>((fakeIpHostOrder >> 8) & 0xFF);
            sa6->sin6_addr.s6_addr[15] = static_cast<uint8_t>(fakeIpHostOrder & 0xFF);
        } else {
            // fd98:0018::0000:<FakeIPv4>
            sa6->sin6_addr.s6_addr[0] = 0xFD;
            sa6->sin6_addr.s6_addr[1] = 0x98;
            sa6->sin6_addr.s6_addr[2] = 0x00;
            sa6->sin6_addr.s6_addr[3] = 0x18;
            sa6->sin6_addr.s6_addr[12] = static_cast<uint8_t>((fakeIpHostOrder >> 24) & 0xFF);
            sa6->sin6_addr.s6_addr[13] = static_cast<uint8_t>((fakeIpHostOrder >> 16) & 0xFF);
            sa6->sin6_addr.s6_addr[14] = static_cast<uint8_t>((fakeIpHostOrder >> 8) & 0xFF);
            sa6->sin6_addr.s6_addr[15] = static_cast<uint8_t>(fakeIpHostOrder & 0xFF);
        }
    } else {
        outFamily = AF_INET;
        outAddrLen = sizeof(sockaddr_in);
        auto* sa4 = reinterpret_cast<sockaddr_in*>(&outAddr);
        sa4->sin_family = AF_INET;
        sa4->sin_port = portNetOrder;
        sa4->sin_addr.s_addr = htonl(fakeIpHostOrder);
    }
}

int WSAAPI HookedGetAddrInfo(
    PCSTR pNodeName,
    PCSTR pServiceName,
    const ADDRINFOA* pHints,
    PADDRINFOA* ppResult) {
    if (!ppResult) return WSAEINVAL;

    int hintFlags = pHints ? pHints->ai_flags : 0;
    int hintFamily = pHints ? pHints->ai_family : AF_UNSPEC;
    if ((hintFamily == AF_UNSPEC || hintFamily == AF_INET || hintFamily == AF_INET6) &&
        ShouldUseFakeDns(pNodeName, hintFlags)) {
        uint32_t fakeIp = SharedBridgeClient::AllocateOrGetFakeIp(pNodeName);
        if (fakeIp != 0) {
            auto* node = new ADDRINFOA{};
            sockaddr_storage sa{};
            size_t saLen = 0;
            int outFamily = AF_INET;
            uint16_t portNet = ResolveServicePortNetworkOrder(pServiceName);
            BuildFakeSockaddr(fakeIp, portNet, hintFamily, hintFlags, sa, saLen, outFamily);

            auto* addrMem = reinterpret_cast<sockaddr*>(new uint8_t[saLen]);
            std::memcpy(addrMem, &sa, saLen);

            node->ai_flags = 0;
            node->ai_family = outFamily;
            node->ai_socktype = pHints ? pHints->ai_socktype : SOCK_STREAM;
            node->ai_protocol = pHints ? pHints->ai_protocol : IPPROTO_TCP;
            node->ai_addrlen = saLen;
            node->ai_addr = addrMem;
            if (hintFlags & AI_CANONNAME) {
                size_t len = std::strlen(pNodeName) + 1;
                node->ai_canonname = new char[len];
                std::memcpy(node->ai_canonname, pNodeName, len);
            }
            node->ai_next = nullptr;

            {
                std::lock_guard<std::mutex> lock(g_fakeDnsAllocMutex);
                g_fakeAddrInfoA.insert(node);
            }
            *ppResult = node;
            return 0;
        }
    }

    return g_TrueGetAddrInfo(pNodeName, pServiceName, pHints, ppResult);
}

void WSAAPI HookedFreeAddrInfo(PADDRINFOA pAddrInfo) {
    if (!pAddrInfo) return;
    bool isFake = false;
    {
        std::lock_guard<std::mutex> lock(g_fakeDnsAllocMutex);
        isFake = g_fakeAddrInfoA.erase(pAddrInfo) > 0;
    }
    if (isFake) {
        PADDRINFOA cur = pAddrInfo;
        while (cur) {
            PADDRINFOA next = cur->ai_next;
            delete[] reinterpret_cast<uint8_t*>(cur->ai_addr);
            delete[] cur->ai_canonname;
            delete cur;
            cur = next;
        }
        return;
    }
    g_TrueFreeAddrInfo(pAddrInfo);
}

int WSAAPI HookedGetAddrInfoW(
    PCWSTR pNodeName,
    PCWSTR pServiceName,
    const ADDRINFOW* pHints,
    PADDRINFOW* ppResult) {
    if (!ppResult) return WSAEINVAL;

    std::string nodeUtf8 = WideToUtf8(pNodeName);
    int hintFlags = pHints ? pHints->ai_flags : 0;
    int hintFamily = pHints ? pHints->ai_family : AF_UNSPEC;

    if ((hintFamily == AF_UNSPEC || hintFamily == AF_INET || hintFamily == AF_INET6) &&
        ShouldUseFakeDns(nodeUtf8.c_str(), hintFlags)) {
        uint32_t fakeIp = SharedBridgeClient::AllocateOrGetFakeIp(nodeUtf8.c_str());
        if (fakeIp != 0) {
            std::string svcUtf8 = WideToUtf8(pServiceName);
            auto* node = new ADDRINFOW{};
            sockaddr_storage sa{};
            size_t saLen = 0;
            int outFamily = AF_INET;
            uint16_t portNet = ResolveServicePortNetworkOrder(svcUtf8.empty() ? nullptr : svcUtf8.c_str());
            BuildFakeSockaddr(fakeIp, portNet, hintFamily, hintFlags, sa, saLen, outFamily);

            auto* addrMem = reinterpret_cast<sockaddr*>(new uint8_t[saLen]);
            std::memcpy(addrMem, &sa, saLen);

            node->ai_flags = 0;
            node->ai_family = outFamily;
            node->ai_socktype = pHints ? pHints->ai_socktype : SOCK_STREAM;
            node->ai_protocol = pHints ? pHints->ai_protocol : IPPROTO_TCP;
            node->ai_addrlen = saLen;
            node->ai_addr = addrMem;
            if (hintFlags & AI_CANONNAME) {
                size_t len = std::wcslen(pNodeName) + 1;
                node->ai_canonname = new wchar_t[len];
                std::memcpy(node->ai_canonname, pNodeName, len * sizeof(wchar_t));
            }
            node->ai_next = nullptr;

            {
                std::lock_guard<std::mutex> lock(g_fakeDnsAllocMutex);
                g_fakeAddrInfoW.insert(node);
            }
            *ppResult = node;
            return 0;
        }
    }

    return g_TrueGetAddrInfoW(pNodeName, pServiceName, pHints, ppResult);
}

void WSAAPI HookedFreeAddrInfoW(PADDRINFOW pAddrInfo) {
    if (!pAddrInfo) return;
    bool isFake = false;
    {
        std::lock_guard<std::mutex> lock(g_fakeDnsAllocMutex);
        isFake = g_fakeAddrInfoW.erase(pAddrInfo) > 0;
    }
    if (isFake) {
        PADDRINFOW cur = pAddrInfo;
        while (cur) {
            PADDRINFOW next = cur->ai_next;
            delete[] reinterpret_cast<uint8_t*>(cur->ai_addr);
            delete[] cur->ai_canonname;
            delete cur;
            cur = next;
        }
        return;
    }
    g_TrueFreeAddrInfoW(pAddrInfo);
}

int WSAAPI HookedGetAddrInfoExW(
    PCWSTR pName,
    PCWSTR pServiceName,
    DWORD dwNameSpace,
    LPGUID lpNspId,
    const ADDRINFOEXW* pHints,
    PADDRINFOEXW* ppResult,
    struct timeval* timeout,
    LPOVERLAPPED lpOverlapped,
    LPLOOKUPSERVICE_COMPLETION_ROUTINE lpCompletionRoutine,
    LPHANDLE lpHandle) {
    if (!ppResult) return WSAEINVAL;

    std::string nodeUtf8 = WideToUtf8(pName);
    int hintFlags = pHints ? pHints->ai_flags : 0;
    int hintFamily = pHints ? pHints->ai_family : AF_UNSPEC;

    if ((dwNameSpace == NS_DNS || dwNameSpace == NS_ALL) &&
        (hintFamily == AF_UNSPEC || hintFamily == AF_INET || hintFamily == AF_INET6) &&
        ShouldUseFakeDns(nodeUtf8.c_str(), hintFlags)) {
        uint32_t fakeIp = SharedBridgeClient::AllocateOrGetFakeIp(nodeUtf8.c_str());
        if (fakeIp != 0) {
            std::string svcUtf8 = WideToUtf8(pServiceName);
            auto* node = new ADDRINFOEXW{};
            sockaddr_storage sa{};
            size_t saLen = 0;
            int outFamily = AF_INET;
            uint16_t portNet = ResolveServicePortNetworkOrder(svcUtf8.empty() ? nullptr : svcUtf8.c_str());
            BuildFakeSockaddr(fakeIp, portNet, hintFamily, hintFlags, sa, saLen, outFamily);

            auto* addrMem = reinterpret_cast<sockaddr*>(new uint8_t[saLen]);
            std::memcpy(addrMem, &sa, saLen);

            node->ai_flags = 0;
            node->ai_family = outFamily;
            node->ai_socktype = pHints ? pHints->ai_socktype : SOCK_STREAM;
            node->ai_protocol = pHints ? pHints->ai_protocol : IPPROTO_TCP;
            node->ai_addrlen = saLen;
            node->ai_addr = addrMem;
            if (hintFlags & AI_CANONNAME) {
                size_t len = std::wcslen(pName) + 1;
                node->ai_canonname = new wchar_t[len];
                std::memcpy(node->ai_canonname, pName, len * sizeof(wchar_t));
            }
            node->ai_blob = nullptr;
            node->ai_bloblen = 0;
            node->ai_provider = nullptr;
            node->ai_next = nullptr;

            {
                std::lock_guard<std::mutex> lock(g_fakeDnsAllocMutex);
                g_fakeAddrInfoExW.insert(node);
            }
            *ppResult = node;
            if (lpHandle) {
                *lpHandle = nullptr;
            }
            return NO_ERROR;
        }
    }

    return g_TrueGetAddrInfoExW(
        pName,
        pServiceName,
        dwNameSpace,
        lpNspId,
        pHints,
        ppResult,
        timeout,
        lpOverlapped,
        lpCompletionRoutine,
        lpHandle);
}

void WSAAPI HookedFreeAddrInfoExW(PADDRINFOEXW pAddrInfo) {
    if (!pAddrInfo) return;
    bool isFake = false;
    {
        std::lock_guard<std::mutex> lock(g_fakeDnsAllocMutex);
        isFake = g_fakeAddrInfoExW.erase(pAddrInfo) > 0;
    }
    if (isFake) {
        PADDRINFOEXW cur = pAddrInfo;
        while (cur) {
            PADDRINFOEXW next = cur->ai_next;
            delete[] reinterpret_cast<uint8_t*>(cur->ai_addr);
            delete[] cur->ai_canonname;
            delete cur;
            cur = next;
        }
        return;
    }
    g_TrueFreeAddrInfoExW(pAddrInfo);
}

struct hostent* WSAAPI HookedGetHostByName(const char* name) {
    if (ShouldUseFakeDns(name, 0)) {
        uint32_t fakeIp = SharedBridgeClient::AllocateOrGetFakeIp(name);
        if (fakeIp != 0) {
            thread_local hostent tlHost{};
            thread_local char tlName[256]{};
            thread_local in_addr tlAddr{};
            thread_local char* tlAddrList[2]{};
            thread_local char* tlAliases[1]{nullptr};

            size_t copyLen = (std::min)(std::strlen(name), sizeof(tlName) - 1);
            std::memcpy(tlName, name, copyLen);
            tlName[copyLen] = '\0';
            tlAddr.s_addr = htonl(fakeIp);
            tlAddrList[0] = reinterpret_cast<char*>(&tlAddr);
            tlAddrList[1] = nullptr;

            tlHost.h_name = tlName;
            tlHost.h_aliases = tlAliases;
            tlHost.h_addrtype = AF_INET;
            tlHost.h_length = sizeof(in_addr);
            tlHost.h_addr_list = tlAddrList;
            return &tlHost;
        }
    }
    return g_TrueGetHostByName(name);
}

} // namespace

bool InstallDnsHooks() {
    static bool s_installed = false;
    if (s_installed) return true;
    if (!GetModuleHandleW(L"ws2_32.dll")) return false;

    MH_CreateHookApi(L"ws2_32", "getaddrinfo", &HookedGetAddrInfo, reinterpret_cast<LPVOID*>(&g_TrueGetAddrInfo));
    MH_CreateHookApi(L"ws2_32", "freeaddrinfo", &HookedFreeAddrInfo, reinterpret_cast<LPVOID*>(&g_TrueFreeAddrInfo));
    MH_CreateHookApi(L"ws2_32", "GetAddrInfoW", &HookedGetAddrInfoW, reinterpret_cast<LPVOID*>(&g_TrueGetAddrInfoW));
    MH_CreateHookApi(L"ws2_32", "FreeAddrInfoW", &HookedFreeAddrInfoW, reinterpret_cast<LPVOID*>(&g_TrueFreeAddrInfoW));
    MH_CreateHookApi(L"ws2_32", "GetAddrInfoExW", &HookedGetAddrInfoExW, reinterpret_cast<LPVOID*>(&g_TrueGetAddrInfoExW));
    MH_CreateHookApi(L"ws2_32", "FreeAddrInfoExW", &HookedFreeAddrInfoExW, reinterpret_cast<LPVOID*>(&g_TrueFreeAddrInfoExW));
    MH_CreateHookApi(L"ws2_32", "gethostbyname", &HookedGetHostByName, reinterpret_cast<LPVOID*>(&g_TrueGetHostByName));
    s_installed = true;
    return true;
}

} // namespace AppProxy::Hook

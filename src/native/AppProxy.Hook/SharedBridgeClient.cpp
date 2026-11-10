#include "SharedBridgeClient.h"
#include "LogProtocol.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <deque>
#include <mutex>
#include <unordered_map>

namespace AppProxy::Hook {

namespace {

std::mutex g_shmMutex;
HANDLE g_hMapFile = nullptr;
HANDLE g_hNamedMutex = nullptr;
IPC::SharedState* g_shared = nullptr;

std::mutex g_fakeCacheMutex;
std::unordered_map<std::string, uint32_t> g_fakeIpCache;

std::mutex g_logQueueMutex;
std::deque<std::string> g_logQueue;
HANDLE g_logEvent = nullptr;
HANDLE g_logThread = nullptr;
std::once_flag g_logWorkerOnce;

std::string NormalizeDomain(const char* domain) {
    if (!domain) return {};
    std::string out(domain);
    while (!out.empty() && out.back() == '.') {
        out.pop_back();
    }
    for (char& c : out) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return out;
}

DWORD WINAPI LogWorkerProc(LPVOID) {
    wchar_t pipeName[128]{};
    swprintf_s(pipeName, L"\\\\.\\pipe\\AppProxy_Log_%u", g_config.bridgePid);

    HANDLE hPipe = INVALID_HANDLE_VALUE;
    while (!g_shuttingDown.load(std::memory_order_acquire)) {
        std::deque<std::string> batch;
        {
            std::lock_guard<std::mutex> lock(g_logQueueMutex);
            if (!g_logQueue.empty()) {
                batch.swap(g_logQueue);
            }
        }

        if (batch.empty()) {
            if (g_logEvent) {
                WaitForSingleObject(g_logEvent, 250);
            } else {
                Sleep(50);
            }
            continue;
        }

        if (g_config.bridgePid == 0) {
            continue;
        }

        if (hPipe == INVALID_HANDLE_VALUE) {
            hPipe = CreateFileW(
                pipeName,
                GENERIC_WRITE,
                0,
                nullptr,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                nullptr);
            if (hPipe == INVALID_HANDLE_VALUE) {
                if (GetLastError() == ERROR_PIPE_BUSY) {
                    WaitNamedPipeW(pipeName, 100);
                    hPipe = CreateFileW(
                        pipeName,
                        GENERIC_WRITE,
                        0,
                        nullptr,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        nullptr);
                }
            }
        }

        if (hPipe == INVALID_HANDLE_VALUE) {
            continue;
        }

        for (const auto& line : batch) {
            DWORD written = 0;
            if (!WriteFile(hPipe, line.data(), static_cast<DWORD>(line.size()), &written, nullptr)) {
                CloseHandle(hPipe);
                hPipe = INVALID_HANDLE_VALUE;
                break;
            }
        }
    }

    if (hPipe != INVALID_HANDLE_VALUE) {
        CloseHandle(hPipe);
    }
    return 0;
}

} // namespace

bool SharedBridgeClient::EnsureConnected() {
    if (g_config.bridgePid == 0) return false;
    std::lock_guard<std::mutex> lock(g_shmMutex);
    if (g_shared && g_shared->magic == IPC::kSharedMagic) {
        return true;
    }

    if (!g_hMapFile) {
        wchar_t mapName[128]{};
        swprintf_s(mapName, L"Local\\AppProxy_Shared_%u", g_config.bridgePid);
        g_hMapFile = OpenFileMappingW(FILE_MAP_ALL_ACCESS, FALSE, mapName);
        if (!g_hMapFile) {
            return false;
        }
    }

    if (!g_shared) {
        g_shared = static_cast<IPC::SharedState*>(
            MapViewOfFile(g_hMapFile, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(IPC::SharedState)));
        if (!g_shared) {
            CloseHandle(g_hMapFile);
            g_hMapFile = nullptr;
            return false;
        }
    }

    if (g_shared->magic != IPC::kSharedMagic || g_shared->version != IPC::kSharedVersion) {
        UnmapViewOfFile(g_shared);
        g_shared = nullptr;
        CloseHandle(g_hMapFile);
        g_hMapFile = nullptr;
        return false;
    }

    if (!g_hNamedMutex) {
        wchar_t mutexName[128]{};
        swprintf_s(mutexName, L"Local\\AppProxy_Mutex_%u", g_config.bridgePid);
        g_hNamedMutex = OpenMutexW(SYNCHRONIZE, FALSE, mutexName);
    }

    return true;
}

bool SharedBridgeClient::GetBridgePorts(uint16_t& outPortV4, uint16_t& outPortV6) {
    if (!EnsureConnected()) return false;
    outPortV4 = g_shared->bridgePortV4;
    outPortV6 = g_shared->bridgePortV6;
    return outPortV4 != 0 || outPortV6 != 0;
}

uint32_t SharedBridgeClient::GetEffectiveFlags() {
    uint32_t flags = g_config.flags;
    if (!EnsureConnected()) return flags;

    for (uint32_t i = 0; i < IPC::kMaxSessions; ++i) {
        const auto& s = g_shared->sessions[i];
        if (s.active && s.sessionId == g_config.sessionId) {
            return s.flags;
        }
    }
    return flags;
}

uint32_t SharedBridgeClient::AllocateOrGetFakeIp(const char* domain) {
    std::string norm = NormalizeDomain(domain);
    if (norm.empty() || norm.size() >= sizeof(IPC::FakeIpEntry::domain)) {
        return 0;
    }

    {
        std::lock_guard<std::mutex> lock(g_fakeCacheMutex);
        auto it = g_fakeIpCache.find(norm);
        if (it != g_fakeIpCache.end()) {
            return it->second;
        }
    }

    if (!EnsureConnected()) return 0;

    DWORD waitRes = g_hNamedMutex ? WaitForSingleObject(g_hNamedMutex, 500) : WAIT_OBJECT_0;
    if (waitRes != WAIT_OBJECT_0 && waitRes != WAIT_ABANDONED) {
        return 0;
    }

    uint32_t resultIp = 0;
    bool newlyAllocated = false;

    // Look for existing mapping in shared memory
    for (uint32_t i = 0; i < IPC::kMaxFakeIps; ++i) {
        auto& entry = g_shared->fakeIps[i];
        if (entry.fakeIpHostOrder == 0) break;
        if (_stricmp(entry.domain, norm.c_str()) == 0) {
            entry.lastUsedTick = GetTickCount();
            resultIp = entry.fakeIpHostOrder;
            break;
        }
    }

    if (resultIp == 0) {
        uint32_t slot = g_shared->nextFakeIpOffset % IPC::kMaxFakeIps;
        g_shared->nextFakeIpOffset = (slot + 1) % IPC::kMaxFakeIps;

        auto& entry = g_shared->fakeIps[slot];
        entry.fakeIpHostOrder = IPC::kFakeIpBase + slot;
        entry.lastUsedTick = GetTickCount();
        std::memset(entry.domain, 0, sizeof(entry.domain));
        std::memcpy(entry.domain, norm.data(), norm.size());
        resultIp = entry.fakeIpHostOrder;
        newlyAllocated = true;
    }

    if (g_hNamedMutex) {
        ReleaseMutex(g_hNamedMutex);
    }

    if (resultIp != 0) {
        std::lock_guard<std::mutex> lock(g_fakeCacheMutex);
        g_fakeIpCache[norm] = resultIp;

        if (newlyAllocated) {
            char ipBuf[32]{};
            std::snprintf(
                ipBuf,
                sizeof(ipBuf),
                "%u.%u.%u.%u",
                (resultIp >> 24) & 0xFF,
                (resultIp >> 16) & 0xFF,
                (resultIp >> 8) & 0xFF,
                resultIp & 0xFF);
            EmitLogEvent("DnsResolved", norm + " -> " + ipBuf);
        }
    }

    return resultIp;
}

bool SharedBridgeClient::RegisterNatMapping(
    uint16_t localPortHostOrder,
    uint8_t ipFamily,
    const sockaddr* origAddr) {
    if (!origAddr || localPortHostOrder == 0 || !EnsureConnected()) {
        return false;
    }

    IPC::NatEntry entry{};
    entry.localPortHostOrder = localPortHostOrder;
    entry.ipFamily = ipFamily;
    entry.sessionId = g_config.sessionId;
    entry.pid = g_config.currentPid;
    entry.timestampMs = GetUnixTimeMs();

    if (origAddr->sa_family == AF_INET) {
        const auto* sa4 = reinterpret_cast<const sockaddr_in*>(origAddr);
        uint32_t ipHost = ntohl(sa4->sin_addr.s_addr);
        entry.targetPortHostOrder = ntohs(sa4->sin_port);
        entry.targetType = IPC::IsFakeIpv4HostOrder(ipHost) ? IPC::ADDR_FAKEIP : IPC::ADDR_IPV4;
        std::memcpy(entry.targetAddr, &sa4->sin_addr.s_addr, 4);
    } else if (origAddr->sa_family == AF_INET6) {
        const auto* sa6 = reinterpret_cast<const sockaddr_in6*>(origAddr);
        entry.targetPortHostOrder = ntohs(sa6->sin6_port);
        if (IN6_IS_ADDR_V4MAPPED(&sa6->sin6_addr)) {
            const uint8_t* v4Bytes = sa6->sin6_addr.s6_addr + 12;
            uint32_t ipHost = (static_cast<uint32_t>(v4Bytes[0]) << 24) |
                              (static_cast<uint32_t>(v4Bytes[1]) << 16) |
                              (static_cast<uint32_t>(v4Bytes[2]) << 8) |
                              static_cast<uint32_t>(v4Bytes[3]);
            entry.ipFamily = 4;
            entry.targetType = IPC::IsFakeIpv4HostOrder(ipHost) ? IPC::ADDR_FAKEIP : IPC::ADDR_IPV4;
            std::memcpy(entry.targetAddr, v4Bytes, 4);
        } else {
            uint32_t fakeIpHost = 0;
            if (IPC::IsFakeIpv6Bytes(sa6->sin6_addr.s6_addr, &fakeIpHost)) {
                entry.targetType = IPC::ADDR_FAKEIP;
            } else {
                entry.targetType = IPC::ADDR_IPV6;
            }
            std::memcpy(entry.targetAddr, sa6->sin6_addr.s6_addr, 16);
        }
    } else {
        return false;
    }

    DWORD waitRes = g_hNamedMutex ? WaitForSingleObject(g_hNamedMutex, 250) : WAIT_OBJECT_0;
    if (waitRes != WAIT_OBJECT_0 && waitRes != WAIT_ABANDONED) {
        return false;
    }

    uint32_t slot = g_shared->nextNatSlot % IPC::kMaxNatSlots;
    g_shared->nextNatSlot = (slot + 1) % IPC::kMaxNatSlots;
    g_shared->natTable[slot] = entry;

    if (g_hNamedMutex) {
        ReleaseMutex(g_hNamedMutex);
    }
    return true;
}

void SharedBridgeClient::StartLogWorker() {
    if (g_config.bridgePid == 0) return;
    std::call_once(g_logWorkerOnce, []() {
        g_logEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        g_logThread = CreateThread(nullptr, 0, LogWorkerProc, nullptr, 0, nullptr);
    });
}

void SharedBridgeClient::EmitLogEvent(const char* eventType, const std::string& message) {
    if (g_config.bridgePid == 0 || g_shuttingDown.load(std::memory_order_acquire)) {
        return;
    }
    StartLogWorker();

    std::string line = IPC::FormatLogLineJson(
        GetUnixTimeMs(),
        g_config.sessionId,
        g_config.currentPid,
        g_config.parentPid,
        CurrentArchString(),
        g_config.processName,
        eventType,
        message);

    {
        std::lock_guard<std::mutex> lock(g_logQueueMutex);
        if (g_logQueue.size() >= 1024) {
            g_logQueue.pop_front();
        }
        g_logQueue.push_back(std::move(line));
    }

    if (g_logEvent) {
        SetEvent(g_logEvent);
    }
}

void SharedBridgeClient::Shutdown(bool processTerminating) {
    g_shuttingDown.store(true, std::memory_order_release);
    if (g_logEvent) {
        SetEvent(g_logEvent);
    }
    if (!processTerminating && g_logThread) {
        WaitForSingleObject(g_logThread, 500);
        CloseHandle(g_logThread);
        g_logThread = nullptr;
    }
    if (!processTerminating) {
        std::lock_guard<std::mutex> lock(g_shmMutex);
        if (g_shared) {
            UnmapViewOfFile(g_shared);
            g_shared = nullptr;
        }
        if (g_hMapFile) {
            CloseHandle(g_hMapFile);
            g_hMapFile = nullptr;
        }
        if (g_hNamedMutex) {
            CloseHandle(g_hNamedMutex);
            g_hNamedMutex = nullptr;
        }
        if (g_logEvent) {
            CloseHandle(g_logEvent);
            g_logEvent = nullptr;
        }
    }
}

} // namespace AppProxy::Hook

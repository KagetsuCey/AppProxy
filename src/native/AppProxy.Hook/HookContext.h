#pragma once

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <windows.h>

#include <atomic>
#include <cstdint>
#include <string>

#include "SharedLayout.h"

namespace AppProxy::Hook {

struct HookRuntimeConfig {
    uint32_t bridgePid = 0;
    uint32_t sessionId = 0;
    uint32_t flags     = 0;
    uint32_t currentPid = 0;
    uint32_t parentPid  = 0;
    std::wstring selfDir;
    std::string  processName;
};

inline HookRuntimeConfig g_config;
inline std::atomic<bool> g_shuttingDown{false};

inline const char* CurrentArchString() {
#if defined(_WIN64)
    return "x64";
#else
    return "x86";
#endif
}

inline std::string WideToUtf8(const wchar_t* wstr, int len = -1) {
    if (!wstr || (len == 0)) return {};
    int needed = WideCharToMultiByte(CP_UTF8, 0, wstr, len, nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr, len, out.data(), needed, nullptr, nullptr);
    if (len == -1 && !out.empty() && out.back() == '\0') {
        out.pop_back();
    }
    return out;
}

inline std::wstring Utf8ToWide(const char* str, int len = -1) {
    if (!str || (len == 0)) return {};
    int needed = MultiByteToWideChar(CP_UTF8, 0, str, len, nullptr, 0);
    if (needed <= 0) return {};
    std::wstring out(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str, len, out.data(), needed);
    if (len == -1 && !out.empty() && out.back() == L'\0') {
        out.pop_back();
    }
    return out;
}

inline uint64_t GetUnixTimeMs() {
    FILETIME ft{};
    GetSystemTimeAsFileTime(&ft);
    ULARGE_INTEGER uli{};
    uli.LowPart  = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    // Convert 100ns intervals since 1601-01-01 to ms since 1970-01-01
    constexpr uint64_t kEpochDiff = 116444736000000000ULL;
    return (uli.QuadPart - kEpochDiff) / 10000ULL;
}

// Hook installers declared across compilation units
bool InstallNetworkHooks();
bool InstallDnsHooks();
bool InstallProcessHooks();
void CleanupProcessHooks();

} // namespace AppProxy::Hook

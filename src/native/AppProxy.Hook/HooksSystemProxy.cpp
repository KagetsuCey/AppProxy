#include "HookContext.h"
#include <wininet.h>
#include <MinHook.h>

#include <algorithm>
#include <cstring>
#include <cwchar>
#include <cwctype>
#include <string>
#include <string_view>
#include <vector>

namespace AppProxy::Hook {

namespace {

enum class ProxyRegValueKind {
    None,
    DwordZero,
    NotFound,
    ConnectionSettingsBlob
};

using FnRegQueryValueExW = LSTATUS(WINAPI*)(HKEY, LPCWSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
using FnRegQueryValueExA = LSTATUS(WINAPI*)(HKEY, LPCSTR, LPDWORD, LPDWORD, LPBYTE, LPDWORD);
using FnRegGetValueW = LSTATUS(WINAPI*)(HKEY, LPCWSTR, LPCWSTR, DWORD, LPDWORD, PVOID, LPDWORD);
using FnRegGetValueA = LSTATUS(WINAPI*)(HKEY, LPCSTR, LPCSTR, DWORD, LPDWORD, PVOID, LPDWORD);

using FnInternetOpenW = HINTERNET(WINAPI*)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
using FnInternetOpenA = HINTERNET(WINAPI*)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD);
using FnInternetQueryOptionW = BOOL(WINAPI*)(HINTERNET, DWORD, LPVOID, LPDWORD);
using FnInternetQueryOptionA = BOOL(WINAPI*)(HINTERNET, DWORD, LPVOID, LPDWORD);

using FnNtQueryKey = LONG(NTAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);

struct NtKeyNameInformation {
    ULONG NameLength;
    WCHAR Name[1];
};

FnRegQueryValueExW g_TrueRegQueryValueExW = nullptr;
FnRegQueryValueExA g_TrueRegQueryValueExA = nullptr;
FnRegGetValueW g_TrueRegGetValueW = nullptr;
FnRegGetValueA g_TrueRegGetValueA = nullptr;

FnInternetOpenW g_TrueInternetOpenW = nullptr;
FnInternetOpenA g_TrueInternetOpenA = nullptr;
FnInternetQueryOptionW g_TrueInternetQueryOptionW = nullptr;
FnInternetQueryOptionA g_TrueInternetQueryOptionA = nullptr;

ProxyRegValueKind ClassifyProxyRegValueW(LPCWSTR valueName) {
    if (!valueName || valueName[0] == L'\0') return ProxyRegValueKind::None;
    if (_wcsicmp(valueName, L"ProxyEnable") == 0 ||
        _wcsicmp(valueName, L"AutoDetect") == 0) {
        return ProxyRegValueKind::DwordZero;
    }
    if (_wcsicmp(valueName, L"ProxyServer") == 0 ||
        _wcsicmp(valueName, L"AutoConfigURL") == 0 ||
        _wcsicmp(valueName, L"ProxyOverride") == 0) {
        return ProxyRegValueKind::NotFound;
    }
    if (_wcsicmp(valueName, L"DefaultConnectionSettings") == 0 ||
        _wcsicmp(valueName, L"SavedLegacySettings") == 0) {
        return ProxyRegValueKind::ConnectionSettingsBlob;
    }
    return ProxyRegValueKind::None;
}

ProxyRegValueKind ClassifyProxyRegValueA(LPCSTR valueName) {
    if (!valueName || valueName[0] == '\0') return ProxyRegValueKind::None;
    if (_stricmp(valueName, "ProxyEnable") == 0 ||
        _stricmp(valueName, "AutoDetect") == 0) {
        return ProxyRegValueKind::DwordZero;
    }
    if (_stricmp(valueName, "ProxyServer") == 0 ||
        _stricmp(valueName, "AutoConfigURL") == 0 ||
        _stricmp(valueName, "ProxyOverride") == 0) {
        return ProxyRegValueKind::NotFound;
    }
    if (_stricmp(valueName, "DefaultConnectionSettings") == 0 ||
        _stricmp(valueName, "SavedLegacySettings") == 0) {
        return ProxyRegValueKind::ConnectionSettingsBlob;
    }
    return ProxyRegValueKind::None;
}

bool IsPredefinedHKey(HKEY hKey) {
    return hKey == HKEY_CLASSES_ROOT ||
           hKey == HKEY_CURRENT_USER ||
           hKey == HKEY_LOCAL_MACHINE ||
           hKey == HKEY_USERS ||
           hKey == HKEY_PERFORMANCE_DATA ||
           hKey == HKEY_PERFORMANCE_TEXT ||
           hKey == HKEY_PERFORMANCE_NLSTEXT ||
           hKey == HKEY_CURRENT_CONFIG ||
           hKey == HKEY_DYN_DATA ||
           hKey == HKEY_CURRENT_USER_LOCAL_SETTINGS;
}

std::wstring AnsiToWide(LPCSTR s) {
    if (!s || s[0] == '\0') return {};
    int needed = MultiByteToWideChar(CP_ACP, 0, s, -1, nullptr, 0);
    if (needed <= 0) return {};
    std::wstring out(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_ACP, 0, s, -1, out.data(), needed);
    if (!out.empty() && out.back() == L'\0') {
        out.pop_back();
    }
    return out;
}

std::wstring QueryNtKeyPath(HKEY hKey) {
    if (!hKey || IsPredefinedHKey(hKey)) return {};

    static auto fnNtQueryKey = reinterpret_cast<FnNtQueryKey>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryKey"));
    if (!fnNtQueryKey) return {};

    constexpr ULONG kKeyNameInformation = 3;
    constexpr LONG kStatusSuccess = 0x00000000L;
    constexpr LONG kStatusBufferOverflow = static_cast<LONG>(0x80000005L);
    constexpr LONG kStatusBufferTooSmall = static_cast<LONG>(0xC0000023L);

    uint8_t stackBuf[1024]{};
    ULONG needed = 0;
    LONG status = fnNtQueryKey(hKey, kKeyNameInformation, stackBuf, sizeof(stackBuf), &needed);
    if (status == kStatusSuccess) {
        const auto* info = reinterpret_cast<const NtKeyNameInformation*>(stackBuf);
        return std::wstring(info->Name, info->NameLength / sizeof(wchar_t));
    }

    if ((status == kStatusBufferOverflow || status == kStatusBufferTooSmall) &&
        needed > sizeof(NtKeyNameInformation) && needed <= 65536) {
        std::vector<uint8_t> heapBuf(needed);
        status = fnNtQueryKey(hKey, kKeyNameInformation, heapBuf.data(), needed, &needed);
        if (status == kStatusSuccess) {
            const auto* info = reinterpret_cast<const NtKeyNameInformation*>(heapBuf.data());
            return std::wstring(info->Name, info->NameLength / sizeof(wchar_t));
        }
    }

    return {};
}

bool EndsWithNoCase(std::wstring_view haystack, std::wstring_view suffix) {
    if (haystack.size() < suffix.size()) return false;
    size_t offset = haystack.size() - suffix.size();
    return _wcsnicmp(haystack.data() + offset, suffix.data(), suffix.size()) == 0;
}

bool IsInternetSettingsPath(HKEY hKey, LPCWSTR subKey) {
    std::wstring fullPath;
    if (IsPredefinedHKey(hKey)) {
        if (!subKey || subKey[0] == L'\0') return false;
        fullPath = subKey;
    } else {
        fullPath = QueryNtKeyPath(hKey);
        if (fullPath.empty()) return false;
        if (subKey && subKey[0] != L'\0') {
            if (fullPath.back() != L'\\' && subKey[0] != L'\\') {
                fullPath.push_back(L'\\');
            }
            fullPath.append(subKey);
        }
    }

    while (!fullPath.empty() && fullPath.back() == L'\\') {
        fullPath.pop_back();
    }
    if (fullPath.empty()) return false;

    static constexpr std::wstring_view kSettingsSuffix =
        L"\\microsoft\\windows\\currentversion\\internet settings";
    static constexpr std::wstring_view kConnectionsSuffix =
        L"\\microsoft\\windows\\currentversion\\internet settings\\connections";
    static constexpr std::wstring_view kRelSettings =
        L"software\\microsoft\\windows\\currentversion\\internet settings";
    static constexpr std::wstring_view kRelConnections =
        L"software\\microsoft\\windows\\currentversion\\internet settings\\connections";

    return EndsWithNoCase(fullPath, kSettingsSuffix) ||
           EndsWithNoCase(fullPath, kConnectionsSuffix) ||
           _wcsicmp(fullPath.c_str(), kRelSettings.data()) == 0 ||
           _wcsicmp(fullPath.c_str(), kRelConnections.data()) == 0;
}

LSTATUS WriteDwordZeroResult(LPDWORD lpType, PVOID lpData, LPDWORD lpcbData) {
    if (lpType) {
        *lpType = REG_DWORD;
    }
    if (!lpData) {
        if (lpcbData) {
            *lpcbData = sizeof(DWORD);
        }
        return ERROR_SUCCESS;
    }
    if (!lpcbData) {
        return ERROR_INVALID_PARAMETER;
    }
    if (*lpcbData < sizeof(DWORD)) {
        *lpcbData = sizeof(DWORD);
        return ERROR_MORE_DATA;
    }
    *static_cast<DWORD*>(lpData) = 0;
    *lpcbData = sizeof(DWORD);
    return ERROR_SUCCESS;
}

void PatchConnectionSettingsBlob(DWORD type, PVOID lpData, LPDWORD lpcbData) {
    if (type == REG_BINARY && lpData && lpcbData && *lpcbData >= 12) {
        auto* dwords = static_cast<uint32_t*>(lpData);
        // Offset 8..11 stores WININET connection flags (PROXY_TYPE_DIRECT = 1)
        dwords[2] = PROXY_TYPE_DIRECT;
    }
}

LSTATUS WINAPI HookedRegQueryValueExW(
    HKEY hKey,
    LPCWSTR lpValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE lpData,
    LPDWORD lpcbData) {
    ProxyRegValueKind kind = ShouldIgnoreSystemProxy()
        ? ClassifyProxyRegValueW(lpValueName)
        : ProxyRegValueKind::None;

    if (kind != ProxyRegValueKind::None && IsInternetSettingsPath(hKey, nullptr)) {
        if (kind == ProxyRegValueKind::DwordZero) {
            return WriteDwordZeroResult(lpType, lpData, lpcbData);
        }
        if (kind == ProxyRegValueKind::NotFound) {
            return ERROR_FILE_NOT_FOUND;
        }
        DWORD localType = REG_BINARY;
        DWORD* typePtr = lpType ? lpType : &localType;
        LSTATUS ret = g_TrueRegQueryValueExW(hKey, lpValueName, lpReserved, typePtr, lpData, lpcbData);
        if (ret == ERROR_SUCCESS) {
            PatchConnectionSettingsBlob(*typePtr, lpData, lpcbData);
        }
        return ret;
    }

    return g_TrueRegQueryValueExW(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}

LSTATUS WINAPI HookedRegQueryValueExA(
    HKEY hKey,
    LPCSTR lpValueName,
    LPDWORD lpReserved,
    LPDWORD lpType,
    LPBYTE lpData,
    LPDWORD lpcbData) {
    ProxyRegValueKind kind = ShouldIgnoreSystemProxy()
        ? ClassifyProxyRegValueA(lpValueName)
        : ProxyRegValueKind::None;

    if (kind != ProxyRegValueKind::None && IsInternetSettingsPath(hKey, nullptr)) {
        if (kind == ProxyRegValueKind::DwordZero) {
            return WriteDwordZeroResult(lpType, lpData, lpcbData);
        }
        if (kind == ProxyRegValueKind::NotFound) {
            return ERROR_FILE_NOT_FOUND;
        }
        DWORD localType = REG_BINARY;
        DWORD* typePtr = lpType ? lpType : &localType;
        LSTATUS ret = g_TrueRegQueryValueExA(hKey, lpValueName, lpReserved, typePtr, lpData, lpcbData);
        if (ret == ERROR_SUCCESS) {
            PatchConnectionSettingsBlob(*typePtr, lpData, lpcbData);
        }
        return ret;
    }

    return g_TrueRegQueryValueExA(hKey, lpValueName, lpReserved, lpType, lpData, lpcbData);
}

LSTATUS WINAPI HookedRegGetValueW(
    HKEY hkey,
    LPCWSTR lpSubKey,
    LPCWSTR lpValue,
    DWORD dwFlags,
    LPDWORD pdwType,
    PVOID pvData,
    LPDWORD pcbData) {
    ProxyRegValueKind kind = ShouldIgnoreSystemProxy()
        ? ClassifyProxyRegValueW(lpValue)
        : ProxyRegValueKind::None;

    if (kind != ProxyRegValueKind::None && IsInternetSettingsPath(hkey, lpSubKey)) {
        if (kind == ProxyRegValueKind::DwordZero) {
            if ((dwFlags & RRF_RT_ANY) != 0 && (dwFlags & RRF_RT_REG_DWORD) == 0) {
                if ((dwFlags & RRF_ZEROONFAILURE) != 0 && pvData && pcbData && *pcbData > 0) {
                    std::memset(pvData, 0, *pcbData);
                }
                return ERROR_UNSUPPORTED_TYPE;
            }
            return WriteDwordZeroResult(pdwType, pvData, pcbData);
        }
        if (kind == ProxyRegValueKind::NotFound) {
            if ((dwFlags & RRF_ZEROONFAILURE) != 0 && pvData && pcbData && *pcbData > 0) {
                std::memset(pvData, 0, *pcbData);
            }
            return ERROR_FILE_NOT_FOUND;
        }
        DWORD localType = REG_BINARY;
        DWORD* typePtr = pdwType ? pdwType : &localType;
        LSTATUS ret = g_TrueRegGetValueW(hkey, lpSubKey, lpValue, dwFlags, typePtr, pvData, pcbData);
        if (ret == ERROR_SUCCESS) {
            PatchConnectionSettingsBlob(*typePtr, pvData, pcbData);
        }
        return ret;
    }

    return g_TrueRegGetValueW(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);
}

LSTATUS WINAPI HookedRegGetValueA(
    HKEY hkey,
    LPCSTR lpSubKey,
    LPCSTR lpValue,
    DWORD dwFlags,
    LPDWORD pdwType,
    PVOID pvData,
    LPDWORD pcbData) {
    ProxyRegValueKind kind = ShouldIgnoreSystemProxy()
        ? ClassifyProxyRegValueA(lpValue)
        : ProxyRegValueKind::None;

    if (kind != ProxyRegValueKind::None) {
        std::wstring subKeyW = AnsiToWide(lpSubKey);
        if (IsInternetSettingsPath(hkey, subKeyW.empty() ? nullptr : subKeyW.c_str())) {
            if (kind == ProxyRegValueKind::DwordZero) {
                if ((dwFlags & RRF_RT_ANY) != 0 && (dwFlags & RRF_RT_REG_DWORD) == 0) {
                    if ((dwFlags & RRF_ZEROONFAILURE) != 0 && pvData && pcbData && *pcbData > 0) {
                        std::memset(pvData, 0, *pcbData);
                    }
                    return ERROR_UNSUPPORTED_TYPE;
                }
                return WriteDwordZeroResult(pdwType, pvData, pcbData);
            }
            if (kind == ProxyRegValueKind::NotFound) {
                if ((dwFlags & RRF_ZEROONFAILURE) != 0 && pvData && pcbData && *pcbData > 0) {
                    std::memset(pvData, 0, *pcbData);
                }
                return ERROR_FILE_NOT_FOUND;
            }
            DWORD localType = REG_BINARY;
            DWORD* typePtr = pdwType ? pdwType : &localType;
            LSTATUS ret = g_TrueRegGetValueA(hkey, lpSubKey, lpValue, dwFlags, typePtr, pvData, pcbData);
            if (ret == ERROR_SUCCESS) {
                PatchConnectionSettingsBlob(*typePtr, pvData, pcbData);
            }
            return ret;
        }
    }

    return g_TrueRegGetValueA(hkey, lpSubKey, lpValue, dwFlags, pdwType, pvData, pcbData);
}

HINTERNET WINAPI HookedInternetOpenW(
    LPCWSTR lpszAgent,
    DWORD dwAccessType,
    LPCWSTR lpszProxy,
    LPCWSTR lpszProxyBypass,
    DWORD dwFlags) {
    if (ShouldIgnoreSystemProxy() &&
        (dwAccessType == INTERNET_OPEN_TYPE_PRECONFIG ||
         dwAccessType == INTERNET_OPEN_TYPE_PRECONFIG_WITH_NO_AUTOPROXY)) {
        dwAccessType = INTERNET_OPEN_TYPE_DIRECT;
        lpszProxy = nullptr;
        lpszProxyBypass = nullptr;
    }
    return g_TrueInternetOpenW(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
}

HINTERNET WINAPI HookedInternetOpenA(
    LPCSTR lpszAgent,
    DWORD dwAccessType,
    LPCSTR lpszProxy,
    LPCSTR lpszProxyBypass,
    DWORD dwFlags) {
    if (ShouldIgnoreSystemProxy() &&
        (dwAccessType == INTERNET_OPEN_TYPE_PRECONFIG ||
         dwAccessType == INTERNET_OPEN_TYPE_PRECONFIG_WITH_NO_AUTOPROXY)) {
        dwAccessType = INTERNET_OPEN_TYPE_DIRECT;
        lpszProxy = nullptr;
        lpszProxyBypass = nullptr;
    }
    return g_TrueInternetOpenA(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
}

template <typename TProxyInfo, typename TOptionList>
BOOL HandleInternetQueryOptionDirect(
    HINTERNET hInternet,
    DWORD dwOption,
    LPVOID lpBuffer,
    LPDWORD lpdwBufferLength,
    BOOL& outHandled) {
    outHandled = FALSE;
    if (!ShouldIgnoreSystemProxy()) {
        return FALSE;
    }

    if (dwOption == INTERNET_OPTION_PROXY && hInternet == nullptr) {
        outHandled = TRUE;
        if (!lpdwBufferLength) {
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        if (!lpBuffer || *lpdwBufferLength < sizeof(TProxyInfo)) {
            *lpdwBufferLength = sizeof(TProxyInfo);
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }
        auto* info = static_cast<TProxyInfo*>(lpBuffer);
        info->dwAccessType = INTERNET_OPEN_TYPE_DIRECT;
        info->lpszProxy = nullptr;
        info->lpszProxyBypass = nullptr;
        *lpdwBufferLength = sizeof(TProxyInfo);
        SetLastError(ERROR_SUCCESS);
        return TRUE;
    }

    if (dwOption == INTERNET_OPTION_PER_CONNECTION_OPTION) {
        if (!lpdwBufferLength) {
            outHandled = TRUE;
            SetLastError(ERROR_INVALID_PARAMETER);
            return FALSE;
        }
        if (!lpBuffer || *lpdwBufferLength < sizeof(TOptionList)) {
            outHandled = TRUE;
            *lpdwBufferLength = sizeof(TOptionList);
            SetLastError(ERROR_INSUFFICIENT_BUFFER);
            return FALSE;
        }
        auto* list = static_cast<TOptionList*>(lpBuffer);
        if (list->dwSize >= sizeof(TOptionList) && list->pOptions != nullptr) {
            outHandled = TRUE;
            for (DWORD i = 0; i < list->dwOptionCount; ++i) {
                switch (list->pOptions[i].dwOption) {
                case INTERNET_PER_CONN_FLAGS:
                case INTERNET_PER_CONN_FLAGS_UI:
                    list->pOptions[i].Value.dwValue = PROXY_TYPE_DIRECT;
                    break;
                case INTERNET_PER_CONN_PROXY_SERVER:
                case INTERNET_PER_CONN_PROXY_BYPASS:
                case INTERNET_PER_CONN_AUTOCONFIG_URL:
                case INTERNET_PER_CONN_AUTOCONFIG_SECONDARY_URL:
                case INTERNET_PER_CONN_AUTOCONFIG_LAST_DETECT_URL:
                    list->pOptions[i].Value.pszValue = nullptr;
                    break;
                case INTERNET_PER_CONN_AUTODISCOVERY_FLAGS:
                case INTERNET_PER_CONN_AUTOCONFIG_RELOAD_DELAY_MINS:
                    list->pOptions[i].Value.dwValue = 0;
                    break;
                case INTERNET_PER_CONN_AUTOCONFIG_LAST_DETECT_TIME:
                    list->pOptions[i].Value.ftValue = FILETIME{};
                    break;
                default:
                    break;
                }
            }
            list->dwOptionError = 0;
            SetLastError(ERROR_SUCCESS);
            return TRUE;
        }
    }

    return FALSE;
}

BOOL WINAPI HookedInternetQueryOptionW(
    HINTERNET hInternet,
    DWORD dwOption,
    LPVOID lpBuffer,
    LPDWORD lpdwBufferLength) {
    BOOL handled = FALSE;
    BOOL res = HandleInternetQueryOptionDirect<INTERNET_PROXY_INFO, INTERNET_PER_CONN_OPTION_LISTW>(
        hInternet, dwOption, lpBuffer, lpdwBufferLength, handled);
    if (handled) {
        return res;
    }
    return g_TrueInternetQueryOptionW(hInternet, dwOption, lpBuffer, lpdwBufferLength);
}

BOOL WINAPI HookedInternetQueryOptionA(
    HINTERNET hInternet,
    DWORD dwOption,
    LPVOID lpBuffer,
    LPDWORD lpdwBufferLength) {
    BOOL handled = FALSE;
    BOOL res = HandleInternetQueryOptionDirect<INTERNET_PROXY_INFO, INTERNET_PER_CONN_OPTION_LISTA>(
        hInternet, dwOption, lpBuffer, lpdwBufferLength, handled);
    if (handled) {
        return res;
    }
    return g_TrueInternetQueryOptionA(hInternet, dwOption, lpBuffer, lpdwBufferLength);
}

} // namespace

void SanitizeProcessProxyEnv() {
    static constexpr const wchar_t* kProxyVars[] = {
        L"HTTP_PROXY", L"HTTPS_PROXY", L"ALL_PROXY", L"FTP_PROXY", L"SOCKS_PROXY",
        L"http_proxy", L"https_proxy", L"all_proxy", L"ftp_proxy", L"socks_proxy",
    };
    for (const wchar_t* var : kProxyVars) {
        SetEnvironmentVariableW(var, nullptr);
    }
}

bool InstallRegistryHooks() {
    static bool s_installed = false;
    if (s_installed) return true;
    if (!GetModuleHandleW(L"kernelbase.dll")) return false;

    MH_CreateHookApi(L"kernelbase", "RegQueryValueExW", &HookedRegQueryValueExW, reinterpret_cast<LPVOID*>(&g_TrueRegQueryValueExW));
    MH_CreateHookApi(L"kernelbase", "RegQueryValueExA", &HookedRegQueryValueExA, reinterpret_cast<LPVOID*>(&g_TrueRegQueryValueExA));
    MH_CreateHookApi(L"kernelbase", "RegGetValueW", &HookedRegGetValueW, reinterpret_cast<LPVOID*>(&g_TrueRegGetValueW));
    MH_CreateHookApi(L"kernelbase", "RegGetValueA", &HookedRegGetValueA, reinterpret_cast<LPVOID*>(&g_TrueRegGetValueA));
    s_installed = true;
    return true;
}

bool InstallWinInetHooks() {
    static bool s_installed = false;
    if (s_installed) return true;
    if (!GetModuleHandleW(L"wininet.dll")) return false;

    MH_CreateHookApi(L"wininet", "InternetOpenW", &HookedInternetOpenW, reinterpret_cast<LPVOID*>(&g_TrueInternetOpenW));
    MH_CreateHookApi(L"wininet", "InternetOpenA", &HookedInternetOpenA, reinterpret_cast<LPVOID*>(&g_TrueInternetOpenA));
    MH_CreateHookApi(L"wininet", "InternetQueryOptionW", &HookedInternetQueryOptionW, reinterpret_cast<LPVOID*>(&g_TrueInternetQueryOptionW));
    MH_CreateHookApi(L"wininet", "InternetQueryOptionA", &HookedInternetQueryOptionA, reinterpret_cast<LPVOID*>(&g_TrueInternetQueryOptionA));
    s_installed = true;
    return true;
}

} // namespace AppProxy::Hook

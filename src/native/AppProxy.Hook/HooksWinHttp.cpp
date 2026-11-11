#include "HookContext.h"
#include <winhttp.h>
#include <MinHook.h>

#include <cstring>

namespace AppProxy::Hook {

namespace {

using FnWinHttpOpen = HINTERNET(WINAPI*)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
using FnWinHttpGetIEProxyConfigForCurrentUser = BOOL(WINAPI*)(WINHTTP_CURRENT_USER_IE_PROXY_CONFIG*);
using FnWinHttpGetDefaultProxyConfiguration = BOOL(WINAPI*)(WINHTTP_PROXY_INFO*);
using FnWinHttpGetProxyForUrl = BOOL(WINAPI*)(HINTERNET, LPCWSTR, WINHTTP_AUTOPROXY_OPTIONS*, WINHTTP_PROXY_INFO*);
using FnWinHttpDetectAutoProxyConfigUrl = BOOL(WINAPI*)(DWORD, LPWSTR*);
using FnWinHttpGetProxyResult = DWORD(WINAPI*)(HINTERNET, WINHTTP_PROXY_RESULT*);
using FnWinHttpGetProxyResultEx = DWORD(WINAPI*)(HINTERNET, WINHTTP_PROXY_RESULT_EX*);
using FnWinHttpReadProxySettings = DWORD(WINAPI*)(HINTERNET, PCWSTR, BOOL, BOOL, DWORD*, BOOL*, WINHTTP_PROXY_SETTINGS*);
using FnWinHttpFreeProxySettings = VOID(WINAPI*)(WINHTTP_PROXY_SETTINGS*);
using FnWinHttpGetProxySettingsResultEx = DWORD(WINAPI*)(HINTERNET, PVOID);

FnWinHttpOpen g_TrueWinHttpOpen = nullptr;
FnWinHttpGetIEProxyConfigForCurrentUser g_TrueWinHttpGetIEProxyConfigForCurrentUser = nullptr;
FnWinHttpGetDefaultProxyConfiguration g_TrueWinHttpGetDefaultProxyConfiguration = nullptr;
FnWinHttpGetProxyForUrl g_TrueWinHttpGetProxyForUrl = nullptr;
FnWinHttpDetectAutoProxyConfigUrl g_TrueWinHttpDetectAutoProxyConfigUrl = nullptr;
FnWinHttpGetProxyResult g_TrueWinHttpGetProxyResult = nullptr;
FnWinHttpGetProxyResultEx g_TrueWinHttpGetProxyResultEx = nullptr;
FnWinHttpReadProxySettings g_TrueWinHttpReadProxySettings = nullptr;
FnWinHttpFreeProxySettings g_WinHttpFreeProxySettings = nullptr;
FnWinHttpGetProxySettingsResultEx g_TrueWinHttpGetProxySettingsResultEx = nullptr;

HINTERNET WINAPI HookedWinHttpOpen(
    LPCWSTR pszAgentW,
    DWORD dwAccessType,
    LPCWSTR pszProxyW,
    LPCWSTR pszProxyBypassW,
    DWORD dwFlags) {
    if (ShouldIgnoreSystemProxy() &&
        (dwAccessType == WINHTTP_ACCESS_TYPE_DEFAULT_PROXY ||
         dwAccessType == WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY)) {
        dwAccessType = WINHTTP_ACCESS_TYPE_NO_PROXY;
        pszProxyW = WINHTTP_NO_PROXY_NAME;
        pszProxyBypassW = WINHTTP_NO_PROXY_BYPASS;
    }
    return g_TrueWinHttpOpen(pszAgentW, dwAccessType, pszProxyW, pszProxyBypassW, dwFlags);
}

BOOL WINAPI HookedWinHttpGetIEProxyConfigForCurrentUser(
    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG* pProxyConfig) {
    if (!ShouldIgnoreSystemProxy()) {
        return g_TrueWinHttpGetIEProxyConfigForCurrentUser(pProxyConfig);
    }
    if (!pProxyConfig) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    pProxyConfig->fAutoDetect = FALSE;
    pProxyConfig->lpszAutoConfigUrl = nullptr;
    pProxyConfig->lpszProxy = nullptr;
    pProxyConfig->lpszProxyBypass = nullptr;
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

BOOL WINAPI HookedWinHttpGetDefaultProxyConfiguration(WINHTTP_PROXY_INFO* pProxyInfo) {
    if (!ShouldIgnoreSystemProxy()) {
        return g_TrueWinHttpGetDefaultProxyConfiguration(pProxyInfo);
    }
    if (!pProxyInfo) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    pProxyInfo->dwAccessType = WINHTTP_ACCESS_TYPE_NO_PROXY;
    pProxyInfo->lpszProxy = nullptr;
    pProxyInfo->lpszProxyBypass = nullptr;
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

BOOL WINAPI HookedWinHttpGetProxyForUrl(
    HINTERNET hSession,
    LPCWSTR lpcwszUrl,
    WINHTTP_AUTOPROXY_OPTIONS* pAutoProxyOptions,
    WINHTTP_PROXY_INFO* pProxyInfo) {
    if (!ShouldIgnoreSystemProxy()) {
        return g_TrueWinHttpGetProxyForUrl(hSession, lpcwszUrl, pAutoProxyOptions, pProxyInfo);
    }
    if (!pProxyInfo) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }
    pProxyInfo->dwAccessType = WINHTTP_ACCESS_TYPE_NO_PROXY;
    pProxyInfo->lpszProxy = nullptr;
    pProxyInfo->lpszProxyBypass = nullptr;
    SetLastError(ERROR_SUCCESS);
    return TRUE;
}

BOOL WINAPI HookedWinHttpDetectAutoProxyConfigUrl(
    DWORD dwAutoDetectFlags,
    LPWSTR* ppwstrAutoConfigUrl) {
    if (!ShouldIgnoreSystemProxy()) {
        return g_TrueWinHttpDetectAutoProxyConfigUrl(dwAutoDetectFlags, ppwstrAutoConfigUrl);
    }
    if (ppwstrAutoConfigUrl) {
        *ppwstrAutoConfigUrl = nullptr;
    }
    SetLastError(ERROR_WINHTTP_AUTODETECTION_FAILED);
    return FALSE;
}

DWORD WINAPI HookedWinHttpGetProxyResult(
    HINTERNET hResolver,
    WINHTTP_PROXY_RESULT* pProxyResult) {
    DWORD ret = g_TrueWinHttpGetProxyResult(hResolver, pProxyResult);
    if (ret == ERROR_SUCCESS && ShouldIgnoreSystemProxy() && pProxyResult && pProxyResult->pEntries) {
        for (DWORD i = 0; i < pProxyResult->cEntries; ++i) {
            pProxyResult->pEntries[i].fProxy = FALSE;
            pProxyResult->pEntries[i].fBypass = FALSE;
        }
    }
    return ret;
}

DWORD WINAPI HookedWinHttpGetProxyResultEx(
    HINTERNET hResolver,
    WINHTTP_PROXY_RESULT_EX* pProxyResultEx) {
    DWORD ret = g_TrueWinHttpGetProxyResultEx(hResolver, pProxyResultEx);
    if (ret == ERROR_SUCCESS && ShouldIgnoreSystemProxy() && pProxyResultEx && pProxyResultEx->pEntries) {
        for (DWORD i = 0; i < pProxyResultEx->cEntries; ++i) {
            pProxyResultEx->pEntries[i].fProxy = FALSE;
            pProxyResultEx->pEntries[i].fBypass = FALSE;
        }
    }
    return ret;
}

DWORD WINAPI HookedWinHttpReadProxySettings(
    HINTERNET hSession,
    PCWSTR pcwszConnectionName,
    BOOL fFallBackToDefaultSettings,
    BOOL fSetAutoDiscoverForDefaultSettings,
    DWORD* pdwSettingsVersion,
    BOOL* pfDefaultSettingsAreReturned,
    WINHTTP_PROXY_SETTINGS* pWinHttpProxySettings) {
    DWORD ret = g_TrueWinHttpReadProxySettings(
        hSession,
        pcwszConnectionName,
        fFallBackToDefaultSettings,
        fSetAutoDiscoverForDefaultSettings,
        pdwSettingsVersion,
        pfDefaultSettingsAreReturned,
        pWinHttpProxySettings);
    if (ret == ERROR_SUCCESS && ShouldIgnoreSystemProxy() && pWinHttpProxySettings) {
        DWORD structSize = pWinHttpProxySettings->dwStructSize;
        DWORD settingsVer = pWinHttpProxySettings->dwCurrentSettingsVersion;
        if (g_WinHttpFreeProxySettings) {
            g_WinHttpFreeProxySettings(pWinHttpProxySettings);
        }
        std::memset(pWinHttpProxySettings, 0, sizeof(*pWinHttpProxySettings));
        pWinHttpProxySettings->dwStructSize = structSize != 0 ? structSize : sizeof(WINHTTP_PROXY_SETTINGS);
        pWinHttpProxySettings->dwCurrentSettingsVersion = settingsVer;
        pWinHttpProxySettings->dwFlags = WINHTTP_PROXY_TYPE_DIRECT;
    }
    return ret;
}

DWORD WINAPI HookedWinHttpGetProxySettingsResultEx(
    HINTERNET hResolver,
    PVOID pProxySettingsEx) {
    DWORD ret = g_TrueWinHttpGetProxySettingsResultEx(hResolver, pProxySettingsEx);
    if (ret == ERROR_SUCCESS && ShouldIgnoreSystemProxy() && pProxySettingsEx) {
        auto* ps = static_cast<WINHTTP_PROXY_SETTINGS_EX*>(pProxySettingsEx);
        ps->ullFlags = WINHTTP_PROXY_TYPE_DIRECT;
    }
    return ret;
}

} // namespace

bool InstallWinHttpHooks() {
    static bool s_installed = false;
    if (s_installed) return true;
    HMODULE hWinHttp = GetModuleHandleW(L"winhttp.dll");
    if (!hWinHttp) return false;

    g_WinHttpFreeProxySettings = reinterpret_cast<FnWinHttpFreeProxySettings>(
        GetProcAddress(hWinHttp, "WinHttpFreeProxySettings"));

    MH_CreateHookApi(L"winhttp", "WinHttpOpen", &HookedWinHttpOpen, reinterpret_cast<LPVOID*>(&g_TrueWinHttpOpen));
    MH_CreateHookApi(L"winhttp", "WinHttpGetIEProxyConfigForCurrentUser", &HookedWinHttpGetIEProxyConfigForCurrentUser, reinterpret_cast<LPVOID*>(&g_TrueWinHttpGetIEProxyConfigForCurrentUser));
    MH_CreateHookApi(L"winhttp", "WinHttpGetDefaultProxyConfiguration", &HookedWinHttpGetDefaultProxyConfiguration, reinterpret_cast<LPVOID*>(&g_TrueWinHttpGetDefaultProxyConfiguration));
    MH_CreateHookApi(L"winhttp", "WinHttpGetProxyForUrl", &HookedWinHttpGetProxyForUrl, reinterpret_cast<LPVOID*>(&g_TrueWinHttpGetProxyForUrl));
    MH_CreateHookApi(L"winhttp", "WinHttpDetectAutoProxyConfigUrl", &HookedWinHttpDetectAutoProxyConfigUrl, reinterpret_cast<LPVOID*>(&g_TrueWinHttpDetectAutoProxyConfigUrl));
    MH_CreateHookApi(L"winhttp", "WinHttpGetProxyResult", &HookedWinHttpGetProxyResult, reinterpret_cast<LPVOID*>(&g_TrueWinHttpGetProxyResult));
    MH_CreateHookApi(L"winhttp", "WinHttpGetProxyResultEx", &HookedWinHttpGetProxyResultEx, reinterpret_cast<LPVOID*>(&g_TrueWinHttpGetProxyResultEx));
    MH_CreateHookApi(L"winhttp", "WinHttpReadProxySettings", &HookedWinHttpReadProxySettings, reinterpret_cast<LPVOID*>(&g_TrueWinHttpReadProxySettings));
    MH_CreateHookApi(L"winhttp", "WinHttpGetProxySettingsResultEx", &HookedWinHttpGetProxySettingsResultEx, reinterpret_cast<LPVOID*>(&g_TrueWinHttpGetProxySettingsResultEx));

    s_installed = true;
    return true;
}

} // namespace AppProxy::Hook

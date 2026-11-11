#include "HookContext.h"
#include "SharedBridgeClient.h"
#include <MinHook.h>

#include <cstdlib>
#include <string>

namespace AppProxy::Hook {

namespace {

struct NtProcessBasicInfoShort {
    LONG ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
};

using FnNtQueryInformationProcess = LONG(NTAPI*)(HANDLE, UINT, PVOID, ULONG, PULONG);

uint32_t QueryParentPid() {
    auto fn = reinterpret_cast<FnNtQueryInformationProcess>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    if (!fn) return 0;
    NtProcessBasicInfoShort pbi{};
    ULONG len = 0;
    if (fn(GetCurrentProcess(), 0, &pbi, sizeof(pbi), &len) == 0) {
        return static_cast<uint32_t>(pbi.InheritedFromUniqueProcessId);
    }
    return 0;
}

uint32_t ReadEnvUInt32(const wchar_t* name) {
    wchar_t buf[64]{};
    DWORD n = GetEnvironmentVariableW(name, buf, 64);
    if (n == 0 || n >= 64) return 0;
    return static_cast<uint32_t>(std::wcstoul(buf, nullptr, 10));
}

void InitializeRuntimeConfig(HMODULE hSelfModule) {
    g_config.bridgePid = ReadEnvUInt32(L"APPPROXY_BRIDGE_PID");
    g_config.sessionId = ReadEnvUInt32(L"APPPROXY_SESSION_ID");
    g_config.flags = ReadEnvUInt32(L"APPPROXY_FLAGS");
    g_config.currentPid = GetCurrentProcessId();
    g_config.parentPid = QueryParentPid();

    wchar_t dirBuf[MAX_PATH]{};
    DWORD envLen = GetEnvironmentVariableW(L"APPPROXY_SELF_DIR", dirBuf, MAX_PATH);
    if (envLen > 0 && envLen < MAX_PATH) {
        g_config.selfDir = dirBuf;
    } else if (hSelfModule) {
        wchar_t modPath[MAX_PATH]{};
        if (GetModuleFileNameW(hSelfModule, modPath, MAX_PATH) > 0) {
            std::wstring full(modPath);
            size_t slash = full.find_last_of(L"\\/");
            if (slash != std::wstring::npos) {
                g_config.selfDir = full.substr(0, slash);
            }
        }
    }

    wchar_t exePath[MAX_PATH]{};
    if (GetModuleFileNameW(nullptr, exePath, MAX_PATH) > 0) {
        std::wstring full(exePath);
        size_t slash = full.find_last_of(L"\\/");
        std::wstring base = (slash != std::wstring::npos) ? full.substr(slash + 1) : full;
        g_config.processName = WideToUtf8(base.c_str());
    } else {
        g_config.processName = "unknown.exe";
    }
}

} // namespace

} // namespace AppProxy::Hook

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ulReasonForCall, LPVOID lpReserved) {
    using namespace AppProxy::Hook;

    if (ulReasonForCall == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hModule);
        InitializeRuntimeConfig(hModule);

        if (ShouldIgnoreSystemProxy()) {
            SanitizeProcessProxyEnv();
        }

        if (MH_Initialize() == MH_OK) {
            InstallProcessHooks();
            if (ShouldIgnoreSystemProxy()) {
                InstallRegistryHooks();
            }
            TryInstallLateHooks(false);
            MH_EnableHook(MH_ALL_HOOKS);

            if (g_config.bridgePid != 0) {
                std::string detail = "Hook DLL attached (" + std::string(CurrentArchString());
                if (ShouldIgnoreSystemProxy()) {
                    detail += ", system-proxy-isolated";
                }
                detail += ")";
                SharedBridgeClient::EmitLogEvent("Injected", detail);
            }
        }
    } else if (ulReasonForCall == DLL_PROCESS_DETACH) {
        bool terminating = (lpReserved != nullptr);
        SharedBridgeClient::Shutdown(terminating);
        if (!terminating) {
            CleanupProcessHooks();
            MH_DisableHook(MH_ALL_HOOKS);
            MH_Uninitialize();
        }
    }
    return TRUE;
}

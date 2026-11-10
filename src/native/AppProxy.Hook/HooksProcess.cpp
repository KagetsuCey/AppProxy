#include "HookContext.h"
#include "SharedBridgeClient.h"
#include <MinHook.h>

#include <atomic>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace AppProxy::Hook {

namespace {

using FnCreateProcessW = BOOL(WINAPI*)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
using FnCreateProcessA = BOOL(WINAPI*)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
using FnCreateProcessAsUserW = BOOL(WINAPI*)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
using FnResumeThread = DWORD(WINAPI*)(HANDLE);
using FnLoadLibraryW = HMODULE(WINAPI*)(LPCWSTR);
using FnLoadLibraryExW = HMODULE(WINAPI*)(LPCWSTR, HANDLE, DWORD);
using FnLoadLibraryA = HMODULE(WINAPI*)(LPCSTR);
using FnLoadLibraryExA = HMODULE(WINAPI*)(LPCSTR, HANDLE, DWORD);

FnCreateProcessW g_TrueCreateProcessW = nullptr;
FnCreateProcessA g_TrueCreateProcessA = nullptr;
FnCreateProcessAsUserW g_TrueCreateProcessAsUserW = nullptr;
FnResumeThread g_TrueResumeThread = nullptr;
FnLoadLibraryW g_TrueLoadLibraryW = nullptr;
FnLoadLibraryExW g_TrueLoadLibraryExW = nullptr;
FnLoadLibraryA g_TrueLoadLibraryA = nullptr;
FnLoadLibraryExA g_TrueLoadLibraryExA = nullptr;

std::mutex g_lateHookMutex;
std::atomic<bool> g_netHooksReady{false};
std::atomic<bool> g_dnsHooksReady{false};
std::atomic<bool> g_advapiHooksReady{false};

struct PendingChildInfo {
    DWORD pid = 0;
    DWORD tid = 0;
};

std::mutex g_pendingChildrenMutex;
std::unordered_map<HANDLE, PendingChildInfo> g_pendingChildren;

struct NtProcessBasicInfo {
    LONG ExitStatus;
    PVOID PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
};

struct RawProcThreadAttributeEntry {
    DWORD_PTR Attribute;
    SIZE_T cbSize;
    PVOID lpValue;
};

struct RawProcThreadAttributeList {
    DWORD dwFlags;
    ULONG Size;
    ULONG Count;
    ULONG Reserved;
    PULONG_PTR Unknown;
    RawProcThreadAttributeEntry Entries[1];
};

bool IsMemoryWritable(const void* ptr, size_t bytes) {
    if (!ptr || bytes == 0) return false;
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    DWORD prot = mbi.Protect & 0xFF;
    return prot == PAGE_READWRITE ||
           prot == PAGE_WRITECOPY ||
           prot == PAGE_EXECUTE_READWRITE ||
           prot == PAGE_EXECUTE_WRITECOPY;
}

class ScopedStripChildMitigationPolicy {
public:
    ScopedStripChildMitigationPolicy(DWORD creationFlags, const void* startupInfo) {
        if ((creationFlags & EXTENDED_STARTUPINFO_PRESENT) == 0 || !startupInfo) {
            return;
        }
        const auto* siEx = static_cast<const STARTUPINFOEXW*>(startupInfo);
        if (siEx->StartupInfo.cb < sizeof(STARTUPINFOEXW) || !siEx->lpAttributeList) {
            return;
        }

        const auto* attrList = reinterpret_cast<const RawProcThreadAttributeList*>(siEx->lpAttributeList);
        if (attrList->Count == 0 || attrList->Count > attrList->Size || attrList->Count > 64) {
            return;
        }

        for (ULONG i = 0; i < attrList->Count; ++i) {
            const auto& entry = attrList->Entries[i];
            if (entry.Attribute != PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY || !entry.lpValue) {
                continue;
            }
            if (entry.cbSize >= sizeof(DWORD64) && IsMemoryWritable(entry.lpValue, sizeof(DWORD64))) {
                auto* p0 = static_cast<DWORD64*>(entry.lpValue);
                m_ptr0 = p0;
                m_orig0 = *p0;
                constexpr DWORD64 kStripMask0 =
                    PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_MASK |
                    PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_MASK |
                    PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_MASK;
                *p0 &= ~kStripMask0;
            }
            if (entry.cbSize >= 2 * sizeof(DWORD64) && IsMemoryWritable(entry.lpValue, 2 * sizeof(DWORD64))) {
                auto* p1 = static_cast<DWORD64*>(entry.lpValue) + 1;
                m_ptr1 = p1;
                m_orig1 = *p1;
                constexpr DWORD64 kStripMask1 =
                    PROCESS_CREATION_MITIGATION_POLICY2_LOADER_INTEGRITY_CONTINUITY_MASK |
                    PROCESS_CREATION_MITIGATION_POLICY2_MODULE_TAMPERING_PROTECTION_MASK;
                *p1 &= ~kStripMask1;
            }
            break;
        }
    }

    ~ScopedStripChildMitigationPolicy() {
        if (m_ptr0) *m_ptr0 = m_orig0;
        if (m_ptr1) *m_ptr1 = m_orig1;
    }

    ScopedStripChildMitigationPolicy(const ScopedStripChildMitigationPolicy&) = delete;
    ScopedStripChildMitigationPolicy& operator=(const ScopedStripChildMitigationPolicy&) = delete;

private:
    DWORD64* m_ptr0 = nullptr;
    DWORD64* m_ptr1 = nullptr;
    DWORD64 m_orig0 = 0;
    DWORD64 m_orig1 = 0;
};

using FnNtQueryInformationProcess = LONG(NTAPI*)(HANDLE, UINT, PVOID, ULONG, PULONG);
using FnIsWow64Process2 = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);

bool IsChildProcess64Bit(HANDLE hProcess) {
    static auto fnIsWow64Process2 = reinterpret_cast<FnIsWow64Process2>(
        GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "IsWow64Process2"));

    if (fnIsWow64Process2) {
        USHORT processMachine = 0;
        USHORT nativeMachine = 0;
        if (fnIsWow64Process2(hProcess, &processMachine, &nativeMachine)) {
            if (nativeMachine == IMAGE_FILE_MACHINE_I386) {
                return false;
            }
            return processMachine == IMAGE_FILE_MACHINE_UNKNOWN;
        }
    }

    BOOL isWow64 = FALSE;
    if (IsWow64Process(hProcess, &isWow64)) {
#if defined(_WIN64)
        return !isWow64;
#else
        if (isWow64) return false;
        SYSTEM_INFO si{};
        GetNativeSystemInfo(&si);
        return si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
               si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64;
#endif
    }

#if defined(_WIN64)
    return true;
#else
    return false;
#endif
}

bool InjectSameBitnessAtOep(HANDLE hProcess, HANDLE hThread, const std::wstring& dllPath, std::string& outDetail) {
    auto fmtErr = [](const char* step, DWORD err) {
        char buf[96]{};
        std::snprintf(buf, sizeof(buf), "%s (err=%lu)", step, err);
        return std::string(buf);
    };

    if (!hProcess || !hThread) {
        outDetail = "Invalid child process/thread handle";
        return false;
    }

    if (WaitForSingleObject(hProcess, 0) == WAIT_OBJECT_0) {
        outDetail = "Child exited before injection";
        return false;
    }

    auto pLoadLibraryW = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    if (!pLoadLibraryW) {
        outDetail = "LoadLibraryW missing";
        return false;
    }

    // Queue LoadLibraryW as a user-mode APC on the suspended child main thread.
    // Avoids RWX VirtualProtectEx on .text (ACG-safe) and CreateRemoteThread
    // entry validation (CFG export-suppression safe).
    size_t dllBytes = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID remoteBuf = VirtualAllocEx(hProcess, nullptr, dllBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteBuf) {
        outDetail = fmtErr("VirtualAllocEx failed", GetLastError());
        return false;
    }

    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, remoteBuf, dllPath.c_str(), dllBytes, &bytesWritten) || bytesWritten != dllBytes) {
        DWORD err = GetLastError();
        VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
        outDetail = fmtErr("WriteProcessMemory(DLL) failed", err);
        return false;
    }

    if (QueueUserAPC(
            reinterpret_cast<PAPCFUNC>(pLoadLibraryW),
            hThread,
            reinterpret_cast<ULONG_PTR>(remoteBuf)) == 0) {
        DWORD err = GetLastError();
        VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
        outDetail = fmtErr("QueueUserAPC(LoadLibraryW) failed", err);
        return false;
    }

    return true;
}

bool InjectCrossBitnessViaHelper(DWORD pid, DWORD tid, bool childIs64) {
    if (g_config.selfDir.empty()) return false;
    const wchar_t* archTag = childIs64 ? L"x64" : L"x86";
    std::wstring helperExe = g_config.selfDir + L"\\AppProxy.Injector." + archTag + L".exe";
    std::wstring targetDll = g_config.selfDir + L"\\AppProxy.Hook." + archTag + L".dll";

    wchar_t cmdLine[1024]{};
    swprintf_s(
        cmdLine,
        L"\"%s\" --attach-suspended --pid %lu --tid %lu --dll \"%s\" --no-resume",
        helperExe.c_str(),
        pid,
        tid,
        targetDll.c_str());

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!g_TrueCreateProcessW(
            helperExe.c_str(),
            cmdLine,
            nullptr,
            nullptr,
            FALSE,
            CREATE_NO_WINDOW,
            nullptr,
            g_config.selfDir.c_str(),
            &si,
            &pi)) {
        return false;
    }

    WaitForSingleObject(pi.hProcess, 6000);
    DWORD exitCode = 1;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return exitCode == 0;
}

bool InjectChildProcess(HANDLE hProcess, HANDLE hThread, DWORD pid, DWORD tid) {
    if (g_config.selfDir.empty()) return false;
    bool childIs64 = IsChildProcess64Bit(hProcess);
#if defined(_WIN64)
    constexpr bool selfIs64 = true;
#else
    constexpr bool selfIs64 = false;
#endif

    bool ok = false;
    std::string failDetail;
    if (childIs64 == selfIs64) {
        const wchar_t* archTag = childIs64 ? L"x64" : L"x86";
        std::wstring dllPath = g_config.selfDir + L"\\AppProxy.Hook." + archTag + L".dll";
        ok = InjectSameBitnessAtOep(hProcess, hThread, dllPath, failDetail);
    } else {
        ok = InjectCrossBitnessViaHelper(pid, tid, childIs64);
        if (!ok) failDetail = "Cross-bitness helper failed";
    }

    char msg[256]{};
    if (ok) {
        std::snprintf(
            msg,
            sizeof(msg),
            "Child PID %lu (%s) injection succeeded",
            pid,
            childIs64 ? "x64" : "x86");
    } else {
        std::snprintf(
            msg,
            sizeof(msg),
            "Child PID %lu (%s) injection failed: %s",
            pid,
            childIs64 ? "x64" : "x86",
            failDetail.c_str());
    }
    SharedBridgeClient::EmitLogEvent("ChildSpawned", msg);
    return ok;
}

std::vector<wchar_t> CloneEnvironmentWithAppProxy(LPVOID lpEnvironment, bool isUnicode) {
    std::vector<wchar_t> result;
    if (!lpEnvironment) return result;

    auto startsWithKey = [](const std::wstring& kv) {
        return _wcsnicmp(kv.c_str(), L"APPPROXY_BRIDGE_PID=", 20) == 0 ||
               _wcsnicmp(kv.c_str(), L"APPPROXY_SESSION_ID=", 20) == 0 ||
               _wcsnicmp(kv.c_str(), L"APPPROXY_FLAGS=", 15) == 0 ||
               _wcsnicmp(kv.c_str(), L"APPPROXY_SELF_DIR=", 18) == 0;
    };

    if (isUnicode) {
        const wchar_t* p = static_cast<const wchar_t*>(lpEnvironment);
        while (*p != L'\0') {
            std::wstring entry(p);
            if (!startsWithKey(entry)) {
                result.insert(result.end(), entry.begin(), entry.end());
                result.push_back(L'\0');
            }
            p += entry.size() + 1;
        }
    } else {
        const char* p = static_cast<const char*>(lpEnvironment);
        while (*p != '\0') {
            std::string entryA(p);
            std::wstring entryW = Utf8ToWide(entryA.c_str());
            if (!startsWithKey(entryW)) {
                result.insert(result.end(), entryW.begin(), entryW.end());
                result.push_back(L'\0');
            }
            p += entryA.size() + 1;
        }
    }

    wchar_t buf[128]{};
    swprintf_s(buf, L"APPPROXY_BRIDGE_PID=%u", g_config.bridgePid);
    result.insert(result.end(), buf, buf + std::wcslen(buf) + 1);

    swprintf_s(buf, L"APPPROXY_SESSION_ID=%u", g_config.sessionId);
    result.insert(result.end(), buf, buf + std::wcslen(buf) + 1);

    swprintf_s(buf, L"APPPROXY_FLAGS=%u", SharedBridgeClient::GetEffectiveFlags());
    result.insert(result.end(), buf, buf + std::wcslen(buf) + 1);

    if (!g_config.selfDir.empty()) {
        std::wstring dirEntry = L"APPPROXY_SELF_DIR=" + g_config.selfDir;
        result.insert(result.end(), dirEntry.begin(), dirEntry.end());
        result.push_back(L'\0');
    }

    result.push_back(L'\0');
    return result;
}

BOOL WINAPI HookedCreateProcessW(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation) {
    uint32_t flags = SharedBridgeClient::GetEffectiveFlags();
    if ((flags & IPC::FLAG_INJECT_CHILDREN) == 0 || !lpProcessInformation) {
        return g_TrueCreateProcessW(
            lpApplicationName,
            lpCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            dwCreationFlags,
            lpEnvironment,
            lpCurrentDirectory,
            lpStartupInfo,
            lpProcessInformation);
    }

    bool callerSuspended = (dwCreationFlags & CREATE_SUSPENDED) != 0;
    DWORD patchedFlags = (dwCreationFlags | CREATE_SUSPENDED) & ~CREATE_BREAKAWAY_FROM_JOB;

    std::vector<wchar_t> clonedEnv;
    LPVOID effectiveEnv = lpEnvironment;
    if (lpEnvironment) {
        clonedEnv = CloneEnvironmentWithAppProxy(lpEnvironment, (dwCreationFlags & CREATE_UNICODE_ENVIRONMENT) != 0);
        effectiveEnv = clonedEnv.data();
        patchedFlags |= CREATE_UNICODE_ENVIRONMENT;
    }

    BOOL ok = FALSE;
    {
        ScopedStripChildMitigationPolicy stripMitigation(patchedFlags, lpStartupInfo);
        ok = g_TrueCreateProcessW(
            lpApplicationName,
            lpCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            patchedFlags,
            effectiveEnv,
            lpCurrentDirectory,
            lpStartupInfo,
            lpProcessInformation);
    }

    if (ok) {
        if (callerSuspended) {
            std::lock_guard<std::mutex> lock(g_pendingChildrenMutex);
            g_pendingChildren[lpProcessInformation->hThread] = PendingChildInfo{
                lpProcessInformation->dwProcessId,
                lpProcessInformation->dwThreadId};
        } else {
            InjectChildProcess(
                lpProcessInformation->hProcess,
                lpProcessInformation->hThread,
                lpProcessInformation->dwProcessId,
                lpProcessInformation->dwThreadId);
            g_TrueResumeThread(lpProcessInformation->hThread);
        }
    }
    return ok;
}

BOOL WINAPI HookedCreateProcessA(
    LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation) {
    uint32_t flags = SharedBridgeClient::GetEffectiveFlags();
    if ((flags & IPC::FLAG_INJECT_CHILDREN) == 0 || !lpProcessInformation) {
        return g_TrueCreateProcessA(
            lpApplicationName,
            lpCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            dwCreationFlags,
            lpEnvironment,
            lpCurrentDirectory,
            lpStartupInfo,
            lpProcessInformation);
    }

    bool callerSuspended = (dwCreationFlags & CREATE_SUSPENDED) != 0;
    DWORD patchedFlags = (dwCreationFlags | CREATE_SUSPENDED) & ~CREATE_BREAKAWAY_FROM_JOB;

    std::vector<wchar_t> clonedEnv;
    LPVOID effectiveEnv = lpEnvironment;
    if (lpEnvironment) {
        clonedEnv = CloneEnvironmentWithAppProxy(lpEnvironment, (dwCreationFlags & CREATE_UNICODE_ENVIRONMENT) != 0);
        effectiveEnv = clonedEnv.data();
        patchedFlags |= CREATE_UNICODE_ENVIRONMENT;
    }

    BOOL ok = FALSE;
    {
        ScopedStripChildMitigationPolicy stripMitigation(patchedFlags, lpStartupInfo);
        ok = g_TrueCreateProcessA(
            lpApplicationName,
            lpCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            patchedFlags,
            effectiveEnv,
            lpCurrentDirectory,
            lpStartupInfo,
            lpProcessInformation);
    }

    if (ok) {
        if (callerSuspended) {
            std::lock_guard<std::mutex> lock(g_pendingChildrenMutex);
            g_pendingChildren[lpProcessInformation->hThread] = PendingChildInfo{
                lpProcessInformation->dwProcessId,
                lpProcessInformation->dwThreadId};
        } else {
            InjectChildProcess(
                lpProcessInformation->hProcess,
                lpProcessInformation->hThread,
                lpProcessInformation->dwProcessId,
                lpProcessInformation->dwThreadId);
            g_TrueResumeThread(lpProcessInformation->hThread);
        }
    }
    return ok;
}

BOOL WINAPI HookedCreateProcessAsUserW(
    HANDLE hToken,
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation) {
    uint32_t flags = SharedBridgeClient::GetEffectiveFlags();
    if ((flags & IPC::FLAG_INJECT_CHILDREN) == 0 || !lpProcessInformation) {
        return g_TrueCreateProcessAsUserW(
            hToken,
            lpApplicationName,
            lpCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            dwCreationFlags,
            lpEnvironment,
            lpCurrentDirectory,
            lpStartupInfo,
            lpProcessInformation);
    }

    bool callerSuspended = (dwCreationFlags & CREATE_SUSPENDED) != 0;
    DWORD patchedFlags = (dwCreationFlags | CREATE_SUSPENDED) & ~CREATE_BREAKAWAY_FROM_JOB;

    std::vector<wchar_t> clonedEnv;
    LPVOID effectiveEnv = lpEnvironment;
    if (lpEnvironment) {
        clonedEnv = CloneEnvironmentWithAppProxy(lpEnvironment, (dwCreationFlags & CREATE_UNICODE_ENVIRONMENT) != 0);
        effectiveEnv = clonedEnv.data();
        patchedFlags |= CREATE_UNICODE_ENVIRONMENT;
    }

    BOOL ok = FALSE;
    {
        ScopedStripChildMitigationPolicy stripMitigation(patchedFlags, lpStartupInfo);
        ok = g_TrueCreateProcessAsUserW(
            hToken,
            lpApplicationName,
            lpCommandLine,
            lpProcessAttributes,
            lpThreadAttributes,
            bInheritHandles,
            patchedFlags,
            effectiveEnv,
            lpCurrentDirectory,
            lpStartupInfo,
            lpProcessInformation);
    }

    if (ok) {
        if (callerSuspended) {
            std::lock_guard<std::mutex> lock(g_pendingChildrenMutex);
            g_pendingChildren[lpProcessInformation->hThread] = PendingChildInfo{
                lpProcessInformation->dwProcessId,
                lpProcessInformation->dwThreadId};
        } else {
            InjectChildProcess(
                lpProcessInformation->hProcess,
                lpProcessInformation->hThread,
                lpProcessInformation->dwProcessId,
                lpProcessInformation->dwThreadId);
            g_TrueResumeThread(lpProcessInformation->hThread);
        }
    }
    return ok;
}

DWORD WINAPI HookedResumeThread(HANDLE hThread) {
    PendingChildInfo child{};
    bool found = false;
    {
        std::lock_guard<std::mutex> lock(g_pendingChildrenMutex);
        auto it = g_pendingChildren.find(hThread);
        if (it != g_pendingChildren.end()) {
            child = it->second;
            g_pendingChildren.erase(it);
            found = true;
        }
    }

    if (found && child.pid != 0) {
        HANDLE hProc = OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
                PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | SYNCHRONIZE,
            FALSE,
            child.pid);
        if (hProc) {
            InjectChildProcess(hProc, hThread, child.pid, child.tid);
            CloseHandle(hProc);
        }
    }

    return g_TrueResumeThread(hThread);
}

HMODULE WINAPI HookedLoadLibraryW(LPCWSTR lpLibFileName) {
    HMODULE mod = g_TrueLoadLibraryW(lpLibFileName);
    if (mod) {
        TryInstallLateHooks(true);
    }
    return mod;
}

HMODULE WINAPI HookedLoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
    HMODULE mod = g_TrueLoadLibraryExW(lpLibFileName, hFile, dwFlags);
    constexpr DWORD kDataOnlyFlags =
        LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | LOAD_LIBRARY_AS_IMAGE_RESOURCE;
    if (mod && (dwFlags & kDataOnlyFlags) == 0) {
        TryInstallLateHooks(true);
    }
    return mod;
}

HMODULE WINAPI HookedLoadLibraryA(LPCSTR lpLibFileName) {
    HMODULE mod = g_TrueLoadLibraryA(lpLibFileName);
    if (mod) {
        TryInstallLateHooks(true);
    }
    return mod;
}

HMODULE WINAPI HookedLoadLibraryExA(LPCSTR lpLibFileName, HANDLE hFile, DWORD dwFlags) {
    HMODULE mod = g_TrueLoadLibraryExA(lpLibFileName, hFile, dwFlags);
    constexpr DWORD kDataOnlyFlags =
        LOAD_LIBRARY_AS_DATAFILE | LOAD_LIBRARY_AS_DATAFILE_EXCLUSIVE | LOAD_LIBRARY_AS_IMAGE_RESOURCE;
    if (mod && (dwFlags & kDataOnlyFlags) == 0) {
        TryInstallLateHooks(true);
    }
    return mod;
}

} // namespace

bool InstallProcessHooks() {
    MH_CreateHookApi(L"kernel32", "CreateProcessW", &HookedCreateProcessW, reinterpret_cast<LPVOID*>(&g_TrueCreateProcessW));
    MH_CreateHookApi(L"kernel32", "CreateProcessA", &HookedCreateProcessA, reinterpret_cast<LPVOID*>(&g_TrueCreateProcessA));
    MH_CreateHookApi(L"kernel32", "ResumeThread", &HookedResumeThread, reinterpret_cast<LPVOID*>(&g_TrueResumeThread));
    MH_CreateHookApi(L"kernel32", "LoadLibraryW", &HookedLoadLibraryW, reinterpret_cast<LPVOID*>(&g_TrueLoadLibraryW));
    MH_CreateHookApi(L"kernel32", "LoadLibraryExW", &HookedLoadLibraryExW, reinterpret_cast<LPVOID*>(&g_TrueLoadLibraryExW));
    MH_CreateHookApi(L"kernel32", "LoadLibraryA", &HookedLoadLibraryA, reinterpret_cast<LPVOID*>(&g_TrueLoadLibraryA));
    MH_CreateHookApi(L"kernel32", "LoadLibraryExA", &HookedLoadLibraryExA, reinterpret_cast<LPVOID*>(&g_TrueLoadLibraryExA));

    HMODULE hKernelBase = GetModuleHandleW(L"kernelbase.dll");
    if (hKernelBase && GetProcAddress(hKernelBase, "CreateProcessAsUserW") != nullptr) {
        if (MH_CreateHookApi(
                L"kernelbase",
                "CreateProcessAsUserW",
                &HookedCreateProcessAsUserW,
                reinterpret_cast<LPVOID*>(&g_TrueCreateProcessAsUserW)) == MH_OK) {
            g_advapiHooksReady.store(true, std::memory_order_release);
        }
    }
    return true;
}

void TryInstallLateHooks(bool enableImmediately) {
    if (g_shuttingDown.load(std::memory_order_acquire)) {
        return;
    }

    bool needWs2 = !g_netHooksReady.load(std::memory_order_acquire) ||
                   !g_dnsHooksReady.load(std::memory_order_acquire);
    bool needAdvapi = !g_advapiHooksReady.load(std::memory_order_acquire);
    if (!needWs2 && !needAdvapi) {
        return;
    }

    bool ws2Loaded = needWs2 && (GetModuleHandleW(L"ws2_32.dll") != nullptr);
    bool advapiLoaded = needAdvapi && (GetModuleHandleW(L"advapi32.dll") != nullptr);
    if (!ws2Loaded && !advapiLoaded) {
        return;
    }

    std::lock_guard<std::mutex> lock(g_lateHookMutex);
    if (g_shuttingDown.load(std::memory_order_acquire)) {
        return;
    }

    bool needEnable = false;

    if (!g_netHooksReady.load(std::memory_order_relaxed) && GetModuleHandleW(L"ws2_32.dll")) {
        if (InstallNetworkHooks()) {
            needEnable = true;
        }
        g_netHooksReady.store(true, std::memory_order_release);
    }

    if (!g_dnsHooksReady.load(std::memory_order_relaxed) && GetModuleHandleW(L"ws2_32.dll")) {
        if (InstallDnsHooks()) {
            needEnable = true;
        }
        g_dnsHooksReady.store(true, std::memory_order_release);
    }

    if (!g_advapiHooksReady.load(std::memory_order_relaxed) && GetModuleHandleW(L"advapi32.dll")) {
        MH_STATUS st = MH_CreateHookApi(
            L"advapi32",
            "CreateProcessAsUserW",
            &HookedCreateProcessAsUserW,
            reinterpret_cast<LPVOID*>(&g_TrueCreateProcessAsUserW));
        if (st == MH_OK) {
            needEnable = true;
        }
        g_advapiHooksReady.store(true, std::memory_order_release);
    }

    if (enableImmediately && needEnable) {
        MH_EnableHook(MH_ALL_HOOKS);
    }
}

void CleanupProcessHooks() {
    std::lock_guard<std::mutex> lock(g_pendingChildrenMutex);
    g_pendingChildren.clear();
}

} // namespace AppProxy::Hook

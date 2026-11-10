#include "HookContext.h"
#include "SharedBridgeClient.h"
#include <MinHook.h>

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

FnCreateProcessW g_TrueCreateProcessW = nullptr;
FnCreateProcessA g_TrueCreateProcessA = nullptr;
FnCreateProcessAsUserW g_TrueCreateProcessAsUserW = nullptr;
FnResumeThread g_TrueResumeThread = nullptr;

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

bool InjectSameBitnessAtOep(HANDLE hProcess, HANDLE hThread, const std::wstring& dllPath) {
    static auto fnNtQueryInfo = reinterpret_cast<FnNtQueryInformationProcess>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    if (!fnNtQueryInfo) return false;

    NtProcessBasicInfo pbi{};
    ULONG retLen = 0;
    if (fnNtQueryInfo(hProcess, 0 /*ProcessBasicInformation*/, &pbi, sizeof(pbi), &retLen) != 0 ||
        !pbi.PebBaseAddress) {
        return false;
    }

    uintptr_t imageBase = 0;
#if defined(_WIN64)
    constexpr size_t kImageBaseOffset = 0x10;
#else
    constexpr size_t kImageBaseOffset = 0x08;
#endif
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(
            hProcess,
            reinterpret_cast<LPCVOID>(reinterpret_cast<uintptr_t>(pbi.PebBaseAddress) + kImageBaseOffset),
            &imageBase,
            sizeof(imageBase),
            &bytesRead) ||
        imageBase == 0) {
        return false;
    }

    IMAGE_DOS_HEADER dosHdr{};
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(imageBase), &dosHdr, sizeof(dosHdr), &bytesRead) ||
        dosHdr.e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    IMAGE_NT_HEADERS ntHdr{};
    if (!ReadProcessMemory(
            hProcess,
            reinterpret_cast<LPCVOID>(imageBase + static_cast<uintptr_t>(dosHdr.e_lfanew)),
            &ntHdr,
            sizeof(ntHdr),
            &bytesRead) ||
        ntHdr.Signature != IMAGE_NT_SIGNATURE ||
        ntHdr.OptionalHeader.AddressOfEntryPoint == 0) {
        return false;
    }

    uintptr_t oepAddr = imageBase + ntHdr.OptionalHeader.AddressOfEntryPoint;
    uint8_t origBytes[2]{};
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(oepAddr), origBytes, 2, &bytesRead)) {
        return false;
    }

    DWORD oldProt = 0;
    if (!VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(oepAddr), 2, PAGE_EXECUTE_READWRITE, &oldProt)) {
        return false;
    }

    const uint8_t jmpSelf[2] = {0xEB, 0xFE};
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(oepAddr), jmpSelf, 2, &bytesWritten)) {
        VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(oepAddr), 2, oldProt, &oldProt);
        return false;
    }
    FlushInstructionCache(hProcess, reinterpret_cast<LPCVOID>(oepAddr), 2);

    // Let Windows loader complete LdrpInitializeProcess until main thread hits OEP
    g_TrueResumeThread(hThread);

    bool reachedOep = false;
    for (int i = 0; i < 5000; ++i) {
        if (WaitForSingleObject(hProcess, 0) == WAIT_OBJECT_0) {
            break;
        }
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_CONTROL;
        if (GetThreadContext(hThread, &ctx)) {
#if defined(_WIN64)
            uintptr_t ip = static_cast<uintptr_t>(ctx.Rip);
#else
            uintptr_t ip = static_cast<uintptr_t>(ctx.Eip);
#endif
            if (ip == oepAddr) {
                reachedOep = true;
                break;
            }
        }
        Sleep(1);
    }

    SuspendThread(hThread);
    CONTEXT syncCtx{};
    syncCtx.ContextFlags = CONTEXT_CONTROL;
    GetThreadContext(hThread, &syncCtx);

    // Restore original OEP bytes unconditionally
    WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(oepAddr), origBytes, 2, &bytesWritten);
    DWORD dummyProt = 0;
    VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(oepAddr), 2, oldProt, &dummyProt);
    FlushInstructionCache(hProcess, reinterpret_cast<LPCVOID>(oepAddr), 2);

    if (!reachedOep) {
        return false;
    }

    size_t dllBytes = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID remoteBuf = VirtualAllocEx(hProcess, nullptr, dllBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteBuf) {
        return false;
    }

    bool injected = false;
    if (WriteProcessMemory(hProcess, remoteBuf, dllPath.c_str(), dllBytes, &bytesWritten)) {
        auto pLoadLibraryW = reinterpret_cast<LPTHREAD_START_ROUTINE>(
            GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));
        if (pLoadLibraryW) {
            HANDLE hRemote = CreateRemoteThread(hProcess, nullptr, 0, pLoadLibraryW, remoteBuf, 0, nullptr);
            if (hRemote) {
                WaitForSingleObject(hRemote, 5000);
                DWORD exitCode = 0;
                GetExitCodeThread(hRemote, &exitCode);
                CloseHandle(hRemote);
                injected = (exitCode != 0);
            }
        }
    }

    VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
    return injected;
}

bool InjectCrossBitnessViaHelper(DWORD pid, DWORD tid, bool childIs64) {
    if (g_config.selfDir.empty()) return false;
    const wchar_t* archTag = childIs64 ? L"x64" : L"x86";
    std::wstring helperExe = g_config.selfDir + L"\\AppProxy.Injector." + archTag + L".exe";
    std::wstring targetDll = g_config.selfDir + L"\\AppProxy.Hook." + archTag + L".dll";

    wchar_t cmdLine[1024]{};
    swprintf_s(
        cmdLine,
        L"\"%s\" --attach-suspended --pid %u --tid %u --dll \"%s\" --no-resume",
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
    if (childIs64 == selfIs64) {
        const wchar_t* archTag = childIs64 ? L"x64" : L"x86";
        std::wstring dllPath = g_config.selfDir + L"\\AppProxy.Hook." + archTag + L".dll";
        ok = InjectSameBitnessAtOep(hProcess, hThread, dllPath);
    } else {
        ok = InjectCrossBitnessViaHelper(pid, tid, childIs64);
    }

    char msg[128]{};
    std::snprintf(
        msg,
        sizeof(msg),
        "Child PID %u (%s) injection %s",
        pid,
        childIs64 ? "x64" : "x86",
        ok ? "succeeded" : "failed");
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
    DWORD patchedFlags = dwCreationFlags | CREATE_SUSPENDED;

    std::vector<wchar_t> clonedEnv;
    LPVOID effectiveEnv = lpEnvironment;
    if (lpEnvironment) {
        clonedEnv = CloneEnvironmentWithAppProxy(lpEnvironment, (dwCreationFlags & CREATE_UNICODE_ENVIRONMENT) != 0);
        effectiveEnv = clonedEnv.data();
        patchedFlags |= CREATE_UNICODE_ENVIRONMENT;
    }

    BOOL ok = g_TrueCreateProcessW(
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
    DWORD patchedFlags = dwCreationFlags | CREATE_SUSPENDED;

    std::vector<wchar_t> clonedEnv;
    LPVOID effectiveEnv = lpEnvironment;
    if (lpEnvironment) {
        clonedEnv = CloneEnvironmentWithAppProxy(lpEnvironment, (dwCreationFlags & CREATE_UNICODE_ENVIRONMENT) != 0);
        effectiveEnv = clonedEnv.data();
        patchedFlags |= CREATE_UNICODE_ENVIRONMENT;
    }

    BOOL ok = g_TrueCreateProcessA(
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
    DWORD patchedFlags = dwCreationFlags | CREATE_SUSPENDED;

    std::vector<wchar_t> clonedEnv;
    LPVOID effectiveEnv = lpEnvironment;
    if (lpEnvironment) {
        clonedEnv = CloneEnvironmentWithAppProxy(lpEnvironment, (dwCreationFlags & CREATE_UNICODE_ENVIRONMENT) != 0);
        effectiveEnv = clonedEnv.data();
        patchedFlags |= CREATE_UNICODE_ENVIRONMENT;
    }

    BOOL ok = g_TrueCreateProcessAsUserW(
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

} // namespace

bool InstallProcessHooks() {
    MH_CreateHookApi(L"kernel32", "CreateProcessW", &HookedCreateProcessW, reinterpret_cast<LPVOID*>(&g_TrueCreateProcessW));
    MH_CreateHookApi(L"kernel32", "CreateProcessA", &HookedCreateProcessA, reinterpret_cast<LPVOID*>(&g_TrueCreateProcessA));
    MH_CreateHookApi(L"kernel32", "ResumeThread", &HookedResumeThread, reinterpret_cast<LPVOID*>(&g_TrueResumeThread));
    if (GetModuleHandleW(L"advapi32.dll")) {
        MH_CreateHookApi(L"advapi32", "CreateProcessAsUserW", &HookedCreateProcessAsUserW, reinterpret_cast<LPVOID*>(&g_TrueCreateProcessAsUserW));
    }
    return true;
}

void CleanupProcessHooks() {
    std::lock_guard<std::mutex> lock(g_pendingChildrenMutex);
    g_pendingChildren.clear();
}

} // namespace AppProxy::Hook

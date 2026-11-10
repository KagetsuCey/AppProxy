#include "OepInjector.h"

#include <cstdint>
#include <cstdio>

namespace AppProxy::Injector {

namespace {

using FnIsWow64Process2 = BOOL(WINAPI*)(HANDLE, USHORT*, USHORT*);

std::string FormatWinError(const char* prefix, DWORD err) {
    char buf[192]{};
    std::snprintf(buf, sizeof(buf), "%s (Win32 error %lu)", prefix, err);
    return buf;
}

} // namespace

bool IsProcess64Bit(HANDLE hProcess) {
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

bool InjectSuspendedProcessAtOep(
    HANDLE hProcess,
    HANDLE hThread,
    const std::wstring& dllPath,
    std::string& outError) {
    if (!hProcess || !hThread) {
        outError = "Invalid suspended process or main thread handle";
        return false;
    }

    if (WaitForSingleObject(hProcess, 0) == WAIT_OBJECT_0) {
        outError = "Target process exited before DLL injection";
        return false;
    }

    auto pLoadLibraryW = GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    if (!pLoadLibraryW) {
        outError = "LoadLibraryW not found in kernel32.dll";
        return false;
    }

    // Allocate a RW data page (ACG-safe: never modifies .text to RWX) and queue
    // LoadLibraryW as a user-mode APC on the suspended main thread. When the
    // thread is resumed, ntdll!LdrInitializeThunk drains user APCs via NtTestAlert()
    // after loader initialization and before entering OEP (CFG-safe).
    size_t dllBytes = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID remoteBuf = VirtualAllocEx(hProcess, nullptr, dllBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteBuf) {
        outError = FormatWinError("VirtualAllocEx failed", GetLastError());
        return false;
    }

    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, remoteBuf, dllPath.c_str(), dllBytes, &bytesWritten) || bytesWritten != dllBytes) {
        DWORD err = GetLastError();
        VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
        outError = FormatWinError("WriteProcessMemory(DLL path) failed", err);
        return false;
    }

    if (QueueUserAPC(
            reinterpret_cast<PAPCFUNC>(pLoadLibraryW),
            hThread,
            reinterpret_cast<ULONG_PTR>(remoteBuf)) == 0) {
        DWORD err = GetLastError();
        VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
        outError = FormatWinError("QueueUserAPC(LoadLibraryW) failed", err);
        return false;
    }

    // Keep remoteBuf allocated because hThread is still suspended and will read
    // the DLL path string when ResumeThread triggers NtTestAlert().
    return true;
}

} // namespace AppProxy::Injector

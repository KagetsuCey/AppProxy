#include "OepInjector.h"

#include <cstdint>
#include <cstdio>

namespace AppProxy::Injector {

namespace {

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
    auto fnNtQueryInfo = reinterpret_cast<FnNtQueryInformationProcess>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    if (!fnNtQueryInfo) {
        outError = "Failed to resolve NtQueryInformationProcess";
        return false;
    }

    NtProcessBasicInfo pbi{};
    ULONG retLen = 0;
    LONG status = fnNtQueryInfo(hProcess, 0, &pbi, sizeof(pbi), &retLen);
    if (status != 0 || !pbi.PebBaseAddress) {
        outError = "NtQueryInformationProcess failed";
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
        outError = FormatWinError("ReadProcessMemory(ImageBaseAddress) failed", GetLastError());
        return false;
    }

    IMAGE_DOS_HEADER dosHdr{};
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(imageBase), &dosHdr, sizeof(dosHdr), &bytesRead) ||
        dosHdr.e_magic != IMAGE_DOS_SIGNATURE) {
        outError = "Invalid remote DOS header";
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
        outError = "Invalid remote NT header or zero entry point";
        return false;
    }

    uintptr_t oepAddr = imageBase + ntHdr.OptionalHeader.AddressOfEntryPoint;
    uint8_t origBytes[2]{};
    if (!ReadProcessMemory(hProcess, reinterpret_cast<LPCVOID>(oepAddr), origBytes, 2, &bytesRead)) {
        outError = FormatWinError("ReadProcessMemory(OEP) failed", GetLastError());
        return false;
    }

    DWORD oldProt = 0;
    if (!VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(oepAddr), 2, PAGE_EXECUTE_READWRITE, &oldProt)) {
        outError = FormatWinError("VirtualProtectEx(OEP) failed", GetLastError());
        return false;
    }

    const uint8_t jmpSelf[2] = {0xEB, 0xFE};
    SIZE_T bytesWritten = 0;
    if (!WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(oepAddr), jmpSelf, 2, &bytesWritten)) {
        DWORD err = GetLastError();
        VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(oepAddr), 2, oldProt, &oldProt);
        outError = FormatWinError("WriteProcessMemory(EB FE) failed", err);
        return false;
    }
    FlushInstructionCache(hProcess, reinterpret_cast<LPCVOID>(oepAddr), 2);

    // Let Windows complete LdrpInitializeProcess up to OEP
    ResumeThread(hThread);

    bool reachedOep = false;
    for (int i = 0; i < 5000; ++i) {
        if (WaitForSingleObject(hProcess, 0) == WAIT_OBJECT_0) {
            outError = "Target process exited before reaching entry point";
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

    WriteProcessMemory(hProcess, reinterpret_cast<LPVOID>(oepAddr), origBytes, 2, &bytesWritten);
    DWORD dummyProt = 0;
    VirtualProtectEx(hProcess, reinterpret_cast<LPVOID>(oepAddr), 2, oldProt, &dummyProt);
    FlushInstructionCache(hProcess, reinterpret_cast<LPCVOID>(oepAddr), 2);

    if (!reachedOep) {
        if (outError.empty()) {
            outError = "Timed out waiting for target process entry point";
        }
        return false;
    }

    size_t dllBytes = (dllPath.size() + 1) * sizeof(wchar_t);
    LPVOID remoteBuf = VirtualAllocEx(hProcess, nullptr, dllBytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteBuf) {
        outError = FormatWinError("VirtualAllocEx failed", GetLastError());
        return false;
    }

    bool ok = false;
    if (!WriteProcessMemory(hProcess, remoteBuf, dllPath.c_str(), dllBytes, &bytesWritten)) {
        outError = FormatWinError("WriteProcessMemory(DLL path) failed", GetLastError());
    } else {
        auto pLoadLibraryW = reinterpret_cast<LPTHREAD_START_ROUTINE>(
            GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW"));
        if (!pLoadLibraryW) {
            outError = "LoadLibraryW not found";
        } else {
            HANDLE hRemote = CreateRemoteThread(hProcess, nullptr, 0, pLoadLibraryW, remoteBuf, 0, nullptr);
            if (!hRemote) {
                outError = FormatWinError("CreateRemoteThread failed", GetLastError());
            } else {
                DWORD waitRes = WaitForSingleObject(hRemote, 8000);
                DWORD exitCode = 0;
                GetExitCodeThread(hRemote, &exitCode);
                CloseHandle(hRemote);
                if (waitRes != WAIT_OBJECT_0 || exitCode == 0) {
                    outError = "LoadLibraryW failed inside target process";
                } else {
                    ok = true;
                }
            }
        }
    }

    VirtualFreeEx(hProcess, remoteBuf, 0, MEM_RELEASE);
    return ok;
}

} // namespace AppProxy::Injector

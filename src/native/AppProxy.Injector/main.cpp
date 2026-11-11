#include "OepInjector.h"
#include "LogProtocol.h"

#include <windows.h>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

std::string WideToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int needed = WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr.c_str(), static_cast<int>(wstr.size()), out.data(), needed, nullptr, nullptr);
    return out;
}

std::wstring Utf8ToWide(const std::string& str) {
    if (str.empty()) return {};
    int needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), nullptr, 0);
    if (needed <= 0) return {};
    std::wstring out(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), static_cast<int>(str.size()), out.data(), needed);
    return out;
}

std::wstring DecodeBase64ToWide(const std::wstring& b64W) {
    std::string b64 = WideToUtf8(b64W);
    if (b64.empty()) return {};

    static const int kDecTable[256] = {
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,62,-1,-1,-1,63,52,53,54,55,56,57,58,59,60,61,-1,-1,-1,-1,-1,-1,
        -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,-1,-1,-1,-1,-1,
        -1,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40,41,42,43,44,45,46,47,48,49,50,51,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
        -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1
    };

    std::string bytes;
    bytes.reserve((b64.size() * 3) / 4);
    int val = 0;
    int valb = -8;
    for (unsigned char c : b64) {
        if (c == '=') break;
        int d = kDecTable[c];
        if (d == -1) continue;
        val = (val << 6) + d;
        valb += 6;
        if (valb >= 0) {
            bytes.push_back(static_cast<char>((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return Utf8ToWide(bytes);
}

std::wstring GetSelfDirectory() {
    wchar_t buf[MAX_PATH]{};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring s(buf);
    size_t pos = s.find_last_of(L"\\/");
    return (pos != std::wstring::npos) ? s.substr(0, pos) : L".";
}

void PrintJsonSuccess(DWORD pid, const char* arch) {
    std::printf("{\"ok\":true,\"pid\":%lu,\"arch\":\"%s\"}\n", pid, arch);
}

void PrintJsonError(const std::string& err) {
    std::printf("{\"ok\":false,\"error\":\"%s\"}\n", AppProxy::IPC::EscapeJsonString(err).c_str());
}

bool IsConsoleSubsystemPe(const std::wstring& exePath) {
    HANDLE hFile = CreateFileW(
        exePath.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        return false;
    }

    auto readExact = [hFile](LONG offset, void* dst, DWORD bytes) -> bool {
        LARGE_INTEGER li{};
        li.QuadPart = offset;
        if (!SetFilePointerEx(hFile, li, nullptr, FILE_BEGIN)) {
            return false;
        }
        DWORD read = 0;
        return ReadFile(hFile, dst, bytes, &read, nullptr) && read == bytes;
    };

    IMAGE_DOS_HEADER dosHdr{};
    bool isCui = false;
    if (readExact(0, &dosHdr, sizeof(dosHdr)) &&
        dosHdr.e_magic == IMAGE_DOS_SIGNATURE &&
        dosHdr.e_lfanew > 0 &&
        dosHdr.e_lfanew <= 0x10000000L) {
        DWORD peSig = 0;
        IMAGE_FILE_HEADER fileHdr{};
        if (readExact(dosHdr.e_lfanew, &peSig, sizeof(peSig)) &&
            peSig == IMAGE_NT_SIGNATURE &&
            readExact(dosHdr.e_lfanew + static_cast<LONG>(sizeof(DWORD)), &fileHdr, sizeof(fileHdr))) {
            LONG optOffset = dosHdr.e_lfanew + static_cast<LONG>(sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER));
            WORD optMagic = 0;
            if (fileHdr.SizeOfOptionalHeader >= sizeof(WORD) &&
                readExact(optOffset, &optMagic, sizeof(optMagic))) {
                if (optMagic == IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
                    fileHdr.SizeOfOptionalHeader >= offsetof(IMAGE_OPTIONAL_HEADER32, Subsystem) + sizeof(WORD)) {
                    IMAGE_OPTIONAL_HEADER32 opt32{};
                    if (readExact(optOffset, &opt32, sizeof(opt32))) {
                        isCui = (opt32.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI);
                    }
                } else if (optMagic == IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
                           fileHdr.SizeOfOptionalHeader >= offsetof(IMAGE_OPTIONAL_HEADER64, Subsystem) + sizeof(WORD)) {
                    IMAGE_OPTIONAL_HEADER64 opt64{};
                    if (readExact(optOffset, &opt64, sizeof(opt64))) {
                        isCui = (opt64.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_CUI);
                    }
                }
            }
        }
    }

    CloseHandle(hFile);
    return isCui;
}

bool CreateSuspendedTargetProcess(
    const std::wstring& exePath,
    std::vector<wchar_t>& cmdBuf,
    const std::wstring& workDir,
    bool detachConsole,
    PROCESS_INFORMATION& outPi,
    DWORD& outError) {
    LPCWSTR dirPtr = workDir.empty() ? nullptr : workDir.c_str();
    DWORD baseFlags = CREATE_SUSPENDED;
    if (detachConsole && IsConsoleSubsystemPe(exePath)) {
        baseFlags |= CREATE_NEW_CONSOLE;
    }

    // Explicitly disable CIG (MicrosoftSignedOnly) and ACG on the target process
    // so Microsoft-signed browsers like msedge.exe allow loading AppProxy.Hook.dll.
    SIZE_T attrSize = 0;
    InitializeProcThreadAttributeList(nullptr, 1, 0, &attrSize);
    if (attrSize > 0) {
        std::vector<uint8_t> attrBuf(attrSize, 0);
        auto attrList = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(attrBuf.data());
        if (InitializeProcThreadAttributeList(attrList, 1, 0, &attrSize)) {
            DWORD64 mitigationPolicy =
                PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_OFF |
                PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_OFF;

            if (UpdateProcThreadAttribute(
                    attrList,
                    0,
                    PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
                    &mitigationPolicy,
                    sizeof(mitigationPolicy),
                    nullptr,
                    nullptr)) {
                STARTUPINFOEXW siEx{};
                siEx.StartupInfo.cb = sizeof(STARTUPINFOEXW);
                siEx.lpAttributeList = attrList;

                std::vector<wchar_t> cmdCopy = cmdBuf;
                BOOL ok = CreateProcessW(
                    exePath.c_str(),
                    cmdCopy.data(),
                    nullptr,
                    nullptr,
                    FALSE,
                    baseFlags | EXTENDED_STARTUPINFO_PRESENT,
                    nullptr,
                    dirPtr,
                    &siEx.StartupInfo,
                    &outPi);
                DWORD err = ok ? 0 : GetLastError();
                DeleteProcThreadAttributeList(attrList);
                if (ok) {
                    return true;
                }
                // Fall back to standard CreateProcessW if extended mitigation flags are rejected
                outError = err;
            } else {
                DeleteProcThreadAttributeList(attrList);
            }
        }
    }

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    if (CreateProcessW(
            exePath.c_str(),
            cmdBuf.data(),
            nullptr,
            nullptr,
            FALSE,
            baseFlags,
            nullptr,
            dirPtr,
            &si,
            &outPi)) {
        return true;
    }

    outError = GetLastError();
    return false;
}

} // namespace

int wmain(int argc, wchar_t* argv[]) {
    bool modeLaunch = false;
    bool modeAttach = false;
    bool noResume = false;
    bool detachConsole = false;
    DWORD targetPid = 0;
    DWORD targetTid = 0;
    std::wstring exePath;
    std::wstring args;
    std::wstring workDir;
    std::wstring dllPath;

    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--launch") modeLaunch = true;
        else if (a == L"--attach-suspended") modeAttach = true;
        else if (a == L"--no-resume") noResume = true;
        else if (a == L"--detach-console") detachConsole = true;
        else if (a == L"--pid" && i + 1 < argc) targetPid = std::wcstoul(argv[++i], nullptr, 10);
        else if (a == L"--tid" && i + 1 < argc) targetTid = std::wcstoul(argv[++i], nullptr, 10);
        else if (a == L"--exe" && i + 1 < argc) exePath = argv[++i];
        else if (a == L"--exe-b64" && i + 1 < argc) exePath = DecodeBase64ToWide(argv[++i]);
        else if (a == L"--args" && i + 1 < argc) args = argv[++i];
        else if (a == L"--args-b64" && i + 1 < argc) args = DecodeBase64ToWide(argv[++i]);
        else if (a == L"--workdir" && i + 1 < argc) workDir = argv[++i];
        else if (a == L"--workdir-b64" && i + 1 < argc) workDir = DecodeBase64ToWide(argv[++i]);
        else if (a == L"--dll" && i + 1 < argc) dllPath = argv[++i];
        else if (a == L"--dll-b64" && i + 1 < argc) dllPath = DecodeBase64ToWide(argv[++i]);
    }

    if (modeAttach) {
        if (targetPid == 0 || targetTid == 0 || dllPath.empty()) {
            PrintJsonError("Missing --pid, --tid, or --dll for --attach-suspended");
            return 2;
        }
        HANDLE hProc = OpenProcess(
            PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE |
                PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | SYNCHRONIZE,
            FALSE,
            targetPid);
        if (!hProc) {
            PrintJsonError("OpenProcess failed");
            return 1;
        }
        HANDLE hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, targetTid);
        if (!hThread) {
            CloseHandle(hProc);
            PrintJsonError("OpenThread failed");
            return 1;
        }

        std::string err;
        bool ok = AppProxy::Injector::InjectSuspendedProcessAtOep(hProc, hThread, dllPath, err);
        if (!noResume) {
            ResumeThread(hThread);
        }
        CloseHandle(hThread);
        CloseHandle(hProc);

        if (!ok) {
            PrintJsonError(err);
            return 1;
        }
        PrintJsonSuccess(targetPid, AppProxy::Injector::IsProcess64Bit(GetCurrentProcess()) ? "x64" : "x86");
        return 0;
    }

    if (modeLaunch) {
        if (exePath.empty()) {
            PrintJsonError("Missing --exe or --exe-b64");
            return 2;
        }

        std::wstring cmdLine = L"\"" + exePath + L"\"";
        if (!args.empty()) {
            cmdLine += L" " + args;
        }
        std::vector<wchar_t> cmdBuf(cmdLine.begin(), cmdLine.end());
        cmdBuf.push_back(L'\0');

        if (workDir.empty()) {
            size_t slash = exePath.find_last_of(L"\\/");
            if (slash != std::wstring::npos) {
                workDir = exePath.substr(0, slash);
            }
        }

        PROCESS_INFORMATION pi{};
        DWORD createErr = 0;
        if (!CreateSuspendedTargetProcess(exePath, cmdBuf, workDir, detachConsole, pi, createErr)) {
            char buf[128]{};
            std::snprintf(buf, sizeof(buf), "CreateProcessW failed (Win32 error %lu)", createErr);
            PrintJsonError(buf);
            return 1;
        }

        bool targetIs64 = AppProxy::Injector::IsProcess64Bit(pi.hProcess);
#if defined(_WIN64)
        constexpr bool selfIs64 = true;
#else
        constexpr bool selfIs64 = false;
#endif
        std::wstring selfDir = GetSelfDirectory();
        const wchar_t* archTag = targetIs64 ? L"x64" : L"x86";
        std::wstring effectiveDll = !dllPath.empty()
                                        ? dllPath
                                        : (selfDir + L"\\AppProxy.Hook." + archTag + L".dll");

        bool injected = false;
        std::string err;

        if (targetIs64 == selfIs64) {
            injected = AppProxy::Injector::InjectSuspendedProcessAtOep(pi.hProcess, pi.hThread, effectiveDll, err);
        } else {
            // Delegate cross-bitness (e.g. AnyCPU .NET running as x64 or WoW64 x86)
            std::wstring helperExe = selfDir + L"\\AppProxy.Injector." + archTag + L".exe";
            std::wstring helperDll = selfDir + L"\\AppProxy.Hook." + archTag + L".dll";
            wchar_t helperCmd[1024]{};
            swprintf_s(
                helperCmd,
                L"\"%s\" --attach-suspended --pid %lu --tid %lu --dll \"%s\" --no-resume",
                helperExe.c_str(),
                pi.dwProcessId,
                pi.dwThreadId,
                helperDll.c_str());

            STARTUPINFOW hsi{};
            hsi.cb = sizeof(hsi);
            hsi.dwFlags = STARTF_USESTDHANDLES;
            hsi.hStdInput = INVALID_HANDLE_VALUE;
            hsi.hStdOutput = INVALID_HANDLE_VALUE;
            hsi.hStdError = INVALID_HANDLE_VALUE;
            PROCESS_INFORMATION hpi{};
            if (CreateProcessW(helperExe.c_str(), helperCmd, nullptr, nullptr, FALSE, CREATE_NO_WINDOW, nullptr, selfDir.c_str(), &hsi, &hpi)) {
                WaitForSingleObject(hpi.hProcess, 10000);
                DWORD exitCode = 1;
                GetExitCodeProcess(hpi.hProcess, &exitCode);
                CloseHandle(hpi.hThread);
                CloseHandle(hpi.hProcess);
                injected = (exitCode == 0);
                if (!injected) {
                    err = "Cross-architecture injector helper failed";
                }
            } else {
                err = "Failed to launch cross-architecture injector helper";
            }
        }

        if (!injected) {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            PrintJsonError(err);
            return 1;
        }

        ResumeThread(pi.hThread);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        PrintJsonSuccess(pi.dwProcessId, targetIs64 ? "x64" : "x86");
        return 0;
    }

    PrintJsonError("Specify --launch or --attach-suspended");
    return 2;
}

#pragma once

#include <windows.h>
#include <string>

namespace AppProxy::Injector {

bool IsProcess64Bit(HANDLE hProcess);

bool InjectSuspendedProcessAtOep(
    HANDLE hProcess,
    HANDLE hThread,
    const std::wstring& dllPath,
    std::string& outError);

} // namespace AppProxy::Injector

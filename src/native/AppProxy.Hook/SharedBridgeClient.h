#pragma once

#include "HookContext.h"
#include <cstdint>
#include <string>

namespace AppProxy::Hook {

class SharedBridgeClient {
public:
    static bool EnsureConnected();
    static bool GetBridgePorts(uint16_t& outPortV4, uint16_t& outPortV6);
    static uint32_t GetEffectiveFlags();

    // Returns Fake-IPv4 in host byte order (0 on failure)
    static uint32_t AllocateOrGetFakeIp(const char* domain);

    // Writes NAT entry before connect/ConnectEx executes
    static bool RegisterNatMapping(uint16_t localPortHostOrder, uint8_t ipFamily, const sockaddr* origAddr);

    // Async Named Pipe log queue
    static void StartLogWorker();
    static void EmitLogEvent(const char* eventType, const std::string& message);
    static void Shutdown(bool processTerminating);
};

} // namespace AppProxy::Hook

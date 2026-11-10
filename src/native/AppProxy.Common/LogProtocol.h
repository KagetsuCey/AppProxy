#pragma once

#include <cstdint>
#include <cstdio>
#include <string>

namespace AppProxy::IPC {

inline std::string EscapeJsonString(const std::string& input) {
    std::string out;
    out.reserve(input.size() + 16);
    for (unsigned char c : input) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out.push_back(static_cast<char>(c));
                }
                break;
        }
    }
    return out;
}

inline std::string FormatLogLineJson(
    uint64_t timestampMs,
    uint32_t sessionId,
    uint32_t pid,
    uint32_t parentPid,
    const char* arch,
    const std::string& processName,
    const char* eventType,
    const std::string& message) {
    std::string json;
    json.reserve(256);
    json += "{\"ts\":";
    json += std::to_string(timestampMs);
    json += ",\"sessionId\":";
    json += std::to_string(sessionId);
    json += ",\"pid\":";
    json += std::to_string(pid);
    json += ",\"parentPid\":";
    json += std::to_string(parentPid);
    json += ",\"arch\":\"";
    json += (arch ? arch : "");
    json += "\",\"process\":\"";
    json += EscapeJsonString(processName);
    json += "\",\"event\":\"";
    json += (eventType ? eventType : "");
    json += "\",\"message\":\"";
    json += EscapeJsonString(message);
    json += "\"}\n";
    return json;
}

} // namespace AppProxy::IPC

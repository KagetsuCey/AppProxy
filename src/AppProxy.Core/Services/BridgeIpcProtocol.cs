using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using AppProxy.UI.Models;

namespace AppProxy.UI.Services;

public sealed class BridgeLaunchRequest
{
    [JsonPropertyName("appName")]
    public string AppName { get; set; } = string.Empty;

    [JsonPropertyName("exePath")]
    public string ExePath { get; set; } = string.Empty;

    [JsonPropertyName("arguments")]
    public string Arguments { get; set; } = string.Empty;

    [JsonPropertyName("workingDirectory")]
    public string WorkingDirectory { get; set; } = string.Empty;

    [JsonPropertyName("remoteDns")]
    public bool RemoteDns { get; set; } = true;

    [JsonPropertyName("bypassLan")]
    public bool BypassLan { get; set; } = true;

    [JsonPropertyName("injectChildren")]
    public bool InjectChildren { get; set; } = true;

    [JsonPropertyName("isolateProfileDir")]
    public bool IsolateProfileDir { get; set; }

    [JsonPropertyName("proxy")]
    public BridgeProxyConfig? Proxy { get; set; }

    public string BuildEffectiveArguments(string baseDir)
    {
        string rawArgs = Arguments?.Trim() ?? string.Empty;
        if (!IsolateProfileDir ||
            rawArgs.Contains("--user-data-dir", StringComparison.OrdinalIgnoreCase))
        {
            return rawArgs;
        }

        string seedName = !string.IsNullOrWhiteSpace(AppName)
            ? AppName
            : Path.GetFileNameWithoutExtension(ExePath);
        string safeFolder = SanitizeDirectoryName(seedName);
        string profileDir = Path.Combine(baseDir, "profiles", safeFolder);
        string userDataArg = $"--user-data-dir=\"{profileDir}\"";
        return string.IsNullOrEmpty(rawArgs) ? userDataArg : $"{rawArgs} {userDataArg}";
    }

    private static string SanitizeDirectoryName(string name)
    {
        if (string.IsNullOrWhiteSpace(name)) return "DefaultApp";
        char[] invalid = Path.GetInvalidFileNameChars();
        var sb = new StringBuilder(name.Length);
        foreach (char c in name.Trim())
        {
            sb.Append(Array.IndexOf(invalid, c) >= 0 ? '_' : c);
        }
        string cleaned = sb.ToString().Trim('.', ' ');
        return string.IsNullOrEmpty(cleaned) ? "DefaultApp" : cleaned;
    }
}

public sealed class BridgeProxyConfig
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = string.Empty;

    [JsonPropertyName("protocol")]
    public ProxyProtocol Protocol { get; set; } = ProxyProtocol.Socks5;

    [JsonPropertyName("host")]
    public string Host { get; set; } = "127.0.0.1";

    [JsonPropertyName("port")]
    public int Port { get; set; } = 1080;

    [JsonPropertyName("username")]
    public string Username { get; set; } = string.Empty;

    [JsonPropertyName("password")]
    public string Password { get; set; } = string.Empty;

    public static BridgeProxyConfig FromProfile(ProxyProfile profile) => new()
    {
        Name = profile.Name,
        Protocol = profile.Protocol,
        Host = profile.Host,
        Port = profile.Port,
        Username = profile.Username,
        Password = profile.Password
    };

    public ProxyProfile ToProfile() => new()
    {
        Name = Name,
        Protocol = Protocol,
        Host = Host,
        Port = Port,
        Username = Username,
        Password = Password
    };
}

public sealed class BridgeHandshakeResponse
{
    [JsonPropertyName("ok")]
    public bool Ok { get; set; }

    [JsonPropertyName("bridgePid")]
    public uint BridgePid { get; set; }

    [JsonPropertyName("portV4")]
    public ushort PortV4 { get; set; }

    [JsonPropertyName("portV6")]
    public ushort PortV6 { get; set; }

    [JsonPropertyName("targetPid")]
    public uint TargetPid { get; set; }

    [JsonPropertyName("arch")]
    public string? Arch { get; set; }

    [JsonPropertyName("warning")]
    public string? Warning { get; set; }

    [JsonPropertyName("error")]
    public string? Error { get; set; }
}

public sealed class UiBridgeEnvelope
{
    [JsonPropertyName("type")]
    public string Type { get; set; } = string.Empty; // "status" | "event" | "conn"

    [JsonPropertyName("bridgePid")]
    public uint BridgePid { get; set; }

    [JsonPropertyName("status")]
    public BridgeStatusDto? Status { get; set; }

    [JsonPropertyName("event")]
    public BridgeEventDto? Event { get; set; }

    [JsonPropertyName("conn")]
    public BridgeConnectionDto? Connection { get; set; }
}

public sealed class BridgeStatusDto
{
    [JsonPropertyName("bridgePid")]
    public uint BridgePid { get; set; }

    [JsonPropertyName("appName")]
    public string AppName { get; set; } = string.Empty;

    [JsonPropertyName("targetPid")]
    public uint TargetPid { get; set; }

    [JsonPropertyName("portV4")]
    public ushort PortV4 { get; set; }

    [JsonPropertyName("portV6")]
    public ushort PortV6 { get; set; }

    [JsonPropertyName("activeConnections")]
    public int ActiveConnections { get; set; }

    [JsonPropertyName("alive")]
    public bool Alive { get; set; }
}

public sealed class BridgeEventDto
{
    [JsonPropertyName("timestampMs")]
    public long TimestampMs { get; set; }

    [JsonPropertyName("bridgePid")]
    public uint BridgePid { get; set; }

    [JsonPropertyName("sessionId")]
    public uint SessionId { get; set; }

    [JsonPropertyName("pid")]
    public uint Pid { get; set; }

    [JsonPropertyName("parentPid")]
    public uint ParentPid { get; set; }

    [JsonPropertyName("arch")]
    public string Arch { get; set; } = string.Empty;

    [JsonPropertyName("processName")]
    public string ProcessName { get; set; } = string.Empty;

    [JsonPropertyName("eventType")]
    public string EventType { get; set; } = string.Empty;

    [JsonPropertyName("message")]
    public string Message { get; set; } = string.Empty;

    public static BridgeEventDto FromRecord(ProcessEventRecord r) => new()
    {
        TimestampMs = new DateTimeOffset(r.Timestamp).ToUnixTimeMilliseconds(),
        BridgePid = r.BridgePid,
        SessionId = r.SessionId,
        Pid = r.Pid,
        ParentPid = r.ParentPid,
        Arch = r.Arch,
        ProcessName = r.ProcessName,
        EventType = r.EventType,
        Message = r.Message
    };

    public ProcessEventRecord ToRecord() => new()
    {
        Timestamp = TimestampMs > 0
            ? DateTimeOffset.FromUnixTimeMilliseconds(TimestampMs).LocalDateTime
            : DateTime.Now,
        BridgePid = BridgePid,
        SessionId = SessionId,
        Pid = Pid,
        ParentPid = ParentPid,
        Arch = Arch,
        ProcessName = ProcessName,
        EventType = EventType,
        Message = Message
    };
}

public sealed class BridgeConnectionDto
{
    [JsonPropertyName("id")]
    public long Id { get; set; }

    [JsonPropertyName("bridgePid")]
    public uint BridgePid { get; set; }

    [JsonPropertyName("startTimeMs")]
    public long StartTimeMs { get; set; }

    [JsonPropertyName("processName")]
    public string ProcessName { get; set; } = string.Empty;

    [JsonPropertyName("pid")]
    public uint Pid { get; set; }

    [JsonPropertyName("targetDisplay")]
    public string TargetDisplay { get; set; } = string.Empty;

    [JsonPropertyName("fakeIp")]
    public string FakeIp { get; set; } = string.Empty;

    [JsonPropertyName("proxyName")]
    public string ProxyName { get; set; } = "Direct";

    [JsonPropertyName("protocol")]
    public string Protocol { get; set; } = "Direct";

    [JsonPropertyName("status")]
    public string Status { get; set; } = "Connecting";

    [JsonPropertyName("latencyMs")]
    public int LatencyMs { get; set; }

    [JsonPropertyName("bytesUp")]
    public long BytesUp { get; set; }

    [JsonPropertyName("bytesDown")]
    public long BytesDown { get; set; }

    [JsonPropertyName("errorMessage")]
    public string ErrorMessage { get; set; } = string.Empty;

    public static BridgeConnectionDto FromRecord(ConnectionRecord r) => new()
    {
        Id = r.Id,
        BridgePid = r.BridgePid,
        StartTimeMs = new DateTimeOffset(r.StartTime).ToUnixTimeMilliseconds(),
        ProcessName = r.ProcessName,
        Pid = r.Pid,
        TargetDisplay = r.TargetDisplay,
        FakeIp = r.FakeIp,
        ProxyName = r.ProxyName,
        Protocol = r.Protocol,
        Status = r.RawStatus,
        LatencyMs = r.RawLatencyMs,
        BytesUp = r.RawBytesUp,
        BytesDown = r.RawBytesDown,
        ErrorMessage = r.RawErrorMessage
    };

    public ConnectionRecord ToRecord()
    {
        var rec = new ConnectionRecord
        {
            Id = Id,
            BridgePid = BridgePid,
            StartTime = StartTimeMs > 0
                ? DateTimeOffset.FromUnixTimeMilliseconds(StartTimeMs).LocalDateTime
                : DateTime.Now,
            ProcessName = ProcessName,
            Pid = Pid,
            TargetDisplay = TargetDisplay,
            FakeIp = FakeIp,
            ProxyName = ProxyName,
            Protocol = Protocol,
            Status = Status,
            LatencyMs = LatencyMs,
            BytesUp = BytesUp,
            BytesDown = BytesDown,
            ErrorMessage = ErrorMessage
        };
        rec.ApplySnapshot(Status, LatencyMs, BytesUp, BytesDown, ErrorMessage);
        return rec;
    }
}

public static class BridgeIpcCodec
{
    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        Converters = { new JsonStringEnumConverter() }
    };

    public static string GetUiPipeName(uint bridgePid) => $"AppProxy_Ui_{bridgePid}";

    public static string EncodeLaunchRequestBase64(BridgeLaunchRequest request)
    {
        string json = JsonSerializer.Serialize(request, JsonOptions);
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(json));
    }

    public static BridgeLaunchRequest? DecodeLaunchRequestBase64(string base64)
    {
        if (string.IsNullOrWhiteSpace(base64)) return null;
        byte[] bytes = Convert.FromBase64String(base64);
        string json = Encoding.UTF8.GetString(bytes);
        return JsonSerializer.Deserialize<BridgeLaunchRequest>(json, JsonOptions);
    }

    public static string SerializeLine<T>(T value) =>
        JsonSerializer.Serialize(value, JsonOptions);

    public static T? DeserializeLine<T>(string line) =>
        JsonSerializer.Deserialize<T>(line, JsonOptions);
}

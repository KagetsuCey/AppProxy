using System.Text.Json.Serialization;

namespace AppProxy.Core.Models;

/// <summary>
/// VLESS protocol and transport/security parameters (used when ProxyProtocol == Vless via managed Xray-core).
/// </summary>
public sealed class VlessSettings
{
    public string Uuid { get; set; } = string.Empty;

    public string Encryption { get; set; } = "none";

    public string Flow { get; set; } = string.Empty;

    public string Network { get; set; } = "tcp";

    public string HeaderType { get; set; } = "none";

    public string Security { get; set; } = "none";

    public string Sni { get; set; } = string.Empty;

    public string Fingerprint { get; set; } = string.Empty;

    public string PublicKey { get; set; } = string.Empty;

    public string ShortId { get; set; } = string.Empty;

    public string SpiderX { get; set; } = string.Empty;

    public string Alpn { get; set; } = string.Empty;

    public bool AllowInsecure { get; set; }

    public string Path { get; set; } = string.Empty;

    public string HostHeader { get; set; } = string.Empty;

    public string ServiceName { get; set; } = string.Empty;

    public string Mode { get; set; } = string.Empty;

    [JsonIgnore]
    public string NormalizedSecurity => string.IsNullOrWhiteSpace(Security)
        ? "none"
        : Security.Trim().ToLowerInvariant();

    [JsonIgnore]
    public string NormalizedNetwork => string.IsNullOrWhiteSpace(Network)
        ? "tcp"
        : Network.Trim().ToLowerInvariant();

    public bool Validate(out string error)
    {
        if (string.IsNullOrWhiteSpace(Uuid))
        {
            error = "VLESS 节点缺少 UUID (id)";
            return false;
        }

        string sec = NormalizedSecurity;
        if (sec == "reality")
        {
            if (string.IsNullOrWhiteSpace(PublicKey))
            {
                error = "VLESS REALITY 节点缺少 PublicKey (pbk)";
                return false;
            }

            if (string.IsNullOrWhiteSpace(Sni))
            {
                error = "VLESS REALITY 节点缺少 SNI (serverName)";
                return false;
            }
        }

        error = string.Empty;
        return true;
    }

    public VlessSettings Clone() => new()
    {
        Uuid = Uuid,
        Encryption = Encryption,
        Flow = Flow,
        Network = Network,
        HeaderType = HeaderType,
        Security = Security,
        Sni = Sni,
        Fingerprint = Fingerprint,
        PublicKey = PublicKey,
        ShortId = ShortId,
        SpiderX = SpiderX,
        Alpn = Alpn,
        AllowInsecure = AllowInsecure,
        Path = Path,
        HostHeader = HostHeader,
        ServiceName = ServiceName,
        Mode = Mode
    };
}

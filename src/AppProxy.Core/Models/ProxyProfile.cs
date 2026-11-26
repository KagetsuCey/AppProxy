using System.Text.Json.Serialization;
using System.Text.RegularExpressions;
using CommunityToolkit.Mvvm.ComponentModel;

namespace AppProxy.Core.Models;

public enum ProxyProtocol
{
    Socks5,
    Http,
    Https,
    Vless
}

public partial class ProxyProfile : ObservableObject
{
    [ObservableProperty]
    private Guid _id = Guid.NewGuid();

    [ObservableProperty]
    private string _name = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ProtocolDisplay))]
    [NotifyPropertyChangedFor(nameof(VlessSummaryText))]
    [NotifyPropertyChangedFor(nameof(HasVlessSummary))]
    private ProxyProtocol _protocol = ProxyProtocol.Socks5;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(EndpointDisplay))]
    private string _host = "127.0.0.1";

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(EndpointDisplay))]
    private int _port = 1080;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasAuth))]
    private string _username = string.Empty;

    [ObservableProperty]
    private string _password = string.Empty;

    [ObservableProperty]
    [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    [NotifyPropertyChangedFor(nameof(HasAuth))]
    [NotifyPropertyChangedFor(nameof(ProtocolDisplay))]
    [NotifyPropertyChangedFor(nameof(SecurityBadgeText))]
    [NotifyPropertyChangedFor(nameof(HasSecurityBadge))]
    [NotifyPropertyChangedFor(nameof(VlessSummaryText))]
    [NotifyPropertyChangedFor(nameof(HasVlessSummary))]
    private VlessSettings? _vless;

    [ObservableProperty]
    [property: JsonIgnore]
    private bool _isSelected;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasExitInfo))]
    [NotifyPropertyChangedFor(nameof(ExitBadgeText))]
    [NotifyPropertyChangedFor(nameof(ExitTooltipText))]
    [NotifyPropertyChangedFor(nameof(ExitBadgeState))]
    private string _exitIp = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasExitInfo))]
    [NotifyPropertyChangedFor(nameof(ExitBadgeText))]
    [NotifyPropertyChangedFor(nameof(ExitTooltipText))]
    private string _exitCountryCode = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(HasExitInfo))]
    [NotifyPropertyChangedFor(nameof(ExitBadgeText))]
    [NotifyPropertyChangedFor(nameof(ExitTooltipText))]
    [NotifyPropertyChangedFor(nameof(ExitBadgeState))]
    private string _exitLocation = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ExitTooltipText))]
    private string _exitIsp = string.Empty;

    [ObservableProperty]
    [property: JsonIgnore]
    [NotifyPropertyChangedFor(nameof(LatencyDisplay))]
    [NotifyPropertyChangedFor(nameof(LatencyLevel))]
    private int? _lastLatencyMs;

    [ObservableProperty]
    [property: JsonIgnore]
    [NotifyPropertyChangedFor(nameof(LatencyDisplay))]
    [NotifyPropertyChangedFor(nameof(LatencyLevel))]
    private string _lastTestStatus = "Untested";

    [ObservableProperty]
    [property: JsonIgnore]
    [NotifyPropertyChangedFor(nameof(LatencyDisplay))]
    [NotifyPropertyChangedFor(nameof(LatencyLevel))]
    private bool _isTesting;

    [ObservableProperty]
    [property: JsonIgnore]
    [NotifyPropertyChangedFor(nameof(HasExitInfo))]
    [NotifyPropertyChangedFor(nameof(ExitBadgeText))]
    [NotifyPropertyChangedFor(nameof(ExitTooltipText))]
    [NotifyPropertyChangedFor(nameof(ExitBadgeState))]
    private bool _isDetectingExitIp;

    [ObservableProperty]
    [property: JsonIgnore]
    [NotifyPropertyChangedFor(nameof(HasExitInfo))]
    [NotifyPropertyChangedFor(nameof(ExitBadgeText))]
    [NotifyPropertyChangedFor(nameof(ExitTooltipText))]
    [NotifyPropertyChangedFor(nameof(ExitBadgeState))]
    private string _exitDetectError = string.Empty;

    [ObservableProperty]
    [property: JsonIgnore]
    [NotifyPropertyChangedFor(nameof(ExitBadgeText))]
    [NotifyPropertyChangedFor(nameof(ExitBadgeState))]
    private bool _isExitIpCopied;

    [JsonIgnore]
    public string ProtocolDisplay => Protocol switch
    {
        ProxyProtocol.Socks5 => "SOCKS5",
        ProxyProtocol.Http => "HTTP",
        ProxyProtocol.Https => "HTTPS",
        ProxyProtocol.Vless => "VLESS",
        _ => "UNKNOWN"
    };

    [JsonIgnore]
    public bool RequiresXrayCore => Protocol == ProxyProtocol.Vless;

    [JsonIgnore]
    public string SecurityBadgeText => Protocol == ProxyProtocol.Vless
        ? Vless?.NormalizedSecurity switch
        {
            "reality" => "REALITY",
            "tls" => "TLS",
            _ => string.Empty
        }
        : string.Empty;

    [JsonIgnore]
    public bool HasSecurityBadge => !string.IsNullOrEmpty(SecurityBadgeText);

    [JsonIgnore]
    public string VlessSummaryText
    {
        get
        {
            if (Protocol != ProxyProtocol.Vless || Vless is null) return string.Empty;

            var parts = new List<string>(3)
            {
                Vless.NormalizedNetwork.ToUpperInvariant()
            };

            string sniOrHost = !string.IsNullOrWhiteSpace(Vless.Sni)
                ? Vless.Sni.Trim()
                : Vless.HostHeader.Trim();
            if (!string.IsNullOrEmpty(sniOrHost))
            {
                parts.Add(sniOrHost);
            }

            string pathOrService = !string.IsNullOrWhiteSpace(Vless.Path)
                ? Vless.Path.Trim()
                : Vless.ServiceName.Trim();
            if (!string.IsNullOrEmpty(pathOrService))
            {
                parts.Add(pathOrService);
            }

            return string.Join(" · ", parts);
        }
    }

    [JsonIgnore]
    public bool HasVlessSummary => !string.IsNullOrEmpty(VlessSummaryText);

    [JsonIgnore]
    public string EndpointDisplay => $"{Host}:{Port}";

    [JsonIgnore]
    public bool HasAuth => Protocol != ProxyProtocol.Vless && !string.IsNullOrWhiteSpace(Username);

    [JsonIgnore]
    public string LatencyDisplay => IsTesting
        ? "Testing..."
        : LastLatencyMs.HasValue
            ? $"{LastLatencyMs.Value} ms"
            : LastTestStatus;

    [JsonIgnore]
    public string LatencyLevel
    {
        get
        {
            if (IsTesting) return "Testing";
            if (LastLatencyMs.HasValue)
            {
                return LastLatencyMs.Value switch
                {
                    <= 120 => "Good",
                    <= 350 => "Medium",
                    _ => "Bad"
                };
            }

            return string.Equals(LastTestStatus, "Untested", StringComparison.OrdinalIgnoreCase)
                ? "Untested"
                : "Bad";
        }
    }

    [JsonIgnore]
    public bool HasExitInfo =>
        IsDetectingExitIp ||
        !string.IsNullOrWhiteSpace(ExitIp) ||
        !string.IsNullOrWhiteSpace(ExitLocation) ||
        !string.IsNullOrWhiteSpace(ExitDetectError);

    [JsonIgnore]
    public string ExitBadgeState
    {
        get
        {
            if (IsDetectingExitIp) return "Detecting";
            if (IsExitIpCopied && !string.IsNullOrWhiteSpace(ExitIp)) return "Copied";
            if (!string.IsNullOrWhiteSpace(ExitIp) || !string.IsNullOrWhiteSpace(ExitLocation)) return "Ok";
            if (!string.IsNullOrWhiteSpace(ExitDetectError)) return "Error";
            return "None";
        }
    }

    [JsonIgnore]
    public string ExitBadgeText
    {
        get
        {
            if (IsDetectingExitIp) return "检测出口中...";
            if (IsExitIpCopied && !string.IsNullOrWhiteSpace(ExitIp)) return $"✓ 已复制 {ExitIp.Trim()}";
            if (!string.IsNullOrWhiteSpace(ExitIp) || !string.IsNullOrWhiteSpace(ExitLocation))
            {
                var parts = new List<string>(3);
                string cc = ExitCountryCode.Trim();
                string loc = ExitLocation.Trim();
                string ip = ExitIp.Trim();

                if (!string.IsNullOrEmpty(cc))
                {
                    parts.Add(cc);
                }
                if (!string.IsNullOrEmpty(loc) &&
                    !string.Equals(loc, cc, StringComparison.OrdinalIgnoreCase))
                {
                    parts.Add(loc);
                }
                if (!string.IsNullOrEmpty(ip))
                {
                    parts.Add(ip);
                }
                return string.Join(" · ", parts);
            }

            return ExitDetectError.Trim();
        }
    }

    [JsonIgnore]
    public string ExitTooltipText
    {
        get
        {
            if (IsDetectingExitIp) return "正在经由代理节点探测落地出口 IP 与地区...";
            if (!string.IsNullOrWhiteSpace(ExitIp) || !string.IsNullOrWhiteSpace(ExitLocation))
            {
                var lines = new List<string>(4);
                if (!string.IsNullOrWhiteSpace(ExitIp)) lines.Add($"出口 IP: {ExitIp}");
                if (!string.IsNullOrWhiteSpace(ExitLocation))
                {
                    string region = string.IsNullOrWhiteSpace(ExitCountryCode)
                        ? ExitLocation
                        : $"{ExitLocation} ({ExitCountryCode})";
                    lines.Add($"归属地: {region}");
                }
                if (!string.IsNullOrWhiteSpace(ExitIsp)) lines.Add($"运营商: {ExitIsp}");
                if (!string.IsNullOrWhiteSpace(ExitIp)) lines.Add("点击可复制出口 IP");
                return string.Join(Environment.NewLine, lines);
            }

            return !string.IsNullOrWhiteSpace(ExitDetectError)
                ? $"上次检测失败: {ExitDetectError}"
                : string.Empty;
        }
    }

    private static readonly Regex CopySuffixRegex = new(@"\s*\(副本(?:\s+\d+)?\)$", RegexOptions.Compiled);

    public static string BuildDuplicateName(string? sourceName, IEnumerable<string>? existingNames = null)
    {
        string raw = string.IsNullOrWhiteSpace(sourceName) ? "Proxy" : sourceName.Trim();
        string baseName = CopySuffixRegex.Replace(raw, string.Empty).Trim();
        if (string.IsNullOrEmpty(baseName))
        {
            baseName = "Proxy";
        }

        var used = existingNames is not null
            ? new HashSet<string>(existingNames.Where(n => !string.IsNullOrWhiteSpace(n)).Select(n => n.Trim()), StringComparer.OrdinalIgnoreCase)
            : null;

        string firstCandidate = $"{baseName} (副本)";
        if (used is null || !used.Contains(firstCandidate))
        {
            return firstCandidate;
        }

        for (int i = 2; ; i++)
        {
            string candidate = $"{baseName} (副本 {i})";
            if (!used.Contains(candidate))
            {
                return candidate;
            }
        }
    }

    public ProxyProfile CreateDuplicate(IEnumerable<string>? existingNames = null, string? customName = null) => new()
    {
        Id = Guid.NewGuid(),
        Name = string.IsNullOrWhiteSpace(customName)
            ? BuildDuplicateName(Name, existingNames)
            : customName.Trim(),
        Protocol = Protocol,
        Host = Host,
        Port = Port,
        Username = Username,
        Password = Password,
        Vless = Vless?.Clone(),
        ExitIp = string.Empty,
        ExitCountryCode = string.Empty,
        ExitLocation = string.Empty,
        ExitIsp = string.Empty,
        LastLatencyMs = null,
        LastTestStatus = "Untested",
        IsTesting = false,
        IsDetectingExitIp = false,
        ExitDetectError = string.Empty,
        IsExitIpCopied = false,
        IsSelected = false
    };

    public ProxyProfile Clone() => new()
    {
        Id = Id,
        Name = Name,
        Protocol = Protocol,
        Host = Host,
        Port = Port,
        Username = Username,
        Password = Password,
        Vless = Vless?.Clone(),
        ExitIp = ExitIp,
        ExitCountryCode = ExitCountryCode,
        ExitLocation = ExitLocation,
        ExitIsp = ExitIsp,
        LastLatencyMs = LastLatencyMs,
        LastTestStatus = LastTestStatus
    };
}

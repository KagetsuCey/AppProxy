using System.Text.Json.Serialization;
using CommunityToolkit.Mvvm.ComponentModel;

namespace AppProxy.UI.Models;

public enum ProxyProtocol
{
    Socks5,
    Http,
    Https
}

public partial class ProxyProfile : ObservableObject
{
    [ObservableProperty]
    private Guid _id = Guid.NewGuid();

    [ObservableProperty]
    private string _name = string.Empty;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(ProtocolDisplay))]
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
    [property: JsonIgnore]
    [NotifyPropertyChangedFor(nameof(LatencyDisplay))]
    private int? _lastLatencyMs;

    [ObservableProperty]
    [property: JsonIgnore]
    [NotifyPropertyChangedFor(nameof(LatencyDisplay))]
    private string _lastTestStatus = "Untested";

    [ObservableProperty]
    [property: JsonIgnore]
    private bool _isTesting;

    [JsonIgnore]
    public string ProtocolDisplay => Protocol switch
    {
        ProxyProtocol.Socks5 => "SOCKS5",
        ProxyProtocol.Http => "HTTP",
        ProxyProtocol.Https => "HTTPS",
        _ => "UNKNOWN"
    };

    [JsonIgnore]
    public string EndpointDisplay => $"{Host}:{Port}";

    [JsonIgnore]
    public bool HasAuth => !string.IsNullOrWhiteSpace(Username);

    [JsonIgnore]
    public string LatencyDisplay => IsTesting
        ? "Testing..."
        : LastLatencyMs.HasValue
            ? $"{LastLatencyMs.Value} ms"
            : LastTestStatus;

    public ProxyProfile Clone() => new()
    {
        Id = Id,
        Name = Name,
        Protocol = Protocol,
        Host = Host,
        Port = Port,
        Username = Username,
        Password = Password,
        LastLatencyMs = LastLatencyMs,
        LastTestStatus = LastTestStatus
    };
}

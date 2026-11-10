using System.Text.Json.Serialization;
using System.Windows.Media;
using CommunityToolkit.Mvvm.ComponentModel;

namespace AppProxy.UI.Models;

public partial class AppProfile : ObservableObject
{
    [ObservableProperty]
    private Guid _id = Guid.NewGuid();

    [ObservableProperty]
    private string _name = string.Empty;

    [ObservableProperty]
    private string _exePath = string.Empty;

    [ObservableProperty]
    private string _arguments = string.Empty;

    [ObservableProperty]
    private string _workingDirectory = string.Empty;

    [ObservableProperty]
    private Guid? _proxyProfileId;

    [ObservableProperty]
    private bool _remoteDns = true;

    [ObservableProperty]
    private bool _bypassLan = true;

    [ObservableProperty]
    private bool _injectChildren = true;

    [ObservableProperty]
    private string _detectedArch = "x64";

    [ObservableProperty]
    [property: JsonIgnore]
    private ImageSource? _icon;

    [ObservableProperty]
    [property: JsonIgnore]
    private string _boundProxyName = "Direct";

    public AppProfile Clone() => new()
    {
        Id = Id,
        Name = Name,
        ExePath = ExePath,
        Arguments = Arguments,
        WorkingDirectory = WorkingDirectory,
        ProxyProfileId = ProxyProfileId,
        RemoteDns = RemoteDns,
        BypassLan = BypassLan,
        InjectChildren = InjectChildren,
        DetectedArch = DetectedArch,
        Icon = Icon,
        BoundProxyName = BoundProxyName
    };
}

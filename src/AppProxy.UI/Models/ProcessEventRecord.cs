namespace AppProxy.UI.Models;

public sealed class ProcessEventRecord
{
    public DateTime Timestamp { get; init; } = DateTime.Now;
    public uint SessionId { get; init; }
    public uint Pid { get; init; }
    public uint ParentPid { get; init; }
    public string Arch { get; init; } = string.Empty;
    public string ProcessName { get; init; } = string.Empty;
    public string EventType { get; init; } = string.Empty;
    public string Message { get; init; } = string.Empty;

    public string FormattedTime => Timestamp.ToString("HH:mm:ss.fff");
}

public sealed class AppConfig
{
    public List<ProxyProfile> Proxies { get; set; } = new();
    public List<AppProfile> Apps { get; set; } = new();
    public bool IsDarkTheme { get; set; } = true;
    public string TestProbeHost { get; set; } = "www.gstatic.com";
    public int TestProbePort { get; set; } = 80;
}

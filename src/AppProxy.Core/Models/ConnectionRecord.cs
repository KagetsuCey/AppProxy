using CommunityToolkit.Mvvm.ComponentModel;

namespace AppProxy.UI.Models;

public partial class ConnectionRecord : ObservableObject
{
    private long _rawBytesUp;
    private long _rawBytesDown;
    private int _rawLatencyMs;
    private string _rawStatus = "Connecting";
    private string _rawErrorMessage = string.Empty;
    private int _dirty;

    public long Id { get; init; }
    public uint BridgePid { get; init; }
    public DateTime StartTime { get; init; } = DateTime.Now;
    public string ProcessName { get; init; } = string.Empty;
    public uint Pid { get; init; }
    public string TargetDisplay { get; init; } = string.Empty;
    public string FakeIp { get; init; } = string.Empty;
    public string ProxyName { get; init; } = "Direct";
    public string Protocol { get; init; } = "Direct";

    [ObservableProperty]
    private string _status = "Connecting";

    [ObservableProperty]
    private int _latencyMs;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(FormattedUp))]
    private long _bytesUp;

    [ObservableProperty]
    [NotifyPropertyChangedFor(nameof(FormattedDown))]
    private long _bytesDown;

    [ObservableProperty]
    private string _errorMessage = string.Empty;

    public string FormattedTime => StartTime.ToString("HH:mm:ss.fff");
    public string FormattedUp => FormatBytes(BytesUp);
    public string FormattedDown => FormatBytes(BytesDown);

    public long RawBytesUp => Interlocked.Read(ref _rawBytesUp);
    public long RawBytesDown => Interlocked.Read(ref _rawBytesDown);
    public int RawLatencyMs => Volatile.Read(ref _rawLatencyMs);
    public string RawStatus => Volatile.Read(ref _rawStatus);
    public string RawErrorMessage => Volatile.Read(ref _rawErrorMessage);

    public void AddBytesUp(long delta)
    {
        Interlocked.Add(ref _rawBytesUp, delta);
        Volatile.Write(ref _dirty, 1);
    }

    public void AddBytesDown(long delta)
    {
        Interlocked.Add(ref _rawBytesDown, delta);
        Volatile.Write(ref _dirty, 1);
    }

    public void UpdateState(string status, int? latencyMs = null, string? error = null)
    {
        Volatile.Write(ref _rawStatus, status);
        if (latencyMs.HasValue)
        {
            Volatile.Write(ref _rawLatencyMs, latencyMs.Value);
        }
        if (error is not null)
        {
            Volatile.Write(ref _rawErrorMessage, error);
        }
        Volatile.Write(ref _dirty, 1);
    }

    public void ApplySnapshot(string status, int latencyMs, long bytesUp, long bytesDown, string error)
    {
        Volatile.Write(ref _rawStatus, status);
        Volatile.Write(ref _rawLatencyMs, latencyMs);
        Interlocked.Exchange(ref _rawBytesUp, bytesUp);
        Interlocked.Exchange(ref _rawBytesDown, bytesDown);
        Volatile.Write(ref _rawErrorMessage, error);
        Volatile.Write(ref _dirty, 1);
    }

    public void SyncToUi()
    {
        if (Interlocked.Exchange(ref _dirty, 0) == 0) return;
        Status = Volatile.Read(ref _rawStatus);
        LatencyMs = Volatile.Read(ref _rawLatencyMs);
        BytesUp = Interlocked.Read(ref _rawBytesUp);
        BytesDown = Interlocked.Read(ref _rawBytesDown);
        ErrorMessage = Volatile.Read(ref _rawErrorMessage);
    }

    public static string FormatBytes(long bytes)
    {
        if (bytes < 1024) return $"{bytes} B";
        if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
        if (bytes < 1024L * 1024 * 1024) return $"{bytes / (1024.0 * 1024.0):F2} MB";
        return $"{bytes / (1024.0 * 1024.0 * 1024.0):F2} GB";
    }
}

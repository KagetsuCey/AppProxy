using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Data;
using System.Windows.Threading;
using AppProxy.UI.Models;
using AppProxy.UI.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Wpf.Ui.Appearance;

namespace AppProxy.UI.ViewModels;

public partial class MainViewModel : ObservableObject, IDisposable
{
    private readonly ConfigService _configService;
    private readonly AppLauncherService _launcher;
    private readonly DispatcherTimer _uiFlushTimer;
    private readonly ConcurrentQueue<BridgeConnectionDto> _pendingConnectionUpserts = new();
    private readonly ConcurrentQueue<ProcessEventRecord> _pendingEvents = new();
    private readonly Dictionary<(uint BridgePid, long Id), ConnectionRecord> _connectionIndex = new();
    private AppConfig _config;
    private bool _isInitializing = true;

    public ObservableCollection<ProxyProfile> Proxies { get; } = new();
    public ObservableCollection<AppProfile> Apps { get; } = new();
    public ObservableCollection<ConnectionRecord> Connections { get; } = new();
    public ObservableCollection<ProcessEventRecord> ProcessEvents { get; } = new();

    public ICollectionView FilteredApps { get; }
    public ICollectionView FilteredConnections { get; }

    public string ConfigFilePath => _configService.ConfigPath;
    public string DataDirectoryPath => AppPaths.GetDataDirectory();

    [ObservableProperty]
    private int _selectedNavIndex;

    [ObservableProperty]
    private int _selectedMonitorTabIndex;

    [ObservableProperty]
    private string _appSearchText = string.Empty;

    [ObservableProperty]
    private string _connectionSearchText = string.Empty;

    [ObservableProperty]
    private string _bridgeStatusText = "独立后台桥接就绪 (按需随应用启动)";

    [ObservableProperty]
    private int _activeBridgesCount;

    [ObservableProperty]
    private bool _hasActiveBridges;

    [ObservableProperty]
    private int _activeConnectionsCount;

    [ObservableProperty]
    private string _totalBytesUpFormatted = "0 B";

    [ObservableProperty]
    private string _totalBytesDownFormatted = "0 B";

    [ObservableProperty]
    private string _statusMessage = "Ready";

    [ObservableProperty]
    private bool _isDarkTheme = true;

    [ObservableProperty]
    private string _testProbeHost = "www.gstatic.com";

    [ObservableProperty]
    private int _testProbePort = 80;

    public MainViewModel()
    {
        _configService = new ConfigService();
        _config = _configService.Load();

        _launcher = new AppLauncherService();
        _launcher.ConnectionUpserted += dto => _pendingConnectionUpserts.Enqueue(dto);
        _launcher.ProcessEventReceived += ev => _pendingEvents.Enqueue(ev);
        _launcher.BridgeStatusUpdated += _ => RefreshBridgeSummary();
        _launcher.BridgeDisconnected += bridgePid =>
        {
            RefreshBridgeSummary();
            MarkBridgeConnectionsClosed(bridgePid);
        };

        IsDarkTheme = _config.IsDarkTheme;
        TestProbeHost = string.IsNullOrWhiteSpace(_config.TestProbeHost) ? "www.gstatic.com" : _config.TestProbeHost;
        TestProbePort = _config.TestProbePort is > 0 and <= 65535 ? _config.TestProbePort : 80;

        foreach (var proxy in _config.Proxies)
        {
            Proxies.Add(proxy);
        }

        foreach (var app in _config.Apps)
        {
            HydrateAppMetadata(app);
            Apps.Add(app);
        }

        FilteredApps = CollectionViewSource.GetDefaultView(Apps);
        FilteredApps.Filter = FilterAppPredicate;

        FilteredConnections = CollectionViewSource.GetDefaultView(Connections);
        FilteredConnections.Filter = FilterConnectionPredicate;

        RefreshBridgeSummary();

        _uiFlushTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromMilliseconds(100)
        };
        _uiFlushTimer.Tick += OnFlushTimerTick;
        _uiFlushTimer.Start();
        _isInitializing = false;
    }

    partial void OnAppSearchTextChanged(string value) => FilteredApps.Refresh();
    partial void OnConnectionSearchTextChanged(string value) => FilteredConnections.Refresh();

    partial void OnIsDarkThemeChanged(bool value)
    {
        if (Application.Current is not null)
        {
            var theme = value ? ApplicationTheme.Dark : ApplicationTheme.Light;
            try
            {
                ApplicationThemeManager.Apply(theme, Wpf.Ui.Controls.WindowBackdropType.Mica, updateAccent: false);
            }
            catch
            {
                try
                {
                    ApplicationThemeManager.Apply(theme, Wpf.Ui.Controls.WindowBackdropType.None, updateAccent: false);
                }
                catch
                {
                }
            }
            ThemeTokenHelper.ApplySemanticTokens(value);
        }
        if (!_isInitializing)
        {
            SaveConfiguration();
        }
    }

    private void RefreshBridgeSummary()
    {
        var bridges = _launcher.ActiveBridges;
        int totalActive = bridges.Sum(b => b.ActiveConnections);
        ActiveBridgesCount = bridges.Count;
        HasActiveBridges = bridges.Count > 0;
        ActiveConnectionsCount = totalActive;

        if (bridges.Count == 0)
        {
            BridgeStatusText = "独立后台桥接就绪 (按需随应用启动)";
        }
        else if (bridges.Count == 1)
        {
            var b = bridges.First();
            string endpoint = b.PortV6 != 0
                ? $"127.0.0.1:{b.PortV4} | [::1]:{b.PortV6}"
                : $"127.0.0.1:{b.PortV4}";
            BridgeStatusText = $"后台桥接 #{b.BridgePid} ({b.AppName}) · {endpoint}";
        }
        else
        {
            BridgeStatusText = $"后台桥接运行中: {bridges.Count} 个独立实例";
        }
    }

    private void RefreshTrafficTotals()
    {
        long totalUp = 0;
        long totalDown = 0;
        foreach (var conn in Connections)
        {
            totalUp += conn.BytesUp;
            totalDown += conn.BytesDown;
        }
        TotalBytesUpFormatted = ConnectionRecord.FormatBytes(totalUp);
        TotalBytesDownFormatted = ConnectionRecord.FormatBytes(totalDown);
    }

    private void MarkBridgeConnectionsClosed(uint bridgePid)
    {
        foreach (var kv in _connectionIndex)
        {
            if (kv.Key.BridgePid == bridgePid &&
                (kv.Value.RawStatus == "Connecting" || kv.Value.RawStatus == "Active"))
            {
                kv.Value.UpdateState("Closed");
            }
        }
    }

    private bool FilterAppPredicate(object obj)
    {
        if (obj is not AppProfile app) return false;
        if (string.IsNullOrWhiteSpace(AppSearchText)) return true;
        return app.Name.Contains(AppSearchText, StringComparison.OrdinalIgnoreCase) ||
               app.ExePath.Contains(AppSearchText, StringComparison.OrdinalIgnoreCase);
    }

    private bool FilterConnectionPredicate(object obj)
    {
        if (obj is not ConnectionRecord conn) return false;
        if (string.IsNullOrWhiteSpace(ConnectionSearchText)) return true;
        return conn.ProcessName.Contains(ConnectionSearchText, StringComparison.OrdinalIgnoreCase) ||
               conn.TargetDisplay.Contains(ConnectionSearchText, StringComparison.OrdinalIgnoreCase) ||
               conn.ProxyName.Contains(ConnectionSearchText, StringComparison.OrdinalIgnoreCase) ||
               conn.Status.Contains(ConnectionSearchText, StringComparison.OrdinalIgnoreCase);
    }

    private void OnFlushTimerTick(object? sender, EventArgs e)
    {
        int connProcessed = 0;
        while (connProcessed < 128 && _pendingConnectionUpserts.TryDequeue(out var dto))
        {
            var key = (dto.BridgePid, dto.Id);
            if (_connectionIndex.TryGetValue(key, out var existing))
            {
                existing.ApplySnapshot(dto.Status, dto.LatencyMs, dto.BytesUp, dto.BytesDown, dto.ErrorMessage);
                existing.SyncToUi();
            }
            else
            {
                var rec = dto.ToRecord();
                rec.SyncToUi();
                _connectionIndex[key] = rec;
                Connections.Insert(0, rec);
            }
            connProcessed++;
        }

        while (Connections.Count > 2000)
        {
            var last = Connections[^1];
            _connectionIndex.Remove((last.BridgePid, last.Id));
            Connections.RemoveAt(Connections.Count - 1);
        }

        int evAdded = 0;
        while (evAdded < 64 && _pendingEvents.TryDequeue(out var ev))
        {
            ProcessEvents.Insert(0, ev);
            evAdded++;
        }
        while (ProcessEvents.Count > 2000)
        {
            ProcessEvents.RemoveAt(ProcessEvents.Count - 1);
        }

        foreach (var conn in Connections)
        {
            conn.SyncToUi();
        }

        RefreshTrafficTotals();
        RefreshBridgeSummary();
    }

    public void HydrateAppMetadata(AppProfile app)
    {
        if (File.Exists(app.ExePath))
        {
            app.DetectedArch = PeInspector.DetectArchitecture(app.ExePath);
            app.Icon = PeInspector.ExtractIcon(app.ExePath);
        }
        SyncAppBoundProxyName(app);
    }

    public void SyncAppBoundProxyName(AppProfile app)
    {
        if (app.ProxyProfileId is null)
        {
            app.BoundProxyName = "Direct";
            return;
        }
        var found = Proxies.FirstOrDefault(p => p.Id == app.ProxyProfileId);
        app.BoundProxyName = found?.Name ?? "Direct";
    }

    public void AddOrUpdateApp(AppProfile edited)
    {
        HydrateAppMetadata(edited);
        var existing = Apps.FirstOrDefault(a => a.Id == edited.Id);
        if (existing is not null)
        {
            int idx = Apps.IndexOf(existing);
            Apps[idx] = edited;
        }
        else
        {
            Apps.Add(edited);
        }
        SaveConfiguration();
        StatusMessage = $"Saved application: {edited.Name}";
    }

    public void AddQuickAppFromPath(string filePath)
    {
        var resolved = ShortcutResolver.ResolveInputPath(filePath);
        if (!resolved.Ok)
        {
            StatusMessage = resolved.Error ?? "Please drop a valid .exe executable or .lnk shortcut.";
            return;
        }

        var defaultProxy = Proxies.FirstOrDefault();
        var app = new AppProfile
        {
            Name = resolved.DisplayName,
            ExePath = resolved.TargetExePath,
            Arguments = resolved.Arguments,
            WorkingDirectory = resolved.WorkingDirectory,
            ProxyProfileId = defaultProxy?.Id,
            RemoteDns = true,
            BypassLan = true,
            InjectChildren = true,
            IgnoreSystemProxy = true,
            MaxInstances = 1,
            IsolateProfileDir = AppProfile.IsChromiumBrowserExe(resolved.TargetExePath)
        };
        AddOrUpdateApp(app);
    }

    [RelayCommand]
    private void DeleteApp(AppProfile? app)
    {
        if (app is null) return;
        Apps.Remove(app);
        SaveConfiguration();
        StatusMessage = $"Removed application: {app.Name}";
    }

    [RelayCommand]
    private async Task LaunchAppAsync(AppProfile? app)
    {
        if (app is null) return;
        SaveConfiguration();
        ProxyProfile? proxy = app.ProxyProfileId is not null
            ? Proxies.FirstOrDefault(p => p.Id == app.ProxyProfileId)
            : null;

        StatusMessage = $"Launching standalone bridge and injecting {app.Name}...";
        var (ok, _, msg) = await _launcher.LaunchAppAsync(app, proxy);
        StatusMessage = msg;
        if (!ok)
        {
            System.Windows.MessageBox.Show(msg, "AppProxy 启动提示", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    [RelayCommand]
    private void CreateDesktopShortcut(AppProfile? app)
    {
        if (app is null) return;
        try
        {
            SaveConfiguration();
            string shortcutPath = ShortcutResolver.CreateAppDesktopShortcut(app);
            StatusMessage = $"已在桌面创建快捷方式: {Path.GetFileName(shortcutPath)}";
        }
        catch (Exception ex)
        {
            string err = $"创建桌面快捷方式失败: {ex.Message}";
            StatusMessage = err;
            System.Windows.MessageBox.Show(err, "AppProxy", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    public void AddOrUpdateProxy(ProxyProfile edited)
    {
        var existing = Proxies.FirstOrDefault(p => p.Id == edited.Id);
        if (existing is not null)
        {
            int idx = Proxies.IndexOf(existing);
            Proxies[idx] = edited;
        }
        else
        {
            Proxies.Add(edited);
        }

        foreach (var app in Apps)
        {
            SyncAppBoundProxyName(app);
        }
        SaveConfiguration();
        StatusMessage = $"Saved proxy: {edited.Name}";
    }

    [RelayCommand]
    private void DeleteProxy(ProxyProfile? proxy)
    {
        if (proxy is null) return;
        Proxies.Remove(proxy);
        foreach (var app in Apps.Where(a => a.ProxyProfileId == proxy.Id))
        {
            app.ProxyProfileId = null;
            SyncAppBoundProxyName(app);
        }
        SaveConfiguration();
        StatusMessage = $"Removed proxy: {proxy.Name}";
    }

    [RelayCommand]
    private async Task TestProxyAsync(ProxyProfile? proxy)
    {
        if (proxy is null || proxy.IsTesting) return;
        await ProxyTester.TestProxyAsync(proxy, TestProbeHost, TestProbePort);
        StatusMessage = $"Tested {proxy.Name}: {proxy.LatencyDisplay}";
    }

    [RelayCommand]
    private async Task TestAllProxiesAsync()
    {
        var tasks = Proxies.Select(p => ProxyTester.TestProxyAsync(p, TestProbeHost, TestProbePort));
        await Task.WhenAll(tasks);
        StatusMessage = "Finished testing all proxies.";
    }

    [RelayCommand]
    private void ClearConnections()
    {
        _connectionIndex.Clear();
        Connections.Clear();
        RefreshTrafficTotals();
    }

    [RelayCommand]
    private void ClearProcessEvents()
    {
        ProcessEvents.Clear();
    }

    [RelayCommand]
    private void ToggleTheme()
    {
        IsDarkTheme = !IsDarkTheme;
    }

    [RelayCommand]
    private void CopyConfigFilePath()
    {
        try
        {
            Clipboard.SetText(ConfigFilePath);
            StatusMessage = "已复制配置文件路径到剪贴板";
        }
        catch
        {
            StatusMessage = "复制配置文件路径失败";
        }
    }

    [RelayCommand]
    private void OpenDataDirectory()
    {
        try
        {
            string dataDir = AppPaths.EnsureDataDirectoryExists();
            Process.Start(new ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = $"\"{dataDir}\"",
                UseShellExecute = true
            });
            StatusMessage = $"已打开数据目录: {dataDir}";
        }
        catch (Exception ex)
        {
            StatusMessage = $"打开数据目录失败: {ex.Message}";
        }
    }

    [RelayCommand]
    public void SaveConfiguration()
    {
        _config.Proxies = Proxies.ToList();
        _config.Apps = Apps.ToList();
        _config.IsDarkTheme = IsDarkTheme;
        _config.TestProbeHost = TestProbeHost;
        _config.TestProbePort = TestProbePort;
        _configService.Save(_config);
    }

    public void Dispose()
    {
        _uiFlushTimer.Stop();
        _launcher.Dispose();
    }
}

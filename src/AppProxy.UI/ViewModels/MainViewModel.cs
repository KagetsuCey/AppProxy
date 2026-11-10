using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.ComponentModel;
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
    private readonly SharedMemoryService _shm;
    private readonly LocalProxyBridge _bridge;
    private readonly AppLauncherService _launcher;
    private readonly DispatcherTimer _uiFlushTimer;
    private readonly ConcurrentQueue<ConnectionRecord> _pendingConnections = new();
    private readonly ConcurrentQueue<ProcessEventRecord> _pendingEvents = new();
    private AppConfig _config;

    public ObservableCollection<ProxyProfile> Proxies { get; } = new();
    public ObservableCollection<AppProfile> Apps { get; } = new();
    public ObservableCollection<ConnectionRecord> Connections { get; } = new();
    public ObservableCollection<ProcessEventRecord> ProcessEvents { get; } = new();

    public ICollectionView FilteredApps { get; }
    public ICollectionView FilteredConnections { get; }

    [ObservableProperty]
    private int _selectedNavIndex;

    [ObservableProperty]
    private int _selectedMonitorTabIndex;

    [ObservableProperty]
    private string _appSearchText = string.Empty;

    [ObservableProperty]
    private string _connectionSearchText = string.Empty;

    [ObservableProperty]
    private string _bridgeStatusText = string.Empty;

    [ObservableProperty]
    private int _activeConnectionsCount;

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

        _shm = new SharedMemoryService();
        _bridge = new LocalProxyBridge(_shm);
        _launcher = new AppLauncherService(_shm, _bridge);

        _bridge.ConnectionCreated += rec => _pendingConnections.Enqueue(rec);
        _launcher.ProcessEventReceived += ev => _pendingEvents.Enqueue(ev);

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

        BridgeStatusText = _bridge.PortV6 != 0
            ? $"Bridge 127.0.0.1:{_bridge.PortV4} | [::1]:{_bridge.PortV6}"
            : $"Bridge 127.0.0.1:{_bridge.PortV4}";

        _uiFlushTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromMilliseconds(100)
        };
        _uiFlushTimer.Tick += OnFlushTimerTick;
        _uiFlushTimer.Start();
    }

    partial void OnAppSearchTextChanged(string value) => FilteredApps.Refresh();
    partial void OnConnectionSearchTextChanged(string value) => FilteredConnections.Refresh();

    partial void OnIsDarkThemeChanged(bool value)
    {
        ApplicationThemeManager.Apply(value ? ApplicationTheme.Dark : ApplicationTheme.Light);
        SaveConfiguration();
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
        int connAdded = 0;
        while (connAdded < 64 && _pendingConnections.TryDequeue(out var conn))
        {
            Connections.Insert(0, conn);
            connAdded++;
        }
        while (Connections.Count > 2000)
        {
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

        ActiveConnectionsCount = _bridge.ActiveConnections;
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

    public void AddQuickAppFromPath(string exePath)
    {
        if (!File.Exists(exePath) || !exePath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            StatusMessage = "Please drop a valid .exe executable.";
            return;
        }

        var defaultProxy = Proxies.FirstOrDefault();
        var app = new AppProfile
        {
            Name = Path.GetFileNameWithoutExtension(exePath),
            ExePath = exePath,
            WorkingDirectory = Path.GetDirectoryName(exePath) ?? string.Empty,
            ProxyProfileId = defaultProxy?.Id,
            RemoteDns = true,
            BypassLan = true,
            InjectChildren = true
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

        StatusMessage = $"Injecting and launching {app.Name}...";
        var (ok, _, msg) = await _launcher.LaunchAppAsync(app, proxy);
        StatusMessage = msg;
        if (!ok)
        {
            System.Windows.MessageBox.Show(msg, "AppProxy Launch Error", MessageBoxButton.OK, MessageBoxImage.Warning);
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
        Connections.Clear();
    }

    [RelayCommand]
    private void ClearProcessEvents()
    {
        ProcessEvents.Clear();
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
        _bridge.Dispose();
        _shm.Dispose();
    }
}

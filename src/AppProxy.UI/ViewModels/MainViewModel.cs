using System.Collections;
using System.Collections.Concurrent;
using System.Collections.ObjectModel;
using System.Collections.Specialized;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Windows;
using System.Windows.Data;
using System.Windows.Threading;
using AppProxy.Core.Models;
using AppProxy.Core.Services;
using AppProxy.UI.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using CommunityToolkit.Mvvm.Input;
using Wpf.Ui.Appearance;

namespace AppProxy.UI.ViewModels;

public sealed record OutboundInterfaceChoice(string Id, string DisplayName);

public partial class MainViewModel : ObservableObject, IDisposable
{
    private readonly record struct ConnectionQueueItem(BridgeConnectionDto? Upsert, uint DisconnectBridgePid)
    {
        public bool IsDisconnect => Upsert is null;
        public static ConnectionQueueItem ForUpsert(BridgeConnectionDto dto) => new(dto, 0);
        public static ConnectionQueueItem ForDisconnect(uint bridgePid) => new(null, bridgePid);
    }

    private readonly ConfigService _configService;
    private readonly AppLauncherService _launcher;
    private readonly DispatcherTimer _uiFlushTimer;
    private readonly ConcurrentQueue<ConnectionQueueItem> _pendingConnectionOps = new();
    private readonly ConcurrentQueue<ProcessEventRecord> _pendingEvents = new();
    private readonly Dictionary<(uint BridgePid, long Id), ConnectionRecord> _connectionIndex = new();
    private readonly Dictionary<Guid, int> _exitIpCopyVersions = new();
    private int _bridgeSummaryDirty;
    private AppConfig _config;
    private bool _isInitializing = true;

    public ObservableCollection<ProxyProfile> Proxies { get; } = new();
    public ObservableCollection<AppProfile> Apps { get; } = new();
    public ObservableCollection<ConnectionRecord> Connections { get; } = new();
    public ObservableCollection<ProcessEventRecord> ProcessEvents { get; } = new();
    public ObservableCollection<OutboundInterfaceChoice> OutboundInterfaceChoices { get; } = new();

    public ICollectionView FilteredApps { get; }
    public ICollectionView FilteredProxies { get; }
    public ICollectionView FilteredConnections { get; }
    public ICollectionView FilteredProcessEvents { get; }

    public string ConfigFilePath => _configService.ConfigPath;
    public string DataDirectoryPath => AppPaths.GetDataDirectory();
    public string AppVersionDisplay { get; } = ResolveAppVersionDisplay();

    [ObservableProperty]
    private int _selectedNavIndex;

    [ObservableProperty]
    private int _selectedMonitorTabIndex;

    [ObservableProperty]
    private string _appSearchText = string.Empty;

    [ObservableProperty]
    private string _proxySearchText = string.Empty;

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

    [ObservableProperty]
    private bool _bypassGlobalTun = true;

    [ObservableProperty]
    private string _preferredOutboundInterface = string.Empty;

    [ObservableProperty]
    private string _outboundNetworkSummary = string.Empty;

    [ObservableProperty]
    private string _outboundStatusLevel = "Ok";

    [ObservableProperty]
    private string _outboundHeadline = "物理出口自动探测中...";

    [ObservableProperty]
    private string _outboundShortStatus = "自动探测";

    [ObservableProperty]
    private string _outboundTunBadgeText = "当前未检测到活跃 TUN";

    [ObservableProperty]
    private bool _hasActiveTun;

    [ObservableProperty]
    private string _xrayCorePath = string.Empty;

    [ObservableProperty]
    private bool _isXrayCoreAvailable;

    [ObservableProperty]
    private string _xrayCoreState = "Unconfigured";

    [ObservableProperty]
    private string _xrayCoreVersionShort = "未配置";

    [ObservableProperty]
    private string _xrayCoreBadgeText = "未配置";

    [ObservableProperty]
    private string _xrayCoreHeadline = "未配置 Xray-core（仅开放原生 SOCKS5 / HTTP / HTTPS）";

    [ObservableProperty]
    private string _xrayCoreDetailText = string.Empty;

    [ObservableProperty]
    private string _xrayCoreStatusText = "未配置 Xray-core（仅开放原生 SOCKS5 / HTTP / HTTPS）";

    [ObservableProperty]
    private bool _isDownloadingXray;

    [ObservableProperty]
    private string _xrayDownloadStatusText = string.Empty;

    [ObservableProperty]
    private double _xrayDownloadProgressPercent;

    private CancellationTokenSource? _xrayDownloadCts;
    private bool _isSyncingSelectionState;

    [ObservableProperty]
    private string _proxyProtocolFilter = "All";

    [ObservableProperty]
    private string _proxySortMode = "Default";

    [ObservableProperty]
    private int _filteredProxyCount;

    [ObservableProperty]
    private bool _hasActiveProxyFilter;

    [ObservableProperty]
    private bool _showProxyFilterEmptyState;

    [ObservableProperty]
    private int _selectedProxyCount;

    [ObservableProperty]
    private bool _hasSelectedProxies;

    [ObservableProperty]
    private string _exportProxyButtonText = "导出";

    [ObservableProperty]
    private bool _areAllVisibleProxiesSelected;

    [ObservableProperty]
    private int _availableProxyCount;

    [ObservableProperty]
    private int _testedProxyCount;

    [ObservableProperty]
    private int _exitDetectedProxyCount;

    [ObservableProperty]
    private string _proxyLatencySummaryText = "尚未测速";

    [ObservableProperty]
    private string _proxyProtocolBreakdownText = "暂无节点";

    [ObservableProperty]
    private string _proxyPageSubtitle = "管理 SOCKS5 / HTTP / HTTPS 上游代理节点，测试握手延迟、识别出口 IP 并支持勾选导出";

    [ObservableProperty]
    private string _appBindingFilter = "All";

    [ObservableProperty]
    private string _appArchFilter = "All";

    [ObservableProperty]
    private int _filteredAppCount;

    [ObservableProperty]
    private bool _hasActiveAppFilter;

    [ObservableProperty]
    private bool _showAppFilterEmptyState;

    [ObservableProperty]
    private int _boundProxyAppsCount;

    [ObservableProperty]
    private int _directAppsCount;

    [ObservableProperty]
    private int _isolatedAppsCount;

    [ObservableProperty]
    private int _fakeIpAppsCount;

    [ObservableProperty]
    private string _appArchBreakdownText = "暂无应用";

    [ObservableProperty]
    private string _appBindingSummaryText = "0 已绑定 · 0 直连";

    [ObservableProperty]
    private string _appPolicySummaryText = "0 Fake-IP · 0 独立目录";

    [ObservableProperty]
    private string _connectionStatusFilter = "All";

    [ObservableProperty]
    private string _eventCategoryFilter = "All";

    [ObservableProperty]
    private bool _hasActiveMonitorFilter;

    public MainViewModel()
    {
        _configService = new ConfigService();
        _config = _configService.Load();

        _launcher = new AppLauncherService();
        _launcher.ConnectionUpserted += EnqueueConnectionUpsert;
        _launcher.ProcessEventReceived += ev => _pendingEvents.Enqueue(ev);
        _launcher.BridgeStatusUpdated += _ => Volatile.Write(ref _bridgeSummaryDirty, 1);
        _launcher.BridgeDisconnected += EnqueueBridgeDisconnect;

        IsDarkTheme = _config.IsDarkTheme;
        TestProbeHost = string.IsNullOrWhiteSpace(_config.TestProbeHost) ? "www.gstatic.com" : _config.TestProbeHost;
        TestProbePort = _config.TestProbePort is > 0 and <= 65535 ? _config.TestProbePort : 80;
        BypassGlobalTun = _config.BypassGlobalTun;
        PreferredOutboundInterface = _config.PreferredOutboundInterface ?? string.Empty;
        XrayCorePath = _config.XrayCorePath ?? string.Empty;
        RefreshOutboundInterfacesCore();
        PhysicalNetworkSelector.NetworkChanged += OnPhysicalNetworkChanged;
        _ = RefreshXrayCoreStatusAsync();
        _ = Task.Run(() => ProcessInstanceCounter.CleanupLegacyLockFiles());

        foreach (var proxy in _config.Proxies)
        {
            proxy.PropertyChanged += OnProxyItemPropertyChanged;
            Proxies.Add(proxy);
        }
        Proxies.CollectionChanged += OnProxiesCollectionChanged;

        foreach (var app in _config.Apps)
        {
            HydrateAppMetadata(app);
            Apps.Add(app);
        }
        Apps.CollectionChanged += (_, _) => RefreshAppStats();

        FilteredApps = CollectionViewSource.GetDefaultView(Apps);
        FilteredApps.Filter = FilterAppPredicate;

        FilteredProxies = CollectionViewSource.GetDefaultView(Proxies);
        FilteredProxies.Filter = FilterProxyPredicate;

        FilteredConnections = CollectionViewSource.GetDefaultView(Connections);
        FilteredConnections.Filter = FilterConnectionPredicate;

        FilteredProcessEvents = CollectionViewSource.GetDefaultView(ProcessEvents);
        FilteredProcessEvents.Filter = FilterProcessEventPredicate;

        UpdateProxyPageSubtitle();
        RefreshAppStats();
        RefreshProxyStatsAndSelection();
        RefreshBridgeSummary();

        _uiFlushTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromMilliseconds(100)
        };
        _uiFlushTimer.Tick += OnFlushTimerTick;
        _uiFlushTimer.Start();
        _isInitializing = false;
    }

    partial void OnAppSearchTextChanged(string value) => ApplyAppFilter();
    partial void OnAppBindingFilterChanged(string value) => ApplyAppFilter();
    partial void OnAppArchFilterChanged(string value) => ApplyAppFilter();
    partial void OnProxySearchTextChanged(string value) => ApplyProxyFilterAndSort();
    partial void OnProxyProtocolFilterChanged(string value) => ApplyProxyFilterAndSort();
    partial void OnProxySortModeChanged(string value) => ApplyProxyFilterAndSort();
    partial void OnIsXrayCoreAvailableChanged(bool value) => UpdateProxyPageSubtitle();
    partial void OnConnectionSearchTextChanged(string value) => ApplyMonitorFilters();
    partial void OnConnectionStatusFilterChanged(string value) => ApplyMonitorFilters();
    partial void OnEventCategoryFilterChanged(string value) => ApplyMonitorFilters();

    partial void OnAreAllVisibleProxiesSelectedChanged(bool value)
    {
        if (_isSyncingSelectionState) return;

        _isSyncingSelectionState = true;
        try
        {
            foreach (ProxyProfile proxy in FilteredProxies.Cast<ProxyProfile>().ToList())
            {
                proxy.IsSelected = value;
            }
        }
        finally
        {
            _isSyncingSelectionState = false;
        }

        RefreshProxyStatsAndSelection();
    }

    partial void OnBypassGlobalTunChanged(bool value)
    {
        UpdateOutboundNetworkSummary();
        if (!_isInitializing)
        {
            SaveConfiguration();
        }
    }

    partial void OnPreferredOutboundInterfaceChanged(string value)
    {
        UpdateOutboundNetworkSummary();
        if (!_isInitializing)
        {
            SaveConfiguration();
        }
    }

    partial void OnXrayCorePathChanged(string value)
    {
        if (!_isInitializing)
        {
            SaveConfiguration();
            _ = RefreshXrayCoreStatusAsync();
        }
    }

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

        if (string.Equals(AppBindingFilter, "Proxied", StringComparison.OrdinalIgnoreCase) && app.ProxyProfileId is null)
        {
            return false;
        }
        if (string.Equals(AppBindingFilter, "Direct", StringComparison.OrdinalIgnoreCase) && app.ProxyProfileId is not null)
        {
            return false;
        }

        if (!string.Equals(AppArchFilter, "All", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(app.DetectedArch, AppArchFilter, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(AppSearchText)) return true;
        return app.Name.Contains(AppSearchText, StringComparison.OrdinalIgnoreCase) ||
               app.ExePath.Contains(AppSearchText, StringComparison.OrdinalIgnoreCase) ||
               app.BoundProxyName.Contains(AppSearchText, StringComparison.OrdinalIgnoreCase) ||
               app.DetectedArch.Contains(AppSearchText, StringComparison.OrdinalIgnoreCase);
    }

    private void ApplyAppFilter()
    {
        FilteredApps.Refresh();
        RefreshAppStats();
    }

    private void RefreshAppStats()
    {
        var all = Apps.ToList();
        int total = all.Count;
        int visibleCount = FilteredApps.Cast<object>().Count();

        bool activeFilter = !string.IsNullOrWhiteSpace(AppSearchText) ||
                            !string.Equals(AppBindingFilter, "All", StringComparison.OrdinalIgnoreCase) ||
                            !string.Equals(AppArchFilter, "All", StringComparison.OrdinalIgnoreCase);

        FilteredAppCount = visibleCount;
        HasActiveAppFilter = activeFilter;
        ShowAppFilterEmptyState = total > 0 && visibleCount == 0;

        int bound = all.Count(a => a.ProxyProfileId is not null);
        int direct = total - bound;
        int isolated = all.Count(a => a.EffectiveIsolateProfileDir);
        int fakeIp = all.Count(a => a.RemoteDns);
        int x64Count = all.Count(a => string.Equals(a.DetectedArch, "x64", StringComparison.OrdinalIgnoreCase));
        int x86Count = all.Count(a => string.Equals(a.DetectedArch, "x86", StringComparison.OrdinalIgnoreCase));

        BoundProxyAppsCount = bound;
        DirectAppsCount = direct;
        IsolatedAppsCount = isolated;
        FakeIpAppsCount = fakeIp;
        AppBindingSummaryText = $"{bound} 已绑定 · {direct} 直连";
        AppPolicySummaryText = $"{fakeIp} Fake-IP · {isolated} 独立目录";

        if (total == 0)
        {
            AppArchBreakdownText = "暂无应用";
        }
        else
        {
            var archParts = new List<string>(2);
            if (x64Count > 0) archParts.Add($"x64 {x64Count}");
            if (x86Count > 0) archParts.Add($"x86 {x86Count}");
            AppArchBreakdownText = archParts.Count > 0 ? string.Join(" · ", archParts) : $"{total} 个应用";
        }
    }

    private bool FilterProxyPredicate(object obj)
    {
        if (obj is not ProxyProfile proxy) return false;

        if (!string.Equals(ProxyProtocolFilter, "All", StringComparison.OrdinalIgnoreCase))
        {
            if (!Enum.TryParse<ProxyProtocol>(ProxyProtocolFilter, ignoreCase: true, out var requiredProto) ||
                proxy.Protocol != requiredProto)
            {
                return false;
            }
        }

        if (string.IsNullOrWhiteSpace(ProxySearchText)) return true;
        return proxy.Name.Contains(ProxySearchText, StringComparison.OrdinalIgnoreCase) ||
               proxy.Host.Contains(ProxySearchText, StringComparison.OrdinalIgnoreCase) ||
               proxy.EndpointDisplay.Contains(ProxySearchText, StringComparison.OrdinalIgnoreCase) ||
               proxy.ProtocolDisplay.Contains(ProxySearchText, StringComparison.OrdinalIgnoreCase) ||
               proxy.SecurityBadgeText.Contains(ProxySearchText, StringComparison.OrdinalIgnoreCase) ||
               (proxy.Vless?.Sni.Contains(ProxySearchText, StringComparison.OrdinalIgnoreCase) ?? false) ||
               proxy.ExitIp.Contains(ProxySearchText, StringComparison.OrdinalIgnoreCase) ||
               proxy.ExitLocation.Contains(ProxySearchText, StringComparison.OrdinalIgnoreCase) ||
               proxy.ExitCountryCode.Contains(ProxySearchText, StringComparison.OrdinalIgnoreCase) ||
               proxy.ExitIsp.Contains(ProxySearchText, StringComparison.OrdinalIgnoreCase);
    }

    private void OnProxiesCollectionChanged(object? sender, NotifyCollectionChangedEventArgs e)
    {
        if (e.OldItems is not null)
        {
            foreach (ProxyProfile oldItem in e.OldItems.OfType<ProxyProfile>())
            {
                oldItem.PropertyChanged -= OnProxyItemPropertyChanged;
            }
        }

        if (e.NewItems is not null)
        {
            foreach (ProxyProfile newItem in e.NewItems.OfType<ProxyProfile>())
            {
                newItem.PropertyChanged += OnProxyItemPropertyChanged;
            }
        }

        RefreshProxyStatsAndSelection();
    }

    private void OnProxyItemPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(ProxyProfile.IsSelected) && _isSyncingSelectionState)
        {
            return;
        }

        if (e.PropertyName is not (
            nameof(ProxyProfile.IsSelected) or
            nameof(ProxyProfile.LastLatencyMs) or
            nameof(ProxyProfile.LastTestStatus) or
            nameof(ProxyProfile.IsTesting) or
            nameof(ProxyProfile.ExitIp) or
            nameof(ProxyProfile.Protocol)))
        {
            return;
        }

        Dispatcher? dispatcher = Application.Current?.Dispatcher;
        if (dispatcher is not null && !dispatcher.CheckAccess())
        {
            _ = dispatcher.BeginInvoke(() => RefreshProxyStatsAndSelection());
            return;
        }

        RefreshProxyStatsAndSelection();
    }

    private void ApplyProxyFilterAndSort()
    {
        if (FilteredProxies is ListCollectionView lcv)
        {
            lcv.CustomSort = ProxySortMode switch
            {
                "Latency" => ProxyLatencyComparer.Instance,
                "Name" => ProxyNameComparer.Instance,
                _ => null
            };
        }

        FilteredProxies.Refresh();
        RefreshProxyStatsAndSelection();
    }

    private void UpdateProxyPageSubtitle()
    {
        ProxyPageSubtitle = IsXrayCoreAvailable
            ? "管理 SOCKS5 / HTTP / HTTPS / VLESS 上游代理节点，测试握手延迟、识别出口 IP 并支持勾选导出"
            : "管理 SOCKS5 / HTTP / HTTPS 上游代理节点，测试握手延迟、识别出口 IP 并支持勾选导出";
    }

    private void RefreshProxyStatsAndSelection()
    {
        var all = Proxies.ToList();
        int total = all.Count;

        var visible = FilteredProxies.Cast<ProxyProfile>().ToList();
        int visibleCount = visible.Count;

        bool activeFilter = !string.IsNullOrWhiteSpace(ProxySearchText) ||
                            !string.Equals(ProxyProtocolFilter, "All", StringComparison.OrdinalIgnoreCase);

        FilteredProxyCount = visibleCount;
        HasActiveProxyFilter = activeFilter;
        ShowProxyFilterEmptyState = total > 0 && visibleCount == 0;

        int selectedCount = all.Count(p => p.IsSelected);
        SelectedProxyCount = selectedCount;
        HasSelectedProxies = selectedCount > 0;

        ExportProxyButtonText = selectedCount > 0
            ? $"导出 ({selectedCount})"
            : activeFilter && visibleCount != total
                ? $"导出筛选 ({visibleCount})"
                : "导出";

        bool allVisibleSelected = visibleCount > 0 && visible.All(p => p.IsSelected);
        if (AreAllVisibleProxiesSelected != allVisibleSelected)
        {
            _isSyncingSelectionState = true;
            try
            {
                AreAllVisibleProxiesSelected = allVisibleSelected;
            }
            finally
            {
                _isSyncingSelectionState = false;
            }
        }

        int available = all.Count(p => p.LastLatencyMs.HasValue);
        int tested = all.Count(p =>
            p.LastLatencyMs.HasValue ||
            !string.Equals(p.LastTestStatus, "Untested", StringComparison.OrdinalIgnoreCase));
        int exitDetected = all.Count(p => !string.IsNullOrWhiteSpace(p.ExitIp));

        AvailableProxyCount = available;
        TestedProxyCount = tested;
        ExitDetectedProxyCount = exitDetected;

        if (total == 0)
        {
            ProxyLatencySummaryText = "暂无节点";
            ProxyProtocolBreakdownText = "暂无节点";
        }
        else
        {
            if (tested == 0)
            {
                ProxyLatencySummaryText = "尚未测速";
            }
            else if (available == 0)
            {
                ProxyLatencySummaryText = $"0 / {total} 可用";
            }
            else
            {
                int minMs = all.Where(p => p.LastLatencyMs.HasValue).Min(p => p.LastLatencyMs!.Value);
                ProxyLatencySummaryText = $"{available} / {total} 可用 · 最快 {minMs} ms";
            }

            var protoCounts = new List<string>(4);
            void AppendProtoCount(ProxyProtocol proto, string label)
            {
                int cnt = all.Count(p => p.Protocol == proto);
                if (cnt > 0) protoCounts.Add($"{label} {cnt}");
            }

            AppendProtoCount(ProxyProtocol.Socks5, "SOCKS5");
            AppendProtoCount(ProxyProtocol.Http, "HTTP");
            AppendProtoCount(ProxyProtocol.Https, "HTTPS");
            AppendProtoCount(ProxyProtocol.Vless, "VLESS");
            ProxyProtocolBreakdownText = protoCounts.Count > 0 ? string.Join(" · ", protoCounts) : "暂无节点";
        }
    }

    private sealed class ProxyLatencyComparer : IComparer
    {
        public static readonly ProxyLatencyComparer Instance = new();

        public int Compare(object? x, object? y)
        {
            if (x is not ProxyProfile a || y is not ProxyProfile b) return 0;

            if (a.LastLatencyMs.HasValue && b.LastLatencyMs.HasValue)
            {
                int msCmp = a.LastLatencyMs.Value.CompareTo(b.LastLatencyMs.Value);
                return msCmp != 0 ? msCmp : string.Compare(a.Name, b.Name, StringComparison.CurrentCultureIgnoreCase);
            }

            if (a.LastLatencyMs.HasValue != b.LastLatencyMs.HasValue)
            {
                return a.LastLatencyMs.HasValue ? -1 : 1;
            }

            int rankA = string.Equals(a.LastTestStatus, "Untested", StringComparison.OrdinalIgnoreCase) ? 1 : 2;
            int rankB = string.Equals(b.LastTestStatus, "Untested", StringComparison.OrdinalIgnoreCase) ? 1 : 2;
            if (rankA != rankB) return rankA.CompareTo(rankB);

            return string.Compare(a.Name, b.Name, StringComparison.CurrentCultureIgnoreCase);
        }
    }

    private sealed class ProxyNameComparer : IComparer
    {
        public static readonly ProxyNameComparer Instance = new();

        public int Compare(object? x, object? y)
        {
            if (x is not ProxyProfile a || y is not ProxyProfile b) return 0;
            int nameCmp = string.Compare(a.Name, b.Name, StringComparison.CurrentCultureIgnoreCase);
            return nameCmp != 0 ? nameCmp : string.Compare(a.EndpointDisplay, b.EndpointDisplay, StringComparison.OrdinalIgnoreCase);
        }
    }

    private bool FilterConnectionPredicate(object obj)
    {
        if (obj is not ConnectionRecord conn) return false;

        if (!string.Equals(ConnectionStatusFilter, "All", StringComparison.OrdinalIgnoreCase) &&
            !string.Equals(conn.Status, ConnectionStatusFilter, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(ConnectionSearchText)) return true;
        return conn.ProcessName.Contains(ConnectionSearchText, StringComparison.OrdinalIgnoreCase) ||
               conn.TargetDisplay.Contains(ConnectionSearchText, StringComparison.OrdinalIgnoreCase) ||
               conn.FakeIp.Contains(ConnectionSearchText, StringComparison.OrdinalIgnoreCase) ||
               conn.ProxyName.Contains(ConnectionSearchText, StringComparison.OrdinalIgnoreCase) ||
               conn.Protocol.Contains(ConnectionSearchText, StringComparison.OrdinalIgnoreCase) ||
               conn.Status.Contains(ConnectionSearchText, StringComparison.OrdinalIgnoreCase) ||
               conn.ErrorMessage.Contains(ConnectionSearchText, StringComparison.OrdinalIgnoreCase);
    }

    private bool FilterProcessEventPredicate(object obj)
    {
        if (obj is not ProcessEventRecord ev) return false;

        if (!string.Equals(EventCategoryFilter, "All", StringComparison.OrdinalIgnoreCase))
        {
            bool categoryMatch = EventCategoryFilter switch
            {
                "Injection" => ev.EventType is "Launched" or "Injected" or "HookInit" or "ChildSpawned",
                "Network" => ev.EventType is "ConnectRedirect" or "NetworkChanged" or "XrayCore",
                "Dns" => ev.EventType is "DnsResolved" or "DnsFakeIp",
                "Issue" => ev.EventType is "Warning" or "JobCleanup" or "Error",
                _ => true
            };
            if (!categoryMatch) return false;
        }

        if (string.IsNullOrWhiteSpace(ConnectionSearchText)) return true;
        return ev.EventType.Contains(ConnectionSearchText, StringComparison.OrdinalIgnoreCase) ||
               ev.ProcessName.Contains(ConnectionSearchText, StringComparison.OrdinalIgnoreCase) ||
               ev.Arch.Contains(ConnectionSearchText, StringComparison.OrdinalIgnoreCase) ||
               ev.Message.Contains(ConnectionSearchText, StringComparison.OrdinalIgnoreCase) ||
               ev.Pid.ToString().Contains(ConnectionSearchText, StringComparison.OrdinalIgnoreCase);
    }

    private void ApplyMonitorFilters()
    {
        HasActiveMonitorFilter =
            !string.IsNullOrWhiteSpace(ConnectionSearchText) ||
            !string.Equals(ConnectionStatusFilter, "All", StringComparison.OrdinalIgnoreCase) ||
            !string.Equals(EventCategoryFilter, "All", StringComparison.OrdinalIgnoreCase);
        FilteredConnections.Refresh();
        FilteredProcessEvents.Refresh();
    }

    internal void EnqueueConnectionUpsert(BridgeConnectionDto dto) =>
        _pendingConnectionOps.Enqueue(ConnectionQueueItem.ForUpsert(dto));

    internal void EnqueueBridgeDisconnect(uint bridgePid)
    {
        _pendingConnectionOps.Enqueue(ConnectionQueueItem.ForDisconnect(bridgePid));
        Volatile.Write(ref _bridgeSummaryDirty, 1);
    }

    internal int ProcessPendingConnectionOpsBatch(int maxItems = 128)
    {
        int processed = 0;
        while (processed < maxItems && _pendingConnectionOps.TryDequeue(out var item))
        {
            if (item.IsDisconnect)
            {
                MarkBridgeConnectionsClosed(item.DisconnectBridgePid);
            }
            else
            {
                BridgeConnectionDto dto = item.Upsert!;
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
            }
            processed++;
        }

        while (Connections.Count > 2000)
        {
            var last = Connections[^1];
            _connectionIndex.Remove((last.BridgePid, last.Id));
            Connections.RemoveAt(Connections.Count - 1);
        }

        return processed;
    }

    private void OnFlushTimerTick(object? sender, EventArgs e)
    {
        ProcessPendingConnectionOpsBatch(128);

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
        Interlocked.Exchange(ref _bridgeSummaryDirty, 0);
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
        }
        else
        {
            var found = Proxies.FirstOrDefault(p => p.Id == app.ProxyProfileId);
            app.BoundProxyName = found?.Name ?? "Direct";
        }

        if (!_isInitializing)
        {
            RefreshAppStats();
        }
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
        RefreshAppStats();
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
        string? preferredNic = string.IsNullOrWhiteSpace(PreferredOutboundInterface)
            ? null
            : PreferredOutboundInterface;
        var (ok, _, msg) = await _launcher.LaunchAppAsync(app, proxy, BypassGlobalTun, preferredNic, XrayCorePath);
        RefreshBridgeSummary();
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

    public ProxyProfile CreateClonedProxyDraft(ProxyProfile source)
    {
        ArgumentNullException.ThrowIfNull(source);
        return source.CreateDuplicate(Proxies.Select(p => p.Name));
    }

    public void AddOrUpdateProxy(ProxyProfile edited, int? insertAfterIndex = null)
    {
        var existing = Proxies.FirstOrDefault(p => p.Id == edited.Id);
        if (existing is not null)
        {
            edited.IsSelected = existing.IsSelected;
            int idx = Proxies.IndexOf(existing);
            Proxies[idx] = edited;
        }
        else if (insertAfterIndex.HasValue && insertAfterIndex.Value >= 0 && insertAfterIndex.Value < Proxies.Count)
        {
            Proxies.Insert(insertAfterIndex.Value + 1, edited);
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

    public (int Added, int Skipped) ImportProxies(IEnumerable<ProxyProfile> incoming, bool skipDuplicates = true)
    {
        ArgumentNullException.ThrowIfNull(incoming);

        var existingKeys = new HashSet<string>(
            Proxies.Select(ProxyBatchParser.BuildDedupeKey),
            StringComparer.Ordinal);
        var existingNames = new HashSet<string>(
            Proxies.Select(p => p.Name).Where(n => !string.IsNullOrWhiteSpace(n)),
            StringComparer.OrdinalIgnoreCase);

        int added = 0;
        int skipped = 0;

        foreach (ProxyProfile candidate in incoming)
        {
            string key = ProxyBatchParser.BuildDedupeKey(candidate);
            if (skipDuplicates && !existingKeys.Add(key))
            {
                skipped++;
                continue;
            }

            var toAdd = new ProxyProfile
            {
                Id = Guid.NewGuid(),
                Protocol = candidate.Protocol,
                Host = candidate.Host.Trim(),
                Port = candidate.Port,
                Username = candidate.Username.Trim(),
                Password = candidate.Password,
                Vless = candidate.Protocol == ProxyProtocol.Vless ? candidate.Vless?.Clone() : null
            };

            string desiredName = string.IsNullOrWhiteSpace(candidate.Name)
                ? $"{toAdd.ProtocolDisplay} {toAdd.Host}:{toAdd.Port}"
                : candidate.Name.Trim();

            if (!existingNames.Add(desiredName))
            {
                desiredName = ProxyProfile.BuildDuplicateName(desiredName, existingNames);
                existingNames.Add(desiredName);
            }
            toAdd.Name = desiredName;

            Proxies.Add(toAdd);
            added++;
        }

        if (added > 0)
        {
            SaveConfiguration();
        }

        StatusMessage = skipped > 0
            ? $"已批量导入 {added} 个代理节点（跳过 {skipped} 个重复节点）"
            : $"已批量导入 {added} 个代理节点";
        return (added, skipped);
    }

    [RelayCommand]
    private void ExportProxiesToClipboard()
    {
        if (Proxies.Count == 0)
        {
            StatusMessage = "暂无可导出的代理节点";
            return;
        }

        string uriText = ProxyBatchParser.ExportToUriLines(Proxies);
        if (ClipboardHelper.TrySetText(uriText, out string? error))
        {
            StatusMessage = $"已导出 {Proxies.Count} 个代理节点 URI 到剪贴板";
        }
        else
        {
            StatusMessage = $"导出代理节点失败: {error}";
        }
    }

    [RelayCommand]
    public void CopyProxyExitIp(ProxyProfile? proxy)
    {
        if (proxy is null || string.IsNullOrWhiteSpace(proxy.ExitIp)) return;
        string ip = proxy.ExitIp.Trim();
        if (ClipboardHelper.TrySetText(ip, out string? error))
        {
            StatusMessage = $"已复制出口 IP: {ip}";
            TriggerExitIpCopiedFeedback(proxy);
        }
        else
        {
            string msg = $"复制出口 IP 失败: {error}";
            StatusMessage = msg;
            System.Windows.MessageBox.Show(
                $"未能写入系统剪贴板（{error}）。\n\n出口 IP：{ip}",
                "复制出口 IP",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
    }

    private void TriggerExitIpCopiedFeedback(ProxyProfile proxy)
    {
        int nextVersion = _exitIpCopyVersions.TryGetValue(proxy.Id, out int current)
            ? current + 1
            : 1;
        _exitIpCopyVersions[proxy.Id] = nextVersion;
        proxy.IsExitIpCopied = true;
        _ = ResetExitIpCopiedAfterDelayAsync(proxy, nextVersion);
    }

    private async Task ResetExitIpCopiedAfterDelayAsync(ProxyProfile proxy, int version)
    {
        await Task.Delay(1800);
        void ResetIfCurrent()
        {
            if (_exitIpCopyVersions.TryGetValue(proxy.Id, out int current) && current == version)
            {
                proxy.IsExitIpCopied = false;
            }
        }

        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher is not null && !dispatcher.CheckAccess())
        {
            await dispatcher.InvokeAsync(ResetIfCurrent);
        }
        else
        {
            ResetIfCurrent();
        }
    }

    [RelayCommand]
    private async Task DetectProxyExitIpAsync(ProxyProfile? proxy)
    {
        if (proxy is null || proxy.IsDetectingExitIp) return;
        string? preferredNic = string.IsNullOrWhiteSpace(PreferredOutboundInterface)
            ? null
            : PreferredOutboundInterface;
        ProxyExitIpInfo? info = await ProxyExitIpDetector.DetectAsync(
            proxy,
            BypassGlobalTun,
            preferredNic,
            xrayCorePath: XrayCorePath);
        if (info is not null)
        {
            SaveConfiguration();
            if (HasActiveProxyFilter)
            {
                FilteredProxies.Refresh();
            }
            RefreshProxyStatsAndSelection();
            StatusMessage = $"{proxy.Name} 落地出口: {proxy.ExitBadgeText}";
        }
        else
        {
            StatusMessage = $"{proxy.Name} 出口检测失败: {proxy.ExitDetectError}";
        }
    }

    [RelayCommand]
    private Task DetectAllProxiesExitIpAsync() =>
        DetectProxyExitIpBatchAsync(Proxies.ToList(), "全部");

    [RelayCommand]
    private Task DetectSelectedProxiesExitIpAsync()
    {
        var selected = GetSelectedProxies();
        return selected.Count == 0
            ? Task.CompletedTask
            : DetectProxyExitIpBatchAsync(selected, "选中");
    }

    private async Task DetectProxyExitIpBatchAsync(IReadOnlyList<ProxyProfile> list, string scopeLabel)
    {
        if (list.Count == 0) return;

        string? preferredNic = string.IsNullOrWhiteSpace(PreferredOutboundInterface)
            ? null
            : PreferredOutboundInterface;
        using var gate = new SemaphoreSlim(4, 4);
        int succeeded = 0;

        XraySidecarSession? batchSidecar = null;
        try
        {
            var vlessProxies = list.Where(p => p.RequiresXrayCore && !p.IsDetectingExitIp).ToList();
            string? xrayExe = XrayCoreManager.ResolveXrayPath(XrayCorePath);
            if (vlessProxies.Count > 1 && xrayExe is not null)
            {
                try
                {
                    batchSidecar = await XraySidecarSession.StartBatchAsync(
                        xrayExe,
                        vlessProxies,
                        BypassGlobalTun,
                        preferredNic,
                        CancellationToken.None);
                }
                catch
                {
                    batchSidecar = null;
                }
            }

            var tasks = list.Select(async proxy =>
            {
                if (proxy.IsDetectingExitIp) return;
                await gate.WaitAsync();
                try
                {
                    ProxyProfile? transportOverride = batchSidecar?.GetLocalSocksProfile(proxy.Id);
                    ProxyExitIpInfo? info = await ProxyExitIpDetector.DetectAsync(
                        proxy,
                        BypassGlobalTun,
                        preferredNic,
                        xrayCorePath: XrayCorePath,
                        resolvedTransportOverride: transportOverride);
                    if (info is not null)
                    {
                        Interlocked.Increment(ref succeeded);
                    }
                }
                finally
                {
                    gate.Release();
                }
            });

            await Task.WhenAll(tasks);
        }
        finally
        {
            batchSidecar?.Dispose();
        }

        if (succeeded > 0)
        {
            SaveConfiguration();
            if (HasActiveProxyFilter)
            {
                FilteredProxies.Refresh();
            }
        }
        RefreshProxyStatsAndSelection();
        StatusMessage = $"{scopeLabel}出口检测完成: {succeeded}/{list.Count} 个节点成功识别";
    }

    public List<ProxyProfile> GetSelectedProxies() =>
        Proxies.Where(p => p.IsSelected).ToList();

    public List<Guid> GetSelectedProxyIds() =>
        Proxies.Where(p => p.IsSelected).Select(p => p.Id).ToList();

    [RelayCommand]
    private void ClearProxySelection()
    {
        _isSyncingSelectionState = true;
        try
        {
            foreach (ProxyProfile proxy in Proxies)
            {
                proxy.IsSelected = false;
            }
        }
        finally
        {
            _isSyncingSelectionState = false;
        }
        RefreshProxyStatsAndSelection();
    }

    [RelayCommand]
    private void ResetProxyFilters()
    {
        ProxySearchText = string.Empty;
        ProxyProtocolFilter = "All";
        ProxySortMode = "Default";
    }

    [RelayCommand]
    private void OpenProxiesPage()
    {
        SelectedNavIndex = 1;
    }

    [RelayCommand]
    private void OpenMonitorPage()
    {
        SelectedNavIndex = 2;
    }

    [RelayCommand]
    private void OpenSettingsPage()
    {
        SelectedNavIndex = 3;
    }

    [RelayCommand]
    private void ResetAppFilters()
    {
        AppSearchText = string.Empty;
        AppBindingFilter = "All";
        AppArchFilter = "All";
    }

    [RelayCommand]
    private void ResetMonitorFilters()
    {
        ConnectionSearchText = string.Empty;
        ConnectionStatusFilter = "All";
        EventCategoryFilter = "All";
    }

    [RelayCommand]
    private void CopySingleProxyUri(ProxyProfile? proxy)
    {
        if (proxy is null) return;
        string uri = ProxyBatchParser.ExportSingleUri(proxy);
        if (ClipboardHelper.TrySetText(uri, out string? error))
        {
            StatusMessage = $"已复制节点链接: {proxy.Name}";
        }
        else
        {
            StatusMessage = $"复制节点链接失败: {error}";
            System.Windows.MessageBox.Show(
                $"未能写入系统剪贴板（{error}）。",
                "复制节点链接",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
    }

    public int DeleteSelectedProxies()
    {
        var selected = GetSelectedProxies();
        if (selected.Count == 0) return 0;

        var removedIds = selected.Select(p => p.Id).ToHashSet();
        foreach (ProxyProfile proxy in selected)
        {
            proxy.IsSelected = false;
            Proxies.Remove(proxy);
        }

        foreach (AppProfile app in Apps.Where(a => a.ProxyProfileId.HasValue && removedIds.Contains(a.ProxyProfileId.Value)))
        {
            app.ProxyProfileId = null;
            SyncAppBoundProxyName(app);
        }

        SaveConfiguration();
        RefreshProxyStatsAndSelection();
        StatusMessage = $"已删除 {selected.Count} 个选中代理节点";
        return selected.Count;
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
        string? preferredNic = string.IsNullOrWhiteSpace(PreferredOutboundInterface)
            ? null
            : PreferredOutboundInterface;
        await ProxyTester.TestProxyAsync(
            proxy,
            TestProbeHost,
            TestProbePort,
            default,
            BypassGlobalTun,
            preferredNic,
            XrayCorePath);
        if (string.Equals(ProxySortMode, "Latency", StringComparison.Ordinal))
        {
            FilteredProxies.Refresh();
        }
        RefreshProxyStatsAndSelection();
        StatusMessage = $"Tested {proxy.Name}: {proxy.LatencyDisplay}";
    }

    [RelayCommand]
    private Task TestAllProxiesAsync() =>
        TestProxyBatchAsync(Proxies.ToList(), "全部");

    [RelayCommand]
    private Task TestSelectedProxiesAsync()
    {
        var selected = GetSelectedProxies();
        return selected.Count == 0
            ? Task.CompletedTask
            : TestProxyBatchAsync(selected, "选中");
    }

    private async Task TestProxyBatchAsync(IReadOnlyList<ProxyProfile> list, string scopeLabel)
    {
        if (list.Count == 0) return;

        string? preferredNic = string.IsNullOrWhiteSpace(PreferredOutboundInterface)
            ? null
            : PreferredOutboundInterface;
        XraySidecarSession? batchSidecar = null;
        try
        {
            var vlessProxies = list.Where(p => p.RequiresXrayCore && !p.IsTesting).ToList();
            string? xrayExe = XrayCoreManager.ResolveXrayPath(XrayCorePath);
            if (vlessProxies.Count > 1 && xrayExe is not null)
            {
                try
                {
                    batchSidecar = await XraySidecarSession.StartBatchAsync(
                        xrayExe,
                        vlessProxies,
                        BypassGlobalTun,
                        preferredNic,
                        CancellationToken.None);
                }
                catch
                {
                    batchSidecar = null;
                }
            }

            var tasks = list.Select(p => ProxyTester.TestProxyAsync(
                p,
                TestProbeHost,
                TestProbePort,
                default,
                BypassGlobalTun,
                preferredNic,
                XrayCorePath,
                batchSidecar?.GetLocalSocksProfile(p.Id)));
            await Task.WhenAll(tasks);
        }
        finally
        {
            batchSidecar?.Dispose();
        }

        if (string.Equals(ProxySortMode, "Latency", StringComparison.Ordinal))
        {
            FilteredProxies.Refresh();
        }
        RefreshProxyStatsAndSelection();
        StatusMessage = $"已完成{scopeLabel} {list.Count} 个代理节点测速";
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
        if (ClipboardHelper.TrySetText(ConfigFilePath, out _))
        {
            StatusMessage = "已复制配置文件路径到剪贴板";
        }
        else
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
    private void RefreshOutboundInterfaces()
    {
        PhysicalNetworkSelector.InvalidateCache();
        RefreshOutboundInterfacesCore();
        StatusMessage = "已刷新可用出口网卡列表";
    }

    private void OnPhysicalNetworkChanged()
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher is null) return;
        _ = dispatcher.BeginInvoke(() => RefreshOutboundInterfacesCore());
    }

    private void RefreshOutboundInterfacesCore()
    {
        string currentPreferred = PreferredOutboundInterface ?? string.Empty;
        bool wasInit = _isInitializing;
        _isInitializing = true;
        try
        {
            OutboundInterfaceChoices.Clear();
            OutboundInterfaceChoices.Add(new OutboundInterfaceChoice(string.Empty, "自动探测物理网卡 (推荐)"));

            IReadOnlyList<OutboundInterfaceInfo> all = PhysicalNetworkSelector.GetSelectableInterfaces();
            foreach (OutboundInterfaceInfo nic in all)
            {
                string tag = nic.IsVirtualOrTun ? " [虚拟/TUN]" : string.Empty;
                OutboundInterfaceChoices.Add(new OutboundInterfaceChoice(nic.Id, $"{nic.DisplaySummary}{tag}"));
            }

            if (!string.IsNullOrEmpty(currentPreferred) &&
                !OutboundInterfaceChoices.Any(c => string.Equals(c.Id, currentPreferred, StringComparison.OrdinalIgnoreCase)))
            {
                OutboundInterfaceChoices.Add(new OutboundInterfaceChoice(currentPreferred, $"已保存网卡 (当前离线，自动故障转移)"));
            }

            PreferredOutboundInterface = currentPreferred;
        }
        finally
        {
            _isInitializing = wasInit;
        }

        UpdateOutboundNetworkSummary();
    }

    private void UpdateOutboundNetworkSummary()
    {
        IReadOnlyList<string> activeTuns = PhysicalNetworkSelector.GetActiveTunAdapterNames();
        HasActiveTun = activeTuns.Count > 0;
        OutboundTunBadgeText = HasActiveTun
            ? $"检测到活跃 TUN: {string.Join(", ", activeTuns)}"
            : "当前未检测到活跃 TUN";
        string tunNote = $" · {OutboundTunBadgeText}";

        if (!BypassGlobalTun)
        {
            OutboundStatusLevel = "Disabled";
            OutboundShortStatus = "已关闭绕过";
            OutboundHeadline = "已关闭全局 TUN 隔离，出站流量遵循系统默认路由";
            OutboundNetworkSummary = $"已关闭 TUN 绕过，出站流量遵循系统默认路由{tunNote}";
            return;
        }

        string? preferredNic = string.IsNullOrWhiteSpace(PreferredOutboundInterface)
            ? null
            : PreferredOutboundInterface;
        OutboundInterfaceInfo? selected = PhysicalNetworkSelector.ResolveBestOutboundInterface(preferredNic);
        if (selected is null)
        {
            OutboundStatusLevel = "Warning";
            OutboundShortStatus = "默认路由回退";
            OutboundHeadline = "暂未检测到可用物理出口网卡，将使用系统默认路由";
            OutboundNetworkSummary = $"{OutboundHeadline}{tunNote}";
        }
        else if (!string.IsNullOrEmpty(preferredNic) &&
                 !string.Equals(selected.Id, preferredNic, StringComparison.OrdinalIgnoreCase))
        {
            OutboundStatusLevel = "Warning";
            OutboundShortStatus = "已故障转移";
            OutboundHeadline = $"指定网卡离线，已自动故障转移至: {selected.DisplaySummary}";
            OutboundNetworkSummary = $"指定网卡当前离线，已自动故障转移至: {selected.DisplaySummary}{tunNote}";
        }
        else
        {
            OutboundStatusLevel = "Ok";
            OutboundShortStatus = "物理网卡直连";
            OutboundHeadline = $"当前物理出口: {selected.DisplaySummary}";
            OutboundNetworkSummary = $"{OutboundHeadline}{tunNote}";
        }
    }

    internal static string ExtractShortXrayVersion(string? versionLine)
    {
        if (string.IsNullOrWhiteSpace(versionLine)) return string.Empty;
        string[] tokens = versionLine.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
        foreach (string token in tokens)
        {
            string trimmed = token.TrimStart('v', 'V');
            if (trimmed.Length >= 3 && char.IsDigit(trimmed[0]) && trimmed.Contains('.'))
            {
                return $"v{trimmed}";
            }
        }
        return string.Empty;
    }

    [RelayCommand]
    private async Task RefreshXrayCoreStatusAsync()
    {
        string defaultPath = AppPaths.GetDefaultXrayExePath();
        string? resolved = XrayCoreManager.ResolveXrayPath(XrayCorePath);
        if (resolved is null)
        {
            IsXrayCoreAvailable = false;
            if (string.IsNullOrWhiteSpace(XrayCorePath))
            {
                XrayCoreState = "Unconfigured";
                XrayCoreVersionShort = "未配置";
                XrayCoreBadgeText = "未配置";
                XrayCoreHeadline = "未配置 Xray-core 内核（当前仅开放原生 SOCKS5 / HTTP / HTTPS）";
                XrayCoreDetailText = $"默认内核路径: {defaultPath}（点击上方「一键下载」或浏览指定 xray.exe 后可解锁 VLESS / REALITY）";
                XrayCoreStatusText = $"未检测到 Xray-core（默认路径 {defaultPath} 不存在），当前仅开放原生 SOCKS5 / HTTP / HTTPS";
            }
            else
            {
                XrayCoreState = "Error";
                XrayCoreVersionShort = "路径无效";
                XrayCoreBadgeText = "路径无效";
                XrayCoreHeadline = "指定的 xray.exe 路径不存在（当前仅开放原生 SOCKS5 / HTTP / HTTPS）";
                XrayCoreDetailText = $"当前配置路径: {XrayCorePath}";
                XrayCoreStatusText = $"指定路径不存在 xray.exe: {XrayCorePath}，当前仅开放原生 SOCKS5 / HTTP / HTTPS";
            }
            return;
        }

        string? version = await XrayCoreManager.DetectVersionAsync(resolved);
        if (!string.IsNullOrWhiteSpace(version))
        {
            string shortVer = ExtractShortXrayVersion(version);
            IsXrayCoreAvailable = true;
            XrayCoreState = "Ready";
            XrayCoreVersionShort = string.IsNullOrEmpty(shortVer) ? "已就绪" : shortVer;
            XrayCoreBadgeText = string.IsNullOrEmpty(shortVer) ? "✓ 已就绪" : $"✓ 已就绪 · {shortVer}";
            XrayCoreHeadline = $"Xray-core 内核已就绪 · {version}";
            XrayCoreDetailText = $"路径: {resolved}";
            XrayCoreStatusText = $"已就绪 · {version} ({resolved})";
        }
        else
        {
            IsXrayCoreAvailable = false;
            XrayCoreState = "Error";
            XrayCoreVersionShort = "运行异常";
            XrayCoreBadgeText = "校验失败";
            XrayCoreHeadline = "无法识别或执行 xray.exe（请检查文件完整性）";
            XrayCoreDetailText = $"目标路径: {resolved}";
            XrayCoreStatusText = $"无法识别或运行 xray.exe: {resolved}";
        }
    }

    [RelayCommand]
    private async Task DownloadXrayCoreAsync()
    {
        if (IsDownloadingXray) return;

        IsDownloadingXray = true;
        XrayDownloadProgressPercent = 0;
        XrayDownloadStatusText = "正在准备下载 Xray-core...";
        _xrayDownloadCts = new CancellationTokenSource();

        var progress = new Progress<XrayDownloadProgress>(p =>
        {
            if (p.TotalBytes is > 0)
            {
                double pct = Math.Clamp((double)p.BytesReceived * 100.0 / p.TotalBytes.Value, 0, 100);
                XrayDownloadProgressPercent = pct;
                double mbDown = p.BytesReceived / (1024.0 * 1024.0);
                double mbTotal = p.TotalBytes.Value / (1024.0 * 1024.0);
                XrayDownloadStatusText = $"{p.Stage} {mbDown:F1} / {mbTotal:F1} MB ({pct:F0}%)";
            }
            else
            {
                XrayDownloadStatusText = p.Stage;
            }
        });

        try
        {
            XrayDownloadResult res = await XrayCoreManager.DownloadLatestAsync(
                progress: progress,
                ct: _xrayDownloadCts.Token);

            _isInitializing = true;
            try
            {
                XrayCorePath = string.Empty;
            }
            finally
            {
                _isInitializing = false;
            }

            SaveConfiguration();
            await RefreshXrayCoreStatusAsync();
            XrayDownloadProgressPercent = 100;
            XrayDownloadStatusText = $"下载并验证成功: {res.DetectedVersion}";
            StatusMessage = $"Xray-core 下载完成 ({res.VersionTag})";
        }
        catch (OperationCanceledException)
        {
            XrayDownloadStatusText = "已取消下载 Xray-core";
            StatusMessage = "已取消下载 Xray-core";
        }
        catch (Exception ex)
        {
            string err = $"下载 Xray-core 失败: {ex.Message}";
            XrayDownloadStatusText = err;
            StatusMessage = err;
            System.Windows.MessageBox.Show(
                $"{err}\n\n如无法直连 GitHub，可手动下载 Xray-windows-64.zip 解压 xray.exe 后在上方浏览指定路径或放入 data\\cores\\xray.exe。",
                "Xray-core 下载失败",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
        finally
        {
            _xrayDownloadCts?.Dispose();
            _xrayDownloadCts = null;
            IsDownloadingXray = false;
        }
    }

    [RelayCommand]
    private void CancelDownloadXrayCore()
    {
        try
        {
            _xrayDownloadCts?.Cancel();
        }
        catch
        {
        }
    }

    [RelayCommand]
    private void ClearXrayCorePath()
    {
        XrayCorePath = string.Empty;
        StatusMessage = "已清除自定义 Xray-core 路径";
    }

    [RelayCommand]
    private void OpenXrayCoreDirectory()
    {
        try
        {
            string? resolved = XrayCoreManager.ResolveXrayPath(XrayCorePath);
            string targetDir = resolved is not null
                ? (Path.GetDirectoryName(resolved) ?? AppPaths.GetCoresDirectory())
                : AppPaths.GetCoresDirectory();
            Directory.CreateDirectory(targetDir);
            Process.Start(new ProcessStartInfo
            {
                FileName = "explorer.exe",
                Arguments = $"\"{targetDir}\"",
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            StatusMessage = $"打开 Xray-core 目录失败: {ex.Message}";
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
        _config.BypassGlobalTun = BypassGlobalTun;
        _config.PreferredOutboundInterface = string.IsNullOrWhiteSpace(PreferredOutboundInterface)
            ? null
            : PreferredOutboundInterface;
        _config.XrayCorePath = string.IsNullOrWhiteSpace(XrayCorePath)
            ? null
            : XrayCorePath.Trim();
        _configService.Save(_config);
    }

    internal static string ResolveAppVersionDisplay()
    {
        Assembly asm = typeof(MainViewModel).Assembly;
        string? infoVer = asm.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion;
        if (!string.IsNullOrWhiteSpace(infoVer))
        {
            int plusIdx = infoVer.IndexOf('+');
            string core = (plusIdx >= 0 ? infoVer[..plusIdx] : infoVer).Trim();
            if (!string.IsNullOrEmpty(core))
            {
                return core.StartsWith('v') ? core : $"v{core}";
            }
        }

        Version? ver = asm.GetName().Version;
        if (ver is not null)
        {
            return $"v{ver.Major}.{ver.Minor}.{Math.Max(0, ver.Build)}";
        }

        return "v1.0.0";
    }

    public void Dispose()
    {
        PhysicalNetworkSelector.NetworkChanged -= OnPhysicalNetworkChanged;
        _uiFlushTimer.Stop();
        _launcher.Dispose();
    }
}

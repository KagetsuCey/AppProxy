using System.Collections.Concurrent;
using System.Collections.ObjectModel;
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
        RefreshOutboundInterfacesCore();
        PhysicalNetworkSelector.NetworkChanged += OnPhysicalNetworkChanged;

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

        FilteredProxies = CollectionViewSource.GetDefaultView(Proxies);
        FilteredProxies.Filter = FilterProxyPredicate;

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
    partial void OnProxySearchTextChanged(string value) => FilteredProxies.Refresh();
    partial void OnConnectionSearchTextChanged(string value) => FilteredConnections.Refresh();

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

    private bool FilterProxyPredicate(object obj)
    {
        if (obj is not ProxyProfile proxy) return false;
        if (string.IsNullOrWhiteSpace(ProxySearchText)) return true;
        return proxy.Name.Contains(ProxySearchText, StringComparison.OrdinalIgnoreCase) ||
               proxy.Host.Contains(ProxySearchText, StringComparison.OrdinalIgnoreCase) ||
               proxy.EndpointDisplay.Contains(ProxySearchText, StringComparison.OrdinalIgnoreCase) ||
               proxy.ProtocolDisplay.Contains(ProxySearchText, StringComparison.OrdinalIgnoreCase) ||
               proxy.ExitIp.Contains(ProxySearchText, StringComparison.OrdinalIgnoreCase) ||
               proxy.ExitLocation.Contains(ProxySearchText, StringComparison.OrdinalIgnoreCase) ||
               proxy.ExitCountryCode.Contains(ProxySearchText, StringComparison.OrdinalIgnoreCase) ||
               proxy.ExitIsp.Contains(ProxySearchText, StringComparison.OrdinalIgnoreCase);
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
        string? preferredNic = string.IsNullOrWhiteSpace(PreferredOutboundInterface)
            ? null
            : PreferredOutboundInterface;
        var (ok, _, msg) = await _launcher.LaunchAppAsync(app, proxy, BypassGlobalTun, preferredNic);
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
                Password = candidate.Password
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
        ProxyExitIpInfo? info = await ProxyExitIpDetector.DetectAsync(proxy, BypassGlobalTun, preferredNic);
        if (info is not null)
        {
            SaveConfiguration();
            if (!string.IsNullOrWhiteSpace(ProxySearchText))
            {
                FilteredProxies.Refresh();
            }
            StatusMessage = $"{proxy.Name} 落地出口: {proxy.ExitBadgeText}";
        }
        else
        {
            StatusMessage = $"{proxy.Name} 出口检测失败: {proxy.ExitDetectError}";
        }
    }

    [RelayCommand]
    private async Task DetectAllProxiesExitIpAsync()
    {
        if (Proxies.Count == 0) return;

        string? preferredNic = string.IsNullOrWhiteSpace(PreferredOutboundInterface)
            ? null
            : PreferredOutboundInterface;
        using var gate = new SemaphoreSlim(4, 4);
        int succeeded = 0;
        var list = Proxies.ToList();

        var tasks = list.Select(async proxy =>
        {
            if (proxy.IsDetectingExitIp) return;
            await gate.WaitAsync();
            try
            {
                ProxyExitIpInfo? info = await ProxyExitIpDetector.DetectAsync(proxy, BypassGlobalTun, preferredNic);
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
        if (succeeded > 0)
        {
            SaveConfiguration();
            if (!string.IsNullOrWhiteSpace(ProxySearchText))
            {
                FilteredProxies.Refresh();
            }
        }
        StatusMessage = $"全部出口检测完成: {succeeded}/{list.Count} 个节点成功识别";
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
        await ProxyTester.TestProxyAsync(proxy, TestProbeHost, TestProbePort, default, BypassGlobalTun, preferredNic);
        StatusMessage = $"Tested {proxy.Name}: {proxy.LatencyDisplay}";
    }

    [RelayCommand]
    private async Task TestAllProxiesAsync()
    {
        string? preferredNic = string.IsNullOrWhiteSpace(PreferredOutboundInterface)
            ? null
            : PreferredOutboundInterface;
        var tasks = Proxies.Select(p => ProxyTester.TestProxyAsync(p, TestProbeHost, TestProbePort, default, BypassGlobalTun, preferredNic));
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
        string tunNote = activeTuns.Count > 0
            ? $" · 检测到活跃 TUN: {string.Join(", ", activeTuns)}"
            : " · 当前未检测到活跃 TUN";

        if (!BypassGlobalTun)
        {
            OutboundNetworkSummary = $"已关闭 TUN 绕过，出站流量遵循系统默认路由{tunNote}";
            return;
        }

        string? preferredNic = string.IsNullOrWhiteSpace(PreferredOutboundInterface)
            ? null
            : PreferredOutboundInterface;
        OutboundInterfaceInfo? selected = PhysicalNetworkSelector.ResolveBestOutboundInterface(preferredNic);
        if (selected is null)
        {
            OutboundNetworkSummary = $"暂未检测到可用物理出口网卡，将使用系统默认路由{tunNote}";
        }
        else if (!string.IsNullOrEmpty(preferredNic) &&
                 !string.Equals(selected.Id, preferredNic, StringComparison.OrdinalIgnoreCase))
        {
            OutboundNetworkSummary = $"指定网卡当前离线，已自动故障转移至: {selected.DisplaySummary}{tunNote}";
        }
        else
        {
            OutboundNetworkSummary = $"当前物理出口: {selected.DisplaySummary}{tunNote}";
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

using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Media;
using AppProxy.Core.Models;
using AppProxy.Core.Services;
using AppProxy.UI.Services;
using CommunityToolkit.Mvvm.ComponentModel;
using Microsoft.Win32;
using Wpf.Ui.Controls;

namespace AppProxy.UI.Views;

public partial class ProxyBatchExportDialog : FluentWindow
{
    private sealed partial class ExportNodeItem : ObservableObject
    {
        public ExportNodeItem(ProxyProfile profile, bool isFilteredMatch, bool isChecked)
        {
            Profile = profile;
            IsFilteredMatch = isFilteredMatch;
            _isChecked = isChecked;
        }

        public ProxyProfile Profile { get; }
        public bool IsFilteredMatch { get; }

        [ObservableProperty]
        private bool _isChecked;

        public string Name => Profile.Name;
        public string ProtocolDisplay => Profile.ProtocolDisplay;
        public string EndpointDisplay => Profile.EndpointDisplay;

        public string SecondaryTag
        {
            get
            {
                if (!string.IsNullOrWhiteSpace(Profile.ExitCountryCode))
                {
                    return Profile.ExitCountryCode.Trim();
                }

                if (Profile.LastLatencyMs.HasValue)
                {
                    return $"{Profile.LastLatencyMs.Value}ms";
                }

                return string.Empty;
            }
        }
    }

    private readonly ObservableCollection<ExportNodeItem> _allItems = new();
    private readonly ICollectionView _itemsView;
    private readonly bool _showFilterOption;
    private bool _suppressRefresh;

    public string? LastStatusMessage { get; private set; }

    public ProxyBatchExportDialog(
        IReadOnlyList<ProxyProfile> allProxies,
        IReadOnlyList<ProxyProfile>? filteredProxies = null,
        bool isFiltered = false,
        IReadOnlyCollection<Guid>? preselectedIds = null)
    {
        IReadOnlyList<ProxyProfile> safeAll = allProxies ?? [];
        var filteredSet = (filteredProxies ?? safeAll).Select(p => p.Id).ToHashSet();
        bool hasPreselection = preselectedIds is { Count: > 0 };
        var preselectedSet = hasPreselection ? preselectedIds!.ToHashSet() : null;
        _showFilterOption = isFiltered && filteredSet.Count > 0 && filteredSet.Count < safeAll.Count;

        foreach (ProxyProfile proxy in safeAll)
        {
            bool inFiltered = filteredSet.Contains(proxy.Id);
            bool initialChecked = hasPreselection
                ? preselectedSet!.Contains(proxy.Id)
                : (!_showFilterOption || inFiltered);

            var item = new ExportNodeItem(proxy, inFiltered, initialChecked);
            item.PropertyChanged += OnExportItemPropertyChanged;
            _allItems.Add(item);
        }

        InitializeComponent();

        _itemsView = CollectionViewSource.GetDefaultView(_allItems);
        _itemsView.Filter = FilterExportItem;
        NodeChecklistControl.ItemsSource = _itemsView;

        if (_showFilterOption)
        {
            SelectFilteredOnlyButton.Visibility = Visibility.Visible;
        }

        RefreshOutput();
    }

    private bool IsJsonMode =>
        string.Equals((FormatCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString(), "Json", StringComparison.OrdinalIgnoreCase);

    private List<ProxyProfile> SelectedProxies =>
        _allItems.Where(i => i.IsChecked).Select(i => i.Profile).ToList();

    private bool FilterExportItem(object obj)
    {
        if (obj is not ExportNodeItem item) return false;
        string query = NodeFilterBox?.Text?.Trim() ?? string.Empty;
        if (string.IsNullOrEmpty(query)) return true;

        ProxyProfile p = item.Profile;
        return p.Name.Contains(query, StringComparison.OrdinalIgnoreCase) ||
               p.Host.Contains(query, StringComparison.OrdinalIgnoreCase) ||
               p.EndpointDisplay.Contains(query, StringComparison.OrdinalIgnoreCase) ||
               p.ProtocolDisplay.Contains(query, StringComparison.OrdinalIgnoreCase) ||
               p.ExitIp.Contains(query, StringComparison.OrdinalIgnoreCase) ||
               p.ExitLocation.Contains(query, StringComparison.OrdinalIgnoreCase) ||
               p.ExitCountryCode.Contains(query, StringComparison.OrdinalIgnoreCase);
    }

    private void OnExportItemPropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (_suppressRefresh) return;
        if (e.PropertyName == nameof(ExportNodeItem.IsChecked))
        {
            RefreshOutput();
        }
    }

    private void OnOptionChanged(object sender, RoutedEventArgs e)
    {
        RefreshOutput();
    }

    private void OnNodeFilterChanged(object sender, TextChangedEventArgs e)
    {
        _itemsView.Refresh();
    }

    private void OnSelectAllClick(object sender, RoutedEventArgs e)
    {
        SetVisibleSelection(_ => true);
    }

    private void OnInvertSelectionClick(object sender, RoutedEventArgs e)
    {
        SetVisibleSelection(item => !item.IsChecked);
    }

    private void OnClearSelectionClick(object sender, RoutedEventArgs e)
    {
        SetVisibleSelection(_ => false);
    }

    private void OnSelectFilteredOnlyClick(object sender, RoutedEventArgs e)
    {
        _suppressRefresh = true;
        try
        {
            foreach (ExportNodeItem item in _allItems)
            {
                item.IsChecked = item.IsFilteredMatch;
            }
        }
        finally
        {
            _suppressRefresh = false;
        }
        RefreshOutput();
    }

    private void SetVisibleSelection(Func<ExportNodeItem, bool> selector)
    {
        _suppressRefresh = true;
        try
        {
            foreach (ExportNodeItem item in _itemsView.Cast<ExportNodeItem>())
            {
                item.IsChecked = selector(item);
            }
        }
        finally
        {
            _suppressRefresh = false;
        }
        RefreshOutput();
    }

    private void RefreshOutput()
    {
        if (!IsInitialized || OutputTextBox is null || FormatCombo is null || SummaryTextBlock is null)
        {
            return;
        }

        List<ProxyProfile> target = SelectedProxies;
        int checkedCount = target.Count;
        bool hasSelection = checkedCount > 0;

        OutputTextBox.Text = !hasSelection
            ? string.Empty
            : IsJsonMode
                ? ProxyBatchParser.ExportToJson(target)
                : ProxyBatchParser.ExportToUriLines(target);

        SummaryTextBlock.Text = $"已选 {checkedCount} / {_allItems.Count} 个节点";
        PreviewFormatBadgeText.Text = IsJsonMode ? "JSON 配置" : "URI 列表";
        PreviewCountText.Text = $"{checkedCount} 项";
        CopyButton.Content = hasSelection ? $"复制到剪贴板 ({checkedCount})" : "复制到剪贴板";
        CopyButton.IsEnabled = hasSelection;
        SaveFileButton.IsEnabled = hasSelection;
        EmptySelectionHintText.Visibility = hasSelection ? Visibility.Collapsed : Visibility.Visible;

        if (FeedbackBorder is not null)
        {
            FeedbackBorder.Visibility = Visibility.Collapsed;
        }
    }

    private void OnCopyClipboardClick(object sender, RoutedEventArgs e)
    {
        List<ProxyProfile> selected = SelectedProxies;
        if (selected.Count == 0) return;

        string content = OutputTextBox.Text ?? string.Empty;
        string formatLabel = IsJsonMode ? "JSON" : "URI";

        if (ClipboardHelper.TrySetText(content, out string? error))
        {
            string msg = $"已复制 {selected.Count} 个代理节点 ({formatLabel}) 到剪贴板";
            LastStatusMessage = msg;
            ShowFeedback(msg, isError: false);
        }
        else
        {
            string msg = $"复制到剪贴板失败: {error}";
            LastStatusMessage = msg;
            ShowFeedback(msg, isError: true);
            System.Windows.MessageBox.Show(
                this,
                $"未能写入系统剪贴板（{error}）。\n\n您可以在右侧预览框中全选 (Ctrl+A) 后手动复制 (Ctrl+C)，或点击“保存为文件”。",
                "导出代理节点",
                System.Windows.MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
    }

    private void OnSaveFileClick(object sender, RoutedEventArgs e)
    {
        List<ProxyProfile> selected = SelectedProxies;
        if (selected.Count == 0) return;

        bool isJson = IsJsonMode;
        string ext = isJson ? ".json" : ".txt";
        var dlg = new SaveFileDialog
        {
            Title = "保存导出的代理节点",
            Filter = isJson
                ? "JSON 配置文件 (*.json)|*.json|所有文件 (*.*)|*.*"
                : "代理 URI 文本文件 (*.txt)|*.txt|所有文件 (*.*)|*.*",
            DefaultExt = ext,
            FileName = $"appproxy-proxies-{DateTime.Now:yyyyMMdd}{ext}"
        };

        if (dlg.ShowDialog(this) != true)
        {
            return;
        }

        try
        {
            File.WriteAllText(dlg.FileName, OutputTextBox.Text ?? string.Empty, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            string msg = $"已保存 {selected.Count} 个代理节点到 {Path.GetFileName(dlg.FileName)}";
            LastStatusMessage = msg;
            ShowFeedback(msg, isError: false);
        }
        catch (Exception ex)
        {
            string msg = $"保存导出文件失败: {ex.Message}";
            LastStatusMessage = msg;
            ShowFeedback(msg, isError: true);
            System.Windows.MessageBox.Show(
                this,
                msg,
                "导出代理节点",
                System.Windows.MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
    }

    private void ShowFeedback(string message, bool isError)
    {
        FeedbackTextBlock.Text = message;
        FeedbackBorder.Background = (TryFindResource(isError ? "SemanticErrorBgBrush" : "SemanticSuccessBgBrush") as Brush)
            ?? (isError ? Brushes.MistyRose : Brushes.Honeydew);
        FeedbackBorder.BorderBrush = (TryFindResource(isError ? "SemanticErrorBorderBrush" : "SemanticSuccessBorderBrush") as Brush)
            ?? (isError ? Brushes.IndianRed : Brushes.MediumSeaGreen);
        FeedbackTextBlock.Foreground = (TryFindResource(isError ? "SemanticErrorBrush" : "SemanticSuccessBrush") as Brush)
            ?? (isError ? Brushes.Crimson : Brushes.SeaGreen);
        FeedbackBorder.Visibility = Visibility.Visible;
    }

    private void OnCloseClick(object sender, RoutedEventArgs e)
    {
        Close();
    }
}

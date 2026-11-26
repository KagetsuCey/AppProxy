using System.IO;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using AppProxy.Core.Models;
using AppProxy.Core.Services;
using AppProxy.UI.Services;
using Microsoft.Win32;
using Wpf.Ui.Controls;

namespace AppProxy.UI.Views;

public partial class ProxyBatchExportDialog : FluentWindow
{
    private readonly IReadOnlyList<ProxyProfile> _allProxies;
    private readonly IReadOnlyList<ProxyProfile> _filteredProxies;
    private readonly bool _showFilterOption;

    public string? LastStatusMessage { get; private set; }

    public ProxyBatchExportDialog(
        IReadOnlyList<ProxyProfile> allProxies,
        IReadOnlyList<ProxyProfile>? filteredProxies = null,
        bool isFiltered = false)
    {
        _allProxies = allProxies ?? [];
        _filteredProxies = filteredProxies ?? _allProxies;
        _showFilterOption = isFiltered && _filteredProxies.Count != _allProxies.Count;

        InitializeComponent();

        if (_showFilterOption)
        {
            FilteredOnlyCheckBox.Content = $"仅导出当前筛选结果 ({_filteredProxies.Count})";
            FilteredOnlyCheckBox.Visibility = Visibility.Visible;
        }

        RefreshOutput();
    }

    private bool IsJsonMode =>
        string.Equals((FormatCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString(), "Json", StringComparison.OrdinalIgnoreCase);

    private IReadOnlyList<ProxyProfile> ActiveProxies =>
        _showFilterOption && FilteredOnlyCheckBox.IsChecked == true
            ? _filteredProxies
            : _allProxies;

    private void OnOptionChanged(object sender, RoutedEventArgs e)
    {
        RefreshOutput();
    }

    private void RefreshOutput()
    {
        if (!IsInitialized || OutputTextBox is null || FormatCombo is null || SummaryTextBlock is null)
        {
            return;
        }

        IReadOnlyList<ProxyProfile> target = ActiveProxies;
        OutputTextBox.Text = IsJsonMode
            ? ProxyBatchParser.ExportToJson(target)
            : ProxyBatchParser.ExportToUriLines(target);

        SummaryTextBlock.Text = $"共导出 {target.Count} 个代理节点";
        if (FeedbackBorder is not null)
        {
            FeedbackBorder.Visibility = Visibility.Collapsed;
        }
    }

    private void OnCopyClipboardClick(object sender, RoutedEventArgs e)
    {
        string content = OutputTextBox.Text ?? string.Empty;
        int count = ActiveProxies.Count;
        string formatLabel = IsJsonMode ? "JSON" : "URI";

        if (ClipboardHelper.TrySetText(content, out string? error))
        {
            string msg = $"已复制 {count} 个代理节点 ({formatLabel}) 到剪贴板";
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
                $"未能写入系统剪贴板（{error}）。\n\n您可以在上方预览框中全选 (Ctrl+A) 后手动复制 (Ctrl+C)，或点击“保存为文件”。",
                "导出代理节点",
                System.Windows.MessageBoxButton.OK,
                MessageBoxImage.Warning);
        }
    }

    private void OnSaveFileClick(object sender, RoutedEventArgs e)
    {
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
            string msg = $"已保存 {ActiveProxies.Count} 个代理节点到 {Path.GetFileName(dlg.FileName)}";
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

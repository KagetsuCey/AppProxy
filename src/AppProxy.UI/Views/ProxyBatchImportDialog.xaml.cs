using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using AppProxy.Core.Models;
using AppProxy.Core.Services;
using Microsoft.Win32;
using Wpf.Ui.Controls;

namespace AppProxy.UI.Views;

public partial class ProxyBatchImportDialog : FluentWindow
{
    private sealed record PreviewRow(
        string ProtocolText,
        string Name,
        string EndpointText,
        string StatusText,
        Brush StatusBrush);

    private readonly HashSet<string> _existingKeys;
    private readonly List<ProxyProfile> _importable = new();

    public IReadOnlyList<ProxyProfile> ImportedProxies { get; private set; } = [];
    public bool SkipDuplicates { get; private set; } = true;

    public ProxyBatchImportDialog(IEnumerable<ProxyProfile> existingProxies)
    {
        InitializeComponent();
        _existingKeys = new HashSet<string>(
            existingProxies.Select(ProxyBatchParser.BuildDedupeKey),
            StringComparer.Ordinal);
    }

    private void OnPasteClipboardClick(object sender, RoutedEventArgs e)
    {
        try
        {
            if (Clipboard.ContainsText())
            {
                InputTextBox.Text = Clipboard.GetText();
            }
        }
        catch
        {
        }
    }

    private void OnOpenFileClick(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Filter = "代理列表或配置文件 (*.txt;*.json)|*.txt;*.json|所有文件 (*.*)|*.*",
            Title = "选择包含代理节点的文本或 JSON 文件"
        };
        if (dlg.ShowDialog(this) == true)
        {
            try
            {
                InputTextBox.Text = File.ReadAllText(dlg.FileName);
            }
            catch (Exception ex)
            {
                System.Windows.MessageBox.Show(
                    this,
                    $"读取文件失败: {ex.Message}",
                    "批量导入",
                    System.Windows.MessageBoxButton.OK,
                    MessageBoxImage.Warning);
            }
        }
    }

    private void OnClearClick(object sender, RoutedEventArgs e)
    {
        InputTextBox.Clear();
    }

    private void OnProtocolSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        RefreshPreview();
    }

    private void OnInputOrOptionChanged(object sender, RoutedEventArgs e)
    {
        RefreshPreview();
    }

    private void RefreshPreview()
    {
        if (!IsInitialized || InputTextBox is null || DefaultProtocolCombo is null ||
            SkipDuplicatesCheckBox is null || PreviewListView is null ||
            SummaryTextBlock is null || ImportButton is null)
        {
            return;
        }

        string tag = (DefaultProtocolCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "Socks5";
        ProxyProtocol defaultProtocol = Enum.TryParse<ProxyProtocol>(tag, out var proto) ? proto : ProxyProtocol.Socks5;
        bool skipDuplicates = SkipDuplicatesCheckBox.IsChecked == true;

        ProxyBatchParseResult parsed = ProxyBatchParser.Parse(InputTextBox.Text, defaultProtocol);
        _importable.Clear();

        var previewRows = new List<PreviewRow>(parsed.Proxies.Count);
        var seenInBatch = new HashSet<string>(_existingKeys, StringComparer.Ordinal);
        int skippedCount = 0;

        Brush okBrush = TryFindResource("SemanticSuccessBrush") as Brush ?? Brushes.MediumSeaGreen;
        Brush warnBrush = TryFindResource("SemanticWarningBrush") as Brush ?? Brushes.Goldenrod;

        foreach (ProxyProfile proxy in parsed.Proxies)
        {
            string key = ProxyBatchParser.BuildDedupeKey(proxy);
            bool isDuplicate = !seenInBatch.Add(key);
            string authTag = proxy.HasAuth ? " (认证)" : string.Empty;

            if (skipDuplicates && isDuplicate)
            {
                skippedCount++;
                previewRows.Add(new PreviewRow(
                    proxy.ProtocolDisplay,
                    proxy.Name,
                    proxy.EndpointDisplay + authTag,
                    "重复跳过",
                    warnBrush));
            }
            else
            {
                _importable.Add(proxy);
                previewRows.Add(new PreviewRow(
                    proxy.ProtocolDisplay,
                    proxy.Name,
                    proxy.EndpointDisplay + authTag,
                    "待导入",
                    okBrush));
            }
        }

        PreviewListView.ItemsSource = previewRows;
        ImportButton.Content = $"导入 ({_importable.Count})";
        ImportButton.IsEnabled = _importable.Count > 0;

        if (string.IsNullOrWhiteSpace(InputTextBox.Text))
        {
            SummaryTextBlock.Text = "请在上方粘贴或打开代理节点列表";
        }
        else
        {
            SummaryTextBlock.Text = $"解析完成: 可导入 {_importable.Count} 个，跳过重复 {skippedCount} 个，格式错误 {parsed.Errors.Count} 行";
        }

        if (parsed.Errors.Count > 0)
        {
            ErrorBoxBorder.Visibility = Visibility.Visible;
            ErrorDetailsTextBlock.Text = string.Join(
                Environment.NewLine,
                parsed.Errors.Select(err => $"第 {err.LineNumber} 行: {err.Reason}  [{err.RawLine}]"));
        }
        else
        {
            ErrorBoxBorder.Visibility = Visibility.Collapsed;
            ErrorDetailsTextBlock.Text = string.Empty;
        }
    }

    private void OnImportClick(object sender, RoutedEventArgs e)
    {
        ImportedProxies = _importable.ToArray();
        SkipDuplicates = SkipDuplicatesCheckBox.IsChecked == true;
        DialogResult = true;
        Close();
    }

    private void OnCancelClick(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}

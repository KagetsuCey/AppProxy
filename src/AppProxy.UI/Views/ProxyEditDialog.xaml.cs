using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using AppProxy.Core.Models;
using AppProxy.Core.Services;
using AppProxy.UI.Services;
using Wpf.Ui.Controls;

namespace AppProxy.UI.Views;

public partial class ProxyEditDialog : FluentWindow
{
    private readonly bool _xrayAvailable;
    private readonly bool _allowVlessOption;
    private string _vlessHeaderType = "none";

    public ProxyProfile ResultProxy { get; private set; }

    public ProxyEditDialog(ProxyProfile? existing, bool isCloneMode = false, bool xrayAvailable = false)
    {
        _xrayAvailable = xrayAvailable;
        InitializeComponent();

        ResultProxy = existing?.Clone() ?? new ProxyProfile();

        _allowVlessOption = _xrayAvailable || ResultProxy.Protocol == ProxyProtocol.Vless;
        if (!_allowVlessOption)
        {
            ProtocolCombo.Items.Remove(VlessProtocolItem);
            QuickFillHintText.Text = "支持 socks5:// · http(s):// · host:port:user:pass · user:pass@host:port · 单节点 JSON（配置 Xray-core 后解锁 vless://）";
        }
        else
        {
            BannerSubtitleText.Text = "支持 SOCKS5、HTTP CONNECT、HTTPS TLS 与 VLESS (Xray-core) 隧道转发";
            QuickFillHintText.Text = "支持 socks5:// · http(s):// · vless:// · host:port:user:pass · user:pass@host:port · 单节点 JSON";
        }

        if (ResultProxy.Protocol == ProxyProtocol.Vless && !_xrayAvailable)
        {
            XrayMissingWarningBorder.Visibility = Visibility.Visible;
        }

        if (isCloneMode)
        {
            Title = "克隆代理节点";
            DialogTitleBar.Title = "克隆代理节点";
            BannerTitleText.Text = "基于已有节点克隆新配置";
        }

        PopulateFieldsFromProfile(ResultProxy);
        DataObject.AddPastingHandler(QuickLinkBox, OnQuickLinkPasting);

        if (isCloneMode)
        {
            Loaded += (_, _) =>
            {
                NameBox.Focus();
                NameBox.SelectAll();
            };
        }
    }

    private void PopulateFieldsFromProfile(ProxyProfile profile)
    {
        NameBox.Text = profile.Name;
        HostBox.Text = profile.Host;
        PortBox.Text = profile.Port.ToString();
        UsernameBox.Text = profile.Username;
        PasswordInput.Password = profile.Password;

        VlessSettings v = profile.Vless ?? new VlessSettings();
        _vlessHeaderType = string.IsNullOrWhiteSpace(v.HeaderType) ? "none" : v.HeaderType;
        VlessUuidBox.Text = v.Uuid;
        VlessEncryptionBox.Text = string.IsNullOrWhiteSpace(v.Encryption) ? "none" : v.Encryption;
        VlessFlowCombo.Text = v.Flow;
        SelectComboByTag(VlessNetworkCombo, v.NormalizedNetwork, "tcp");
        SelectComboByTag(VlessSecurityCombo, v.NormalizedSecurity, "reality");
        VlessSniBox.Text = v.Sni;
        VlessFingerprintCombo.Text = string.IsNullOrWhiteSpace(v.Fingerprint) ? "chrome" : v.Fingerprint;
        VlessPublicKeyBox.Text = v.PublicKey;
        VlessShortIdBox.Text = v.ShortId;
        VlessSpiderXBox.Text = v.SpiderX;
        VlessAlpnBox.Text = v.Alpn;
        VlessAllowInsecureCheck.IsChecked = v.AllowInsecure;
        VlessPathBox.Text = v.Path;
        VlessHostHeaderBox.Text = v.HostHeader;
        VlessServiceNameBox.Text = v.ServiceName;
        VlessModeBox.Text = v.Mode;

        SelectComboByTag(ProtocolCombo, profile.Protocol.ToString(), "Socks5");
        UpdateProtocolPanels();
    }

    private static void SelectComboByTag(ComboBox combo, string tag, string fallbackTag)
    {
        foreach (object? itemObj in combo.Items)
        {
            if (itemObj is ComboBoxItem item &&
                string.Equals(item.Tag?.ToString(), tag, StringComparison.OrdinalIgnoreCase))
            {
                combo.SelectedItem = item;
                return;
            }
        }

        foreach (object? itemObj in combo.Items)
        {
            if (itemObj is ComboBoxItem item &&
                string.Equals(item.Tag?.ToString(), fallbackTag, StringComparison.OrdinalIgnoreCase))
            {
                combo.SelectedItem = item;
                return;
            }
        }

        if (combo.Items.Count > 0)
        {
            combo.SelectedIndex = 0;
        }
    }

    private void OnProtocolSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsInitialized) return;
        UpdateProtocolPanels();
    }

    private void OnVlessOptionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsInitialized) return;
        UpdateProtocolPanels();
    }

    private void UpdateProtocolPanels()
    {
        if (ProtocolCombo is null || StandardAuthPanel is null || VlessSettingsPanel is null) return;

        string protoTag = (ProtocolCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "Socks5";
        bool isVless = string.Equals(protoTag, "Vless", StringComparison.OrdinalIgnoreCase);

        StandardAuthPanel.Visibility = isVless ? Visibility.Collapsed : Visibility.Visible;
        VlessSettingsPanel.Visibility = isVless ? Visibility.Visible : Visibility.Collapsed;

        if (!isVless) return;

        string secTag = ((VlessSecurityCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "none").ToLowerInvariant();
        string netTag = ((VlessNetworkCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "tcp").ToLowerInvariant();

        VlessTlsCommonPanel.Visibility = secTag is "reality" or "tls" ? Visibility.Visible : Visibility.Collapsed;
        VlessRealityPanel.Visibility = secTag == "reality" ? Visibility.Visible : Visibility.Collapsed;
        VlessTlsExtraPanel.Visibility = secTag == "tls" ? Visibility.Visible : Visibility.Collapsed;
        VlessTransportExtraPanel.Visibility = netTag != "tcp" ? Visibility.Visible : Visibility.Collapsed;
    }

    private void OnQuickLinkPasting(object sender, DataObjectPastingEventArgs e)
    {
        Dispatcher.BeginInvoke(() =>
        {
            ApplyQuickLinkText(QuickLinkBox.Text, fromAutoPaste: true);
        }, DispatcherPriority.Background);
    }

    private void OnQuickLinkKeyDown(object sender, KeyEventArgs e)
    {
        if (e.Key == Key.Enter)
        {
            e.Handled = true;
            ApplyQuickLinkText(QuickLinkBox.Text, fromAutoPaste: false);
        }
    }

    private void OnParseQuickLinkClick(object sender, RoutedEventArgs e)
    {
        ApplyQuickLinkText(QuickLinkBox.Text, fromAutoPaste: false);
    }

    private void OnPasteQuickLinkClick(object sender, RoutedEventArgs e)
    {
        if (!ClipboardHelper.TryGetText(out string raw, out string? error))
        {
            ShowQuickFillFeedback($"读取剪贴板失败: {error}", isError: true);
            return;
        }

        string trimmed = raw.Trim();
        if (string.IsNullOrEmpty(trimmed))
        {
            ShowQuickFillFeedback("剪贴板中没有文本内容，请先复制代理链接。", isError: true);
            return;
        }

        QuickLinkBox.Text = trimmed;
        ApplyQuickLinkText(trimmed, fromAutoPaste: false);
    }

    private void ApplyQuickLinkText(string raw, bool fromAutoPaste)
    {
        string trimmed = (raw ?? string.Empty).Trim();
        if (string.IsNullOrEmpty(trimmed))
        {
            if (!fromAutoPaste)
            {
                ShowQuickFillFeedback("请先粘贴或输入单个代理链接。", isError: true);
            }
            else if (QuickFillFeedbackBorder is not null)
            {
                QuickFillFeedbackBorder.Visibility = Visibility.Collapsed;
            }
            return;
        }

        string tag = (ProtocolCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "Socks5";
        ProxyProtocol defaultProtocol = Enum.TryParse<ProxyProtocol>(tag, out var proto) && proto != ProxyProtocol.Vless
            ? proto
            : ProxyProtocol.Socks5;

        if (!ProxyBatchParser.TryParseSingle(
                trimmed,
                defaultProtocol,
                _allowVlessOption,
                out ProxyProfile? parsed,
                out string error,
                out int totalCount) ||
            parsed is null)
        {
            ShowQuickFillFeedback(error, isError: true);
            return;
        }

        PopulateFieldsFromProfile(parsed);

        string okMsg = totalCount > 1
            ? $"✓ 已解析第 1 条链接并填充（{parsed.ProtocolDisplay} · {parsed.Host}:{parsed.Port}）；共检测到 {totalCount} 条，多节点请使用「批量导入」"
            : $"✓ 已自动填充: {parsed.ProtocolDisplay} · {parsed.Name} ({parsed.Host}:{parsed.Port})";
        ShowQuickFillFeedback(okMsg, isError: false);
    }

    private void ShowQuickFillFeedback(string message, bool isError)
    {
        QuickFillFeedbackText.Text = message;
        QuickFillFeedbackBorder.Background = (TryFindResource(isError ? "SemanticErrorBgBrush" : "SemanticSuccessBgBrush") as Brush)
            ?? (isError ? Brushes.MistyRose : Brushes.Honeydew);
        QuickFillFeedbackBorder.BorderBrush = (TryFindResource(isError ? "SemanticErrorBorderBrush" : "SemanticSuccessBorderBrush") as Brush)
            ?? (isError ? Brushes.IndianRed : Brushes.MediumSeaGreen);
        QuickFillFeedbackText.Foreground = (TryFindResource(isError ? "SemanticErrorBrush" : "SemanticSuccessBrush") as Brush)
            ?? (isError ? Brushes.Crimson : Brushes.SeaGreen);
        QuickFillFeedbackBorder.Visibility = Visibility.Visible;
    }

    private void OnSave(object sender, RoutedEventArgs e)
    {
        string host = HostBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(host))
        {
            System.Windows.MessageBox.Show(this, "请输入代理服务器地址。", "提示", System.Windows.MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (!int.TryParse(PortBox.Text.Trim(), out int port) || port < 1 || port > 65535)
        {
            System.Windows.MessageBox.Show(this, "请输入有效的端口号 (1 - 65535)。", "提示", System.Windows.MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        string tag = (ProtocolCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "Socks5";
        ProxyProtocol newProto = Enum.TryParse<ProxyProtocol>(tag, out var proto) ? proto : ProxyProtocol.Socks5;

        VlessSettings? newVless = null;
        if (newProto == ProxyProtocol.Vless)
        {
            newVless = new VlessSettings
            {
                Uuid = VlessUuidBox.Text.Trim(),
                Encryption = string.IsNullOrWhiteSpace(VlessEncryptionBox.Text) ? "none" : VlessEncryptionBox.Text.Trim(),
                Flow = VlessFlowCombo.Text?.Trim() ?? string.Empty,
                Network = (VlessNetworkCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "tcp",
                HeaderType = _vlessHeaderType,
                Security = (VlessSecurityCombo.SelectedItem as ComboBoxItem)?.Tag?.ToString() ?? "reality",
                Sni = VlessSniBox.Text.Trim(),
                Fingerprint = VlessFingerprintCombo.Text?.Trim() ?? string.Empty,
                PublicKey = VlessPublicKeyBox.Text.Trim(),
                ShortId = VlessShortIdBox.Text.Trim(),
                SpiderX = VlessSpiderXBox.Text.Trim(),
                Alpn = VlessAlpnBox.Text.Trim(),
                AllowInsecure = VlessAllowInsecureCheck.IsChecked == true,
                Path = VlessPathBox.Text.Trim(),
                HostHeader = VlessHostHeaderBox.Text.Trim(),
                ServiceName = VlessServiceNameBox.Text.Trim(),
                Mode = VlessModeBox.Text.Trim()
            };

            if (!newVless.Validate(out string vlessErr))
            {
                System.Windows.MessageBox.Show(this, vlessErr, "VLESS 参数校验失败", System.Windows.MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
        }

        bool endpointChanged =
            ResultProxy.Protocol != newProto ||
            !string.Equals(ResultProxy.Host, host, StringComparison.OrdinalIgnoreCase) ||
            ResultProxy.Port != port ||
            (newProto == ProxyProtocol.Vless && (
                !string.Equals(ResultProxy.Vless?.Uuid, newVless?.Uuid, StringComparison.OrdinalIgnoreCase) ||
                !string.Equals(ResultProxy.Vless?.PublicKey, newVless?.PublicKey, StringComparison.Ordinal) ||
                !string.Equals(ResultProxy.Vless?.Sni, newVless?.Sni, StringComparison.OrdinalIgnoreCase)));

        ResultProxy.Protocol = newProto;
        ResultProxy.Host = host;
        ResultProxy.Port = port;
        ResultProxy.Name = string.IsNullOrWhiteSpace(NameBox.Text) ? $"{ResultProxy.ProtocolDisplay} {host}:{port}" : NameBox.Text.Trim();

        if (newProto == ProxyProtocol.Vless)
        {
            ResultProxy.Username = string.Empty;
            ResultProxy.Password = string.Empty;
            ResultProxy.Vless = newVless;
        }
        else
        {
            ResultProxy.Username = UsernameBox.Text.Trim();
            ResultProxy.Password = PasswordInput.Password ?? string.Empty;
            ResultProxy.Vless = null;
        }

        if (endpointChanged)
        {
            ResultProxy.ExitIp = string.Empty;
            ResultProxy.ExitCountryCode = string.Empty;
            ResultProxy.ExitLocation = string.Empty;
            ResultProxy.ExitIsp = string.Empty;
            ResultProxy.ExitDetectError = string.Empty;
            ResultProxy.IsExitIpCopied = false;
        }

        DialogResult = true;
        Close();
    }

    private void OnCancel(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}

using System.Windows;
using System.Windows.Controls;
using AppProxy.Core.Models;
using AppProxy.Core.Services;
using Wpf.Ui.Controls;

namespace AppProxy.UI.Views;

public partial class ProxyEditDialog : FluentWindow
{
    private readonly bool _xrayAvailable;

    public ProxyProfile ResultProxy { get; private set; }

    public ProxyEditDialog(ProxyProfile? existing, bool isCloneMode = false, bool xrayAvailable = false)
    {
        _xrayAvailable = xrayAvailable;
        InitializeComponent();

        ResultProxy = existing?.Clone() ?? new ProxyProfile();

        bool allowVlessOption = _xrayAvailable || ResultProxy.Protocol == ProxyProtocol.Vless;
        if (!allowVlessOption)
        {
            ProtocolCombo.Items.Remove(VlessProtocolItem);
        }
        else
        {
            BannerSubtitleText.Text = "支持 SOCKS5、HTTP CONNECT、HTTPS TLS 与 VLESS (Xray-core) 隧道转发";
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

    private void OnPasteVlessUriClick(object sender, RoutedEventArgs e)
    {
        try
        {
            if (!Clipboard.ContainsText())
            {
                System.Windows.MessageBox.Show(this, "剪贴板中没有文本内容。", "粘贴 VLESS 链接", System.Windows.MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            string raw = Clipboard.GetText().Trim();
            ProxyBatchParseResult parsed = ProxyBatchParser.Parse(raw, ProxyProtocol.Vless, allowXrayProtocols: true);
            ProxyProfile? vless = parsed.Proxies.FirstOrDefault(p => p.Protocol == ProxyProtocol.Vless);
            if (vless is null)
            {
                string reason = parsed.Errors.FirstOrDefault()?.Reason ?? "未能从剪贴板解析出有效的 vless:// 链接。";
                System.Windows.MessageBox.Show(this, reason, "粘贴 VLESS 链接", System.Windows.MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            PopulateFieldsFromProfile(vless);
        }
        catch (Exception ex)
        {
            System.Windows.MessageBox.Show(this, $"读取剪贴板失败: {ex.Message}", "粘贴 VLESS 链接", System.Windows.MessageBoxButton.OK, MessageBoxImage.Warning);
        }
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
                HeaderType = ResultProxy.Vless?.HeaderType ?? "none",
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

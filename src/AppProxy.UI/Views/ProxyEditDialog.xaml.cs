using System.Windows;
using System.Windows.Controls;
using AppProxy.Core.Models;
using Wpf.Ui.Controls;

namespace AppProxy.UI.Views;

public partial class ProxyEditDialog : FluentWindow
{
    public ProxyProfile ResultProxy { get; private set; }

    public ProxyEditDialog(ProxyProfile? existing, bool isCloneMode = false)
    {
        InitializeComponent();

        ResultProxy = existing?.Clone() ?? new ProxyProfile();

        if (isCloneMode)
        {
            Title = "克隆代理节点";
            DialogTitleBar.Title = "克隆代理节点";
            BannerTitleText.Text = "基于已有节点克隆新配置";
        }

        NameBox.Text = ResultProxy.Name;
        HostBox.Text = ResultProxy.Host;
        PortBox.Text = ResultProxy.Port.ToString();
        UsernameBox.Text = ResultProxy.Username;
        PasswordInput.Password = ResultProxy.Password;

        ProtocolCombo.SelectedIndex = ResultProxy.Protocol switch
        {
            ProxyProtocol.Socks5 => 0,
            ProxyProtocol.Http => 1,
            ProxyProtocol.Https => 2,
            _ => 0
        };

        if (isCloneMode)
        {
            Loaded += (_, _) =>
            {
                NameBox.Focus();
                NameBox.SelectAll();
            };
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
        bool endpointChanged =
            ResultProxy.Protocol != newProto ||
            !string.Equals(ResultProxy.Host, host, StringComparison.OrdinalIgnoreCase) ||
            ResultProxy.Port != port;

        ResultProxy.Protocol = newProto;
        ResultProxy.Host = host;
        ResultProxy.Port = port;
        ResultProxy.Name = string.IsNullOrWhiteSpace(NameBox.Text) ? $"{ResultProxy.ProtocolDisplay} {host}:{port}" : NameBox.Text.Trim();
        ResultProxy.Username = UsernameBox.Text.Trim();
        ResultProxy.Password = PasswordInput.Password ?? string.Empty;

        if (endpointChanged)
        {
            ResultProxy.ExitIp = string.Empty;
            ResultProxy.ExitCountryCode = string.Empty;
            ResultProxy.ExitLocation = string.Empty;
            ResultProxy.ExitIsp = string.Empty;
            ResultProxy.ExitDetectError = string.Empty;
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

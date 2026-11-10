using System.Windows;
using System.Windows.Controls;
using AppProxy.UI.Models;
using Wpf.Ui.Controls;

namespace AppProxy.UI.Views;

public partial class ProxyEditDialog : FluentWindow
{
    public ProxyProfile ResultProxy { get; private set; }

    public ProxyEditDialog(ProxyProfile? existing)
    {
        InitializeComponent();

        ResultProxy = existing?.Clone() ?? new ProxyProfile();

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
        ResultProxy.Protocol = Enum.TryParse<ProxyProtocol>(tag, out var proto) ? proto : ProxyProtocol.Socks5;
        ResultProxy.Host = host;
        ResultProxy.Port = port;
        ResultProxy.Name = string.IsNullOrWhiteSpace(NameBox.Text) ? $"{ResultProxy.ProtocolDisplay} {host}:{port}" : NameBox.Text.Trim();
        ResultProxy.Username = UsernameBox.Text.Trim();
        ResultProxy.Password = PasswordInput.Password ?? string.Empty;

        DialogResult = true;
        Close();
    }

    private void OnCancel(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}

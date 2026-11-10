using System.IO;
using System.Windows;
using AppProxy.UI.Models;
using Microsoft.Win32;
using Wpf.Ui.Controls;

namespace AppProxy.UI.Views;

public partial class AppEditDialog : FluentWindow
{
    private sealed record ProxyChoice(Guid? Id, string DisplayName);

    public AppProfile ResultApp { get; private set; }

    public AppEditDialog(AppProfile? existing, IEnumerable<ProxyProfile> proxies)
    {
        InitializeComponent();

        ResultApp = existing?.Clone() ?? new AppProfile();

        var choices = new List<ProxyChoice> { new(null, "直连 (Direct - 不走代理)") };
        choices.AddRange(proxies.Select(p => new ProxyChoice(p.Id, $"{p.Name} ({p.ProtocolDisplay} {p.EndpointDisplay})")));
        ProxyCombo.ItemsSource = choices;

        NameBox.Text = ResultApp.Name;
        ExePathBox.Text = ResultApp.ExePath;
        ArgsBox.Text = ResultApp.Arguments;
        WorkDirBox.Text = ResultApp.WorkingDirectory;
        ProxyCombo.SelectedValue = ResultApp.ProxyProfileId;
        if (ProxyCombo.SelectedItem is null)
        {
            ProxyCombo.SelectedIndex = 0;
        }

        RemoteDnsToggle.IsChecked = ResultApp.RemoteDns;
        BypassLanToggle.IsChecked = ResultApp.BypassLan;
        InjectChildrenToggle.IsChecked = ResultApp.InjectChildren;
    }

    private void OnBrowseExe(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Filter = "可执行文件 (*.exe)|*.exe|所有文件 (*.*)|*.*",
            Title = "选择要注入代理的应用程序"
        };
        if (dlg.ShowDialog(this) == true)
        {
            ExePathBox.Text = dlg.FileName;
            if (string.IsNullOrWhiteSpace(NameBox.Text))
            {
                NameBox.Text = Path.GetFileNameWithoutExtension(dlg.FileName);
            }
            if (string.IsNullOrWhiteSpace(WorkDirBox.Text))
            {
                WorkDirBox.Text = Path.GetDirectoryName(dlg.FileName) ?? string.Empty;
            }
        }
    }

    private void OnSave(object sender, RoutedEventArgs e)
    {
        string exePath = ExePathBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(exePath))
        {
            System.Windows.MessageBox.Show(this, "请填写或选择可执行文件路径。", "提示", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        ResultApp.Name = string.IsNullOrWhiteSpace(NameBox.Text)
            ? Path.GetFileNameWithoutExtension(exePath)
            : NameBox.Text.Trim();
        ResultApp.ExePath = exePath;
        ResultApp.Arguments = ArgsBox.Text.Trim();
        ResultApp.WorkingDirectory = WorkDirBox.Text.Trim();
        ResultApp.ProxyProfileId = (ProxyCombo.SelectedItem as ProxyChoice)?.Id;
        ResultApp.RemoteDns = RemoteDnsToggle.IsChecked == true;
        ResultApp.BypassLan = BypassLanToggle.IsChecked == true;
        ResultApp.InjectChildren = InjectChildrenToggle.IsChecked == true;

        DialogResult = true;
        Close();
    }

    private void OnCancel(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}

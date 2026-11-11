using System.IO;
using System.Windows;
using AppProxy.UI.Models;
using AppProxy.UI.Services;
using Microsoft.Win32;
using Wpf.Ui.Controls;

namespace AppProxy.UI.Views;

public partial class AppEditDialog : FluentWindow
{
    private sealed record ProxyChoice(Guid? Id, string DisplayName);
    private bool _isolateToggledByUser;

    public AppProfile ResultApp { get; private set; }

    public AppEditDialog(AppProfile? existing, IEnumerable<ProxyProfile> proxies)
    {
        InitializeComponent();

        ResultApp = existing?.Clone() ?? new AppProfile();
        _isolateToggledByUser = existing is not null;

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
        IgnoreSystemProxyToggle.IsChecked = ResultApp.IgnoreSystemProxy;
        IsolateProfileToggle.IsChecked = ResultApp.GetEffectiveIsolateProfileDir();
        MaxInstancesBox.Text = ResultApp.MaxInstances.ToString();
        UpdateStepperButtonState();
    }

    private void OnDecrementMaxInstances(object sender, RoutedEventArgs e)
    {
        int current = int.TryParse(MaxInstancesBox.Text.Trim(), out int parsed) ? parsed : 1;
        int next = Math.Max(1, current - 1);
        MaxInstancesBox.Text = next.ToString();
        UpdateStepperButtonState();
    }

    private void OnIncrementMaxInstances(object sender, RoutedEventArgs e)
    {
        int current = int.TryParse(MaxInstancesBox.Text.Trim(), out int parsed) ? Math.Max(1, parsed) : 1;
        int next = current < int.MaxValue ? current + 1 : int.MaxValue;
        MaxInstancesBox.Text = next.ToString();
        UpdateStepperButtonState();
    }

    private void OnMaxInstancesTextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e)
    {
        UpdateStepperButtonState();
    }

    private void UpdateStepperButtonState()
    {
        if (!IsInitialized || DecrementMaxInstancesBtn is null || MaxInstancesBox is null)
        {
            return;
        }

        DecrementMaxInstancesBtn.IsEnabled =
            int.TryParse(MaxInstancesBox.Text.Trim(), out int parsed) && parsed > 1;
    }

    private void OnIsolateProfileClick(object sender, RoutedEventArgs e)
    {
        _isolateToggledByUser = true;
    }

    private void OnBrowseExe(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Filter = "应用程序与快捷方式 (*.exe;*.lnk)|*.exe;*.lnk|可执行文件 (*.exe)|*.exe|快捷方式 (*.lnk)|*.lnk|所有文件 (*.*)|*.*",
            Title = "选择要注入代理的应用程序或快捷方式",
            DereferenceLinks = false
        };
        if (dlg.ShowDialog(this) == true)
        {
            var resolved = ShortcutResolver.ResolveInputPath(dlg.FileName);
            if (!resolved.Ok)
            {
                System.Windows.MessageBox.Show(
                    this,
                    resolved.Error ?? "无法解析所选文件。",
                    "提示",
                    System.Windows.MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            ExePathBox.Text = resolved.TargetExePath;
            if (string.IsNullOrWhiteSpace(NameBox.Text))
            {
                NameBox.Text = resolved.DisplayName;
            }
            if (!string.IsNullOrWhiteSpace(resolved.Arguments) && string.IsNullOrWhiteSpace(ArgsBox.Text))
            {
                ArgsBox.Text = resolved.Arguments;
            }
            if (string.IsNullOrWhiteSpace(WorkDirBox.Text))
            {
                WorkDirBox.Text = resolved.WorkingDirectory;
            }
            if (!_isolateToggledByUser)
            {
                IsolateProfileToggle.IsChecked = AppProfile.IsChromiumBrowserExe(resolved.TargetExePath);
            }
        }
    }

    private void OnSave(object sender, RoutedEventArgs e)
    {
        string exePath = ExePathBox.Text.Trim();
        if (string.IsNullOrWhiteSpace(exePath))
        {
            System.Windows.MessageBox.Show(this, "请填写或选择可执行文件路径。", "提示", System.Windows.MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (!int.TryParse(MaxInstancesBox.Text.Trim(), out int maxInstances) || maxInstances < 1)
        {
            System.Windows.MessageBox.Show(this, "最大运行实例数必须为不小于 1 的整数。", "提示", System.Windows.MessageBoxButton.OK, MessageBoxImage.Information);
            MaxInstancesBox.Focus();
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
        ResultApp.IgnoreSystemProxy = IgnoreSystemProxyToggle.IsChecked == true;
        ResultApp.MaxInstances = maxInstances;
        ResultApp.IsolateProfileDir = IsolateProfileToggle.IsChecked == true;

        DialogResult = true;
        Close();
    }

    private void OnCancel(object sender, RoutedEventArgs e)
    {
        DialogResult = false;
        Close();
    }
}

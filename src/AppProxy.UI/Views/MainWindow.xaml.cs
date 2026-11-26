using System.Windows;
using System.Windows.Controls;
using AppProxy.Core.Models;
using Wpf.Ui.Controls;

namespace AppProxy.UI.Views;

public partial class MainWindow : FluentWindow
{
    public MainWindow()
    {
        InitializeComponent();
        DataContext = App.ViewModel;
    }

    private void OnOpenMonitorClick(object sender, RoutedEventArgs e)
    {
        App.ViewModel.SelectedNavIndex = 2;
    }

    private void OnAddAppClick(object sender, RoutedEventArgs e)
    {
        var dlg = new AppEditDialog(null, App.ViewModel.Proxies) { Owner = this };
        if (dlg.ShowDialog() == true)
        {
            App.ViewModel.AddOrUpdateApp(dlg.ResultApp);
        }
    }

    private void OnEditAppClick(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is not AppProfile app) return;
        var dlg = new AppEditDialog(app, App.ViewModel.Proxies) { Owner = this };
        if (dlg.ShowDialog() == true)
        {
            App.ViewModel.AddOrUpdateApp(dlg.ResultApp);
        }
    }

    private void OnQuickProxyChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded) return;
        if ((sender as FrameworkElement)?.DataContext is AppProfile app)
        {
            App.ViewModel.SyncAppBoundProxyName(app);
            App.ViewModel.SaveConfiguration();
        }
    }

    private void OnAddProxyClick(object sender, RoutedEventArgs e)
    {
        var dlg = new ProxyEditDialog(null, xrayAvailable: App.ViewModel.IsXrayCoreAvailable) { Owner = this };
        if (dlg.ShowDialog() == true)
        {
            App.ViewModel.AddOrUpdateProxy(dlg.ResultProxy);
        }
    }

    private void OnBatchImportProxiesClick(object sender, RoutedEventArgs e)
    {
        var dlg = new ProxyBatchImportDialog(App.ViewModel.Proxies, App.ViewModel.IsXrayCoreAvailable) { Owner = this };
        if (dlg.ShowDialog() == true && dlg.ImportedProxies.Count > 0)
        {
            App.ViewModel.ImportProxies(dlg.ImportedProxies, dlg.SkipDuplicates);
        }
    }

    private void OnExportProxiesClick(object sender, RoutedEventArgs e)
    {
        if (App.ViewModel.Proxies.Count == 0)
        {
            App.ViewModel.StatusMessage = "暂无可导出的代理节点";
            System.Windows.MessageBox.Show(
                this,
                "当前暂无可导出的代理节点，请先添加或批量导入代理节点。",
                "导出代理节点",
                System.Windows.MessageBoxButton.OK,
                MessageBoxImage.Information);
            return;
        }

        var allProxies = App.ViewModel.Proxies.ToList();
        var filteredProxies = App.ViewModel.FilteredProxies.Cast<ProxyProfile>().ToList();
        bool isFiltered = App.ViewModel.HasActiveProxyFilter;
        var preselectedIds = App.ViewModel.GetSelectedProxyIds();

        var dlg = new ProxyBatchExportDialog(allProxies, filteredProxies, isFiltered, preselectedIds) { Owner = this };
        dlg.ShowDialog();
        if (!string.IsNullOrWhiteSpace(dlg.LastStatusMessage))
        {
            App.ViewModel.StatusMessage = dlg.LastStatusMessage;
        }
    }

    private void OnDeleteSelectedProxiesClick(object sender, RoutedEventArgs e)
    {
        List<ProxyProfile> selected = App.ViewModel.GetSelectedProxies();
        if (selected.Count == 0) return;

        var selectedIds = selected.Select(p => p.Id).ToHashSet();
        int affectedApps = App.ViewModel.Apps.Count(a => a.ProxyProfileId.HasValue && selectedIds.Contains(a.ProxyProfileId.Value));

        string prompt = affectedApps > 0
            ? $"确定要删除选中的 {selected.Count} 个代理节点吗？\n\n其中有 {affectedApps} 个应用正在绑定这些节点，删除后将自动切换为 Direct（直连）。"
            : $"确定要删除选中的 {selected.Count} 个代理节点吗？此操作无法撤销。";

        if (System.Windows.MessageBox.Show(
                this,
                prompt,
                "批量删除代理节点",
                System.Windows.MessageBoxButton.YesNo,
                MessageBoxImage.Question) == System.Windows.MessageBoxResult.Yes)
        {
            App.ViewModel.DeleteSelectedProxies();
        }
    }

    private void OnCloneProxyClick(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is not ProxyProfile proxy) return;
        int sourceIndex = App.ViewModel.Proxies.IndexOf(proxy);
        ProxyProfile draft = App.ViewModel.CreateClonedProxyDraft(proxy);
        var dlg = new ProxyEditDialog(draft, isCloneMode: true, xrayAvailable: App.ViewModel.IsXrayCoreAvailable) { Owner = this };
        if (dlg.ShowDialog() == true)
        {
            App.ViewModel.AddOrUpdateProxy(dlg.ResultProxy, insertAfterIndex: sourceIndex >= 0 ? sourceIndex : null);
        }
    }

    private void OnCopyProxyExitIpClick(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is not ProxyProfile proxy) return;
        App.ViewModel.CopyProxyExitIp(proxy);
    }

    private void OnEditProxyClick(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is not ProxyProfile proxy) return;
        var dlg = new ProxyEditDialog(proxy, xrayAvailable: App.ViewModel.IsXrayCoreAvailable) { Owner = this };
        if (dlg.ShowDialog() == true)
        {
            App.ViewModel.AddOrUpdateProxy(dlg.ResultProxy);
        }
    }

    private void OnBrowseXrayCoreClick(object sender, RoutedEventArgs e)
    {
        var dlg = new Microsoft.Win32.OpenFileDialog
        {
            Title = "选择 Xray-core 可执行文件 (xray.exe)",
            Filter = "xray.exe|xray.exe|可执行文件 (*.exe)|*.exe|所有文件 (*.*)|*.*"
        };
        if (dlg.ShowDialog(this) == true)
        {
            App.ViewModel.XrayCorePath = dlg.FileName;
        }
    }

    private void OnAppsDragOver(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop))
        {
            e.Effects = DragDropEffects.Copy;
            e.Handled = true;
            AppsDropOverlay.Visibility = Visibility.Visible;
        }
    }

    private void OnAppsDragLeave(object sender, DragEventArgs e)
    {
        Point pos = e.GetPosition(AppsPageRoot);
        if (pos.X <= 0 || pos.Y <= 0 || pos.X >= AppsPageRoot.ActualWidth || pos.Y >= AppsPageRoot.ActualHeight)
        {
            AppsDropOverlay.Visibility = Visibility.Collapsed;
        }
    }

    private void OnAppsDrop(object sender, DragEventArgs e)
    {
        AppsDropOverlay.Visibility = Visibility.Collapsed;
        if (e.Data.GetData(DataFormats.FileDrop) is string[] files)
        {
            foreach (string file in files)
            {
                App.ViewModel.AddQuickAppFromPath(file);
            }
        }
    }
}

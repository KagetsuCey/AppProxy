using System.Windows;
using System.Windows.Controls;
using AppProxy.UI.Models;
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
        var dlg = new ProxyEditDialog(null) { Owner = this };
        if (dlg.ShowDialog() == true)
        {
            App.ViewModel.AddOrUpdateProxy(dlg.ResultProxy);
        }
    }

    private void OnEditProxyClick(object sender, RoutedEventArgs e)
    {
        if ((sender as FrameworkElement)?.DataContext is not ProxyProfile proxy) return;
        var dlg = new ProxyEditDialog(proxy) { Owner = this };
        if (dlg.ShowDialog() == true)
        {
            App.ViewModel.AddOrUpdateProxy(dlg.ResultProxy);
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

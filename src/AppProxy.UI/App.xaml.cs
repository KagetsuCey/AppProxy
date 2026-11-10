using System.Windows;
using AppProxy.UI.ViewModels;
using Wpf.Ui.Appearance;

namespace AppProxy.UI;

public partial class App : Application
{
    public static MainViewModel ViewModel { get; private set; } = null!;

    protected override void OnStartup(StartupEventArgs e)
    {
        base.OnStartup(e);
        ViewModel = new MainViewModel();
        ApplicationThemeManager.Apply(ViewModel.IsDarkTheme ? ApplicationTheme.Dark : ApplicationTheme.Light);
    }

    protected override void OnExit(ExitEventArgs e)
    {
        ViewModel?.Dispose();
        base.OnExit(e);
    }
}

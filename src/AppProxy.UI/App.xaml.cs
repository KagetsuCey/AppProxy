using System.IO;
using System.Windows;
using System.Windows.Threading;
using AppProxy.UI.Services;
using AppProxy.UI.ViewModels;
using Wpf.Ui.Appearance;

namespace AppProxy.UI;

public partial class App : Application
{
    public static MainViewModel ViewModel { get; private set; } = null!;

    private int _fatalReported;

    protected override void OnStartup(StartupEventArgs e)
    {
        DispatcherUnhandledException += OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException += OnDomainUnhandledException;

        try
        {
            base.OnStartup(e);
            ViewModel = new MainViewModel();
            ApplyThemeSafe(ViewModel.IsDarkTheme);
            ThemeTokenHelper.ApplySemanticTokens(ViewModel.IsDarkTheme);
        }
        catch (Exception ex)
        {
            ReportFatalException("AppProxy 启动初始化失败", ex);
            Shutdown(1);
        }
    }

    protected override void OnExit(ExitEventArgs e)
    {
        DispatcherUnhandledException -= OnDispatcherUnhandledException;
        AppDomain.CurrentDomain.UnhandledException -= OnDomainUnhandledException;
        ViewModel?.Dispose();
        base.OnExit(e);
    }

    private static void ApplyThemeSafe(bool isDark)
    {
        var theme = isDark ? ApplicationTheme.Dark : ApplicationTheme.Light;
        try
        {
            ApplicationThemeManager.Apply(theme, Wpf.Ui.Controls.WindowBackdropType.Mica, updateAccent: false);
        }
        catch
        {
            try
            {
                ApplicationThemeManager.Apply(theme, Wpf.Ui.Controls.WindowBackdropType.None, updateAccent: false);
            }
            catch
            {
            }
        }
    }

    private void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
    {
        bool hasVisibleWindow = false;
        try
        {
            foreach (Window w in Windows)
            {
                if (w.IsVisible)
                {
                    hasVisibleWindow = true;
                    break;
                }
            }
        }
        catch
        {
        }

        ReportFatalException(
            hasVisibleWindow ? "AppProxy 运行时发生未处理异常" : "AppProxy 启动阶段发生未处理异常",
            e.Exception);

        e.Handled = true;
        if (!hasVisibleWindow)
        {
            Shutdown(1);
        }
    }

    private void OnDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        if (e.ExceptionObject is Exception ex)
        {
            ReportFatalException("AppProxy 发生致命异常", ex);
        }
    }

    private void ReportFatalException(string title, Exception ex)
    {
        string? logPath = TryWriteCrashLog(ex);
        if (Interlocked.Exchange(ref _fatalReported, 1) != 0)
        {
            return;
        }

        string details = logPath is not null
            ? $"{title}：\n\n{ex.GetType().Name}: {ex.Message}\n\n完整错误日志已写入：\n{logPath}"
            : $"{title}：\n\n{ex}";

        try
        {
            System.Windows.MessageBox.Show(details, "AppProxy 错误", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        catch
        {
        }
    }

    private static string? TryWriteCrashLog(Exception ex)
    {
        string content = $"[{DateTimeOffset.Now:O}] Unhandled Exception{Environment.NewLine}{ex}{Environment.NewLine}{new string('-', 60)}{Environment.NewLine}";
        string[] candidates =
        {
            Path.Combine(AppContext.BaseDirectory, "AppProxy.UI.crash.log"),
            Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "AppProxy", "AppProxy.UI.crash.log")
        };

        foreach (string path in candidates)
        {
            try
            {
                string? dir = Path.GetDirectoryName(path);
                if (!string.IsNullOrEmpty(dir))
                {
                    Directory.CreateDirectory(dir);
                }
                File.AppendAllText(path, content);
                return path;
            }
            catch
            {
            }
        }

        return null;
    }
}

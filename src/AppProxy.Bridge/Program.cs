using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using AppProxy.Core.Models;
using AppProxy.Core.Services;

namespace AppProxy.Bridge;

internal static class Program
{
    private const uint MB_OK = 0x00000000;
    private const uint MB_ICONERROR = 0x00000010;

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int MessageBoxW(IntPtr hWnd, string text, string caption, uint type);

    [STAThread]
    private static async Task<int> Main(string[] args)
    {
        bool directShortcutMode = false;
        try
        {
            string? launchB64 = null;
            string? launchAppIdRaw = null;
            bool launchFromStdin = false;

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--launch-b64" && i + 1 < args.Length)
                {
                    launchB64 = args[++i];
                }
                else if (args[i] == "--launch-app-id" && i + 1 < args.Length)
                {
                    launchAppIdRaw = args[++i];
                }
                else if (args[i] == "--launch-stdin")
                {
                    launchFromStdin = true;
                }
            }

            BridgeLaunchRequest? request;
            if (!string.IsNullOrWhiteSpace(launchAppIdRaw))
            {
                directShortcutMode = true;
                if (!Guid.TryParse(launchAppIdRaw.Trim(), out Guid appId))
                {
                    ReportError("无效的应用快捷方式参数 (--launch-app-id)。", directShortcutMode);
                    return 2;
                }

                var configService = new ConfigService();
                AppConfig cfg = configService.Load();
                AppProfile? app = cfg.Apps.FirstOrDefault(a => a.Id == appId);
                if (app is null)
                {
                    ReportError(
                        $"未在配置文件 ({configService.ConfigPath}) 中找到对应的应用配置（ID: {appId:D}）。\n请打开 AppProxy 重新为该应用创建桌面快捷方式。",
                        directShortcutMode);
                    return 2;
                }

                ProxyProfile? proxy = app.ProxyProfileId.HasValue
                    ? cfg.Proxies.FirstOrDefault(p => p.Id == app.ProxyProfileId.Value)
                    : null;

                request = new BridgeLaunchRequest
                {
                    AppName = string.IsNullOrWhiteSpace(app.Name) ? Path.GetFileName(app.ExePath) : app.Name,
                    ExePath = app.ExePath,
                    Arguments = app.Arguments ?? string.Empty,
                    WorkingDirectory = string.IsNullOrWhiteSpace(app.WorkingDirectory)
                        ? (Path.GetDirectoryName(app.ExePath) ?? string.Empty)
                        : app.WorkingDirectory,
                    RemoteDns = app.RemoteDns,
                    BypassLan = app.BypassLan,
                    InjectChildren = app.InjectChildren,
                    IgnoreSystemProxy = app.IgnoreSystemProxy,
                    MaxInstances = app.MaxInstances,
                    IsolateProfileDir = app.GetEffectiveIsolateProfileDir(),
                    BypassGlobalTun = cfg.BypassGlobalTun,
                    PreferredOutboundInterface = cfg.PreferredOutboundInterface,
                    Proxy = proxy is not null ? BridgeProxyConfig.FromProfile(proxy) : null
                };
            }
            else if (launchFromStdin)
            {
                string? stdinJson = await ReadLaunchPayloadFromStdinAsync();
                if (string.IsNullOrWhiteSpace(stdinJson))
                {
                    ReportError("Empty launch request payload on stdin (--launch-stdin).", directShortcutMode);
                    return 2;
                }

                request = BridgeIpcCodec.DeserializeLine<BridgeLaunchRequest>(stdinJson.Trim());
            }
            else if (!string.IsNullOrWhiteSpace(launchB64))
            {
                request = BridgeIpcCodec.DecodeLaunchRequestBase64(launchB64);
            }
            else
            {
                ReportError("Missing --launch-stdin, --launch-b64, or --launch-app-id argument.", directShortcutMode);
                return 2;
            }

            if (request is null || string.IsNullOrWhiteSpace(request.ExePath))
            {
                ReportError("Launch request missing target executable path.", directShortcutMode);
                return 2;
            }

            using var host = new BridgeDaemonHost(request);
            return await host.RunAsync(response =>
            {
                if (!directShortcutMode)
                {
                    WriteHandshakeAndCloseStdout(response);
                }
                else if (!response.Ok)
                {
                    ShowErrorDialog(response.Error ?? "启动代理失败。");
                }
            });
        }
        catch (Exception ex)
        {
            TryWriteCrashLog(ex);
            ReportError($"Bridge startup error: {ex.Message}", directShortcutMode);
            return 1;
        }
    }

    private static void TryWriteCrashLog(Exception ex)
    {
        try
        {
            string path = AppPaths.GetCrashLogFilePath(AppPaths.BridgeCrashLogFileName);
            string? dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }
            string content = $"[{DateTimeOffset.Now:O}] Bridge Startup Exception{Environment.NewLine}{ex}{Environment.NewLine}{new string('-', 60)}{Environment.NewLine}";
            File.AppendAllText(path, content);
        }
        catch
        {
        }
    }

    private static void ReportError(string message, bool showDialog)
    {
        if (showDialog)
        {
            ShowErrorDialog(message);
            return;
        }

        WriteHandshakeAndCloseStdout(new BridgeHandshakeResponse
        {
            Ok = false,
            BridgePid = (uint)Environment.ProcessId,
            Error = message
        });
    }

    private static void ShowErrorDialog(string message)
    {
        try
        {
            MessageBoxW(IntPtr.Zero, message, "AppProxy 启动代理失败", MB_OK | MB_ICONERROR);
        }
        catch
        {
        }
    }

    private const int MaxStdinPayloadBytes = 256 * 1024;

    private static async Task<string?> ReadLaunchPayloadFromStdinAsync()
    {
        using Stream stdin = Console.OpenStandardInput();
        using var ms = new MemoryStream();
        byte[] buf = new byte[4096];
        int total = 0;

        while (true)
        {
            int n = await stdin.ReadAsync(buf.AsMemory(0, buf.Length));
            if (n <= 0) break;

            total += n;
            if (total > MaxStdinPayloadBytes)
            {
                throw new InvalidOperationException($"Launch request payload on stdin exceeded {MaxStdinPayloadBytes} bytes.");
            }

            ms.Write(buf, 0, n);
        }

        return total == 0 ? null : Encoding.UTF8.GetString(ms.GetBuffer(), 0, total);
    }

    private static void WriteHandshakeAndCloseStdout(BridgeHandshakeResponse response)
    {
        try
        {
            string line = BridgeIpcCodec.SerializeLine(response);
            using Stream stdout = Console.OpenStandardOutput();
            using var writer = new StreamWriter(stdout, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            writer.WriteLine(line);
            writer.Flush();
        }
        catch
        {
            // Parent UI may have timed out or closed pipe
        }
    }
}

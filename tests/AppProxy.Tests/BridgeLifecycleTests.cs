using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using AppProxy.UI.Interop;
using AppProxy.UI.Models;
using AppProxy.UI.Services;
using Xunit;

namespace AppProxy.Tests;

[Collection("EnvironmentVariables")]
public class BridgeLifecycleTests
{
    [Fact]
    public void BridgeIpcCodec_LaunchRequestAndEnvelope_RoundTripsAccurately()
    {
        var req = new BridgeLaunchRequest
        {
            AppName = "ChatGPT",
            ExePath = @"D:\Tools\scoop\apps\chatgpt\current\ChatGPT.exe",
            Arguments = "--flag",
            WorkingDirectory = @"D:\Tools\scoop\apps\chatgpt\current",
            RemoteDns = true,
            BypassLan = true,
            InjectChildren = true,
            Proxy = new BridgeProxyConfig
            {
                Name = "JP",
                Protocol = ProxyProtocol.Https,
                Host = "jp.exfantasy.com",
                Port = 9999,
                Username = "u",
                Password = "p"
            }
        };

        string b64 = BridgeIpcCodec.EncodeLaunchRequestBase64(req);
        BridgeLaunchRequest? decoded = BridgeIpcCodec.DecodeLaunchRequestBase64(b64);

        Assert.NotNull(decoded);
        Assert.Equal("ChatGPT", decoded!.AppName);
        Assert.Equal(req.ExePath, decoded.ExePath);
        Assert.True(decoded.IgnoreSystemProxy);
        Assert.Equal(1, decoded.MaxInstances);
        Assert.NotNull(decoded.Proxy);

        req.MaxInstances = 0;
        Assert.Equal(1, req.MaxInstances);
        req.MaxInstances = 4;

        req.IgnoreSystemProxy = false;
        BridgeLaunchRequest? decodedFalse = BridgeIpcCodec.DecodeLaunchRequestBase64(
            BridgeIpcCodec.EncodeLaunchRequestBase64(req));
        Assert.NotNull(decodedFalse);
        Assert.False(decodedFalse!.IgnoreSystemProxy);
        Assert.Equal(4, decodedFalse.MaxInstances);
        Assert.Equal(ProxyProtocol.Https, decoded.Proxy!.Protocol);
        Assert.Equal("jp.exfantasy.com", decoded.Proxy.Host);
        Assert.Equal(9999, decoded.Proxy.Port);

        var env = new UiBridgeEnvelope
        {
            Type = "status",
            BridgePid = 43210,
            Status = new BridgeStatusDto
            {
                BridgePid = 43210,
                AppName = "ChatGPT",
                TargetPid = 9876,
                PortV4 = 51234,
                PortV6 = 51235,
                ActiveConnections = 2,
                Alive = true
            }
        };

        string line = BridgeIpcCodec.SerializeLine(env);
        UiBridgeEnvelope? decodedEnv = BridgeIpcCodec.DeserializeLine<UiBridgeEnvelope>(line);

        Assert.NotNull(decodedEnv);
        Assert.Equal("status", decodedEnv!.Type);
        Assert.Equal(43210u, decodedEnv.BridgePid);
        Assert.NotNull(decodedEnv.Status);
        Assert.Equal(51234, decodedEnv.Status!.PortV4);
        Assert.True(decodedEnv.Status.Alive);
    }

    [Fact]
    public async Task JobObjectTracker_SignalsAllProcessesExited_WhenTrackedChildExits()
    {
        using var tracker = new JobObjectTracker();
        string cmdExe = Path.Combine(Environment.SystemDirectory, "cmd.exe");

        var (exitCode, stdout, _) = await tracker.RunInJobAndCaptureAsync(
            cmdExe,
            "/c echo job-ok",
            Environment.SystemDirectory,
            new Dictionary<string, string>());

        Assert.Equal(0, exitCode);
        Assert.Contains("job-ok", stdout);

        Task completed = await Task.WhenAny(tracker.AllProcessesExited, Task.Delay(TimeSpan.FromSeconds(5)));
        Assert.Same(tracker.AllProcessesExited, completed);
    }

    [Fact]
    public async Task DetachedProcessLauncher_StartsDetachedChildAndReadsHandshake()
    {
        string cmdExe = Path.Combine(Environment.SystemDirectory, "cmd.exe");
        var (pid, firstLine) = await DetachedProcessLauncher.StartDetachedAndReadFirstLineAsync(
            cmdExe,
            "/c echo detached-handshake",
            Environment.SystemDirectory,
            TimeSpan.FromSeconds(5));

        Assert.True(pid > 0);
        Assert.Equal("detached-handshake", firstLine.Trim());
    }

    [Fact]
    public void ChromiumBrowserIsolation_DetectsBrowsersAndAppendsUserDataDir()
    {
        Assert.True(AppProfile.IsChromiumBrowserExe(@"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"));
        Assert.True(AppProfile.IsChromiumBrowserExe(@"C:\Program Files\Google\Chrome\Application\chrome.exe"));
        Assert.False(AppProfile.IsChromiumBrowserExe(@"C:\Windows\System32\curl.exe"));

        var legacyEdgeProfile = new AppProfile
        {
            Name = "Microsoft Edge",
            ExePath = @"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            IsolateProfileDir = null
        };
        Assert.True(legacyEdgeProfile.GetEffectiveIsolateProfileDir());

        var req = new BridgeLaunchRequest
        {
            AppName = "Microsoft Edge",
            ExePath = legacyEdgeProfile.ExePath,
            Arguments = "--no-first-run",
            IsolateProfileDir = true
        };

        string effective = req.BuildEffectiveArguments(@"D:\Apps\AppProxy");
        Assert.Contains("--no-first-run", effective);
        Assert.Contains(@"--user-data-dir=""D:\Apps\AppProxy\data\profiles\Microsoft Edge""", effective);

        // Must not duplicate --user-data-dir if user already supplied one
        req.Arguments = @"--user-data-dir=""D:\CustomEdgeProfile""";
        Assert.Equal(@"--user-data-dir=""D:\CustomEdgeProfile""", req.BuildEffectiveArguments(@"D:\Apps\AppProxy"));
    }

    [Fact]
    public async Task JobObjectTracker_RemovesProxyEnvironmentVariables_CaseInsensitively()
    {
        string? origHttp = Environment.GetEnvironmentVariable("HTTP_PROXY");
        string? origHttpsLower = Environment.GetEnvironmentVariable("https_proxy");
        string? origAll = Environment.GetEnvironmentVariable("ALL_PROXY");
        string? origKeep = Environment.GetEnvironmentVariable("APPPROXY_KEEP_TEST");

        try
        {
            Environment.SetEnvironmentVariable("HTTP_PROXY", "http://127.0.0.1:10809");
            Environment.SetEnvironmentVariable("https_proxy", "http://127.0.0.1:10809");
            Environment.SetEnvironmentVariable("ALL_PROXY", "socks5://127.0.0.1:10808");
            Environment.SetEnvironmentVariable("APPPROXY_KEEP_TEST", "keep-value");

            using var tracker = new JobObjectTracker();
            string cmdExe = Path.Combine(Environment.SystemDirectory, "cmd.exe");

            var (exitCode, stdout, _) = await tracker.RunInJobAndCaptureAsync(
                cmdExe,
                "/c set",
                Environment.SystemDirectory,
                new Dictionary<string, string>
                {
                    ["APPPROXY_ADDED_TEST"] = "added-value"
                },
                removeEnvKeys: new[] { "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "FTP_PROXY", "SOCKS_PROXY" });

            Assert.Equal(0, exitCode);
            string[] lines = stdout.Split(new[] { "\r\n", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            Assert.DoesNotContain(lines, l => l.StartsWith("HTTP_PROXY=", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(lines, l => l.StartsWith("HTTPS_PROXY=", StringComparison.OrdinalIgnoreCase));
            Assert.DoesNotContain(lines, l => l.StartsWith("ALL_PROXY=", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(lines, l => l.Equals("APPPROXY_KEEP_TEST=keep-value", StringComparison.OrdinalIgnoreCase));
            Assert.Contains(lines, l => l.Equals("APPPROXY_ADDED_TEST=added-value", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            Environment.SetEnvironmentVariable("HTTP_PROXY", origHttp);
            Environment.SetEnvironmentVariable("https_proxy", origHttpsLower);
            Environment.SetEnvironmentVariable("ALL_PROXY", origAll);
            Environment.SetEnvironmentVariable("APPPROXY_KEEP_TEST", origKeep);
        }
    }

    private const string Csc64Path = @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe";

    [Fact]
    public async Task JobObjectTracker_OrphanBackgroundChild_CleansUpOrphansAndCompletesAfterTargetExits()
    {
        if (!File.Exists(Csc64Path))
        {
            return;
        }

        string tempRoot = Path.Combine(Path.GetTempPath(), "AppProxyOrphanJobTest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempRoot);

        string targetCs = Path.Combine(tempRoot, "TargetLauncher.cs");
        string orphanCs = Path.Combine(tempRoot, "OrphanWorker.cs");
        string targetExe = Path.Combine(tempRoot, "TargetLauncher.exe");
        string orphanExe = Path.Combine(tempRoot, "OrphanWorker.exe");
        string orphanPidFile = Path.Combine(tempRoot, "orphan_pid.txt");

        int? orphanPid = null;
        try
        {
            File.WriteAllText(orphanCs, BuildOrphanWorkerSource(), Encoding.UTF8);
            File.WriteAllText(targetCs, BuildTargetSpawningOrphanSource(), Encoding.UTF8);
            CompileTestExe(orphanCs, orphanExe, target: "winexe");
            CompileTestExe(targetCs, targetExe, target: "winexe");

            string? cleanupSummary = null;
            using var tracker = new JobObjectTracker();

            var (exitCode, _, _) = await tracker.RunInJobAndCaptureAsync(
                targetExe,
                $"\"{orphanExe}\" \"{orphanPidFile}\"",
                tempRoot,
                new Dictionary<string, string>());

            Assert.Equal(0, exitCode);
            await WaitForFileAsync(orphanPidFile, TimeSpan.FromSeconds(5));
            orphanPid = int.Parse(File.ReadAllText(orphanPidFile).Trim());

            tracker.StartTargetExitWatchdog(new JobTargetMonitorOptions
            {
                TargetExePath = targetExe,
                PollInterval = TimeSpan.FromMilliseconds(80),
                InfraOnlyGracePeriod = TimeSpan.FromMilliseconds(150),
                OrphanHelperGracePeriod = TimeSpan.FromMilliseconds(350),
                TerminateOrphansOnTargetExit = true,
                OnJobCleanup = summary => cleanupSummary = summary
            });

            Task completed = await Task.WhenAny(tracker.AllProcessesExited, Task.Delay(TimeSpan.FromSeconds(5)));
            Assert.Same(tracker.AllProcessesExited, completed);
            Assert.False(string.IsNullOrWhiteSpace(cleanupSummary));
            Assert.Contains("OrphanWorker.exe", cleanupSummary!, StringComparison.OrdinalIgnoreCase);

            await Task.Delay(150);
            Assert.False(IsProcessAlive(orphanPid.Value), "Orphan child process should have been terminated when target exited.");
        }
        finally
        {
            if (orphanPid.HasValue)
            {
                KillPidSafe(orphanPid.Value);
            }
            DeleteDirSafe(tempRoot);
        }
    }

    [Fact]
    public async Task JobObjectTracker_VisibleWindowGuiChild_StaysAliveUntilChildWindowCloses()
    {
        if (!File.Exists(Csc64Path))
        {
            return;
        }

        string tempRoot = Path.Combine(Path.GetTempPath(), "AppProxyGuiChildJobTest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempRoot);

        string guiCs = Path.Combine(tempRoot, "VisibleGuiChild.cs");
        string launcherCs = Path.Combine(tempRoot, "WrapperGuiLauncher.cs");
        string guiExe = Path.Combine(tempRoot, "VisibleGuiChild.exe");
        string launcherExe = Path.Combine(tempRoot, "WrapperGuiLauncher.exe");
        string readyFile = Path.Combine(tempRoot, "gui_ready.txt");
        string stopFile = Path.Combine(tempRoot, "gui_stop.txt");

        int? childPid = null;
        try
        {
            File.WriteAllText(guiCs, BuildVisibleGuiChildSource(), Encoding.UTF8);
            File.WriteAllText(launcherCs, BuildWrapperSpawningGuiSource(), Encoding.UTF8);
            CompileTestExe(guiCs, guiExe, target: "winexe", extraRefs: new[] { "System.Windows.Forms.dll", "System.Drawing.dll" });
            CompileTestExe(launcherCs, launcherExe, target: "winexe");

            using var tracker = new JobObjectTracker();
            var (exitCode, _, _) = await tracker.RunInJobAndCaptureAsync(
                launcherExe,
                $"\"{guiExe}\" \"{readyFile}\" \"{stopFile}\"",
                tempRoot,
                new Dictionary<string, string>());

            Assert.Equal(0, exitCode);
            await WaitForFileAsync(readyFile, TimeSpan.FromSeconds(5));
            childPid = int.Parse(File.ReadAllText(readyFile).Trim());

            tracker.StartTargetExitWatchdog(new JobTargetMonitorOptions
            {
                TargetExePath = launcherExe,
                PollInterval = TimeSpan.FromMilliseconds(80),
                InfraOnlyGracePeriod = TimeSpan.FromMilliseconds(150),
                OrphanHelperGracePeriod = TimeSpan.FromMilliseconds(350),
                TerminateOrphansOnTargetExit = true
            });

            // Wait well past OrphanHelperGracePeriod; visible GUI child window must keep JobObjectTracker alive
            await Task.Delay(1100);
            Assert.False(tracker.AllProcessesExited.IsCompleted, "Bridge should stay alive while visible child GUI window is open.");
            Assert.True(IsProcessAlive(childPid.Value), "Visible child GUI process must not be prematurely terminated.");

            // Close the child GUI window and verify tracker completes promptly
            File.WriteAllText(stopFile, "stop");
            Task completed = await Task.WhenAny(tracker.AllProcessesExited, Task.Delay(TimeSpan.FromSeconds(5)));
            Assert.Same(tracker.AllProcessesExited, completed);
        }
        finally
        {
            try { File.WriteAllText(stopFile, "stop"); } catch { }
            if (childPid.HasValue)
            {
                KillPidSafe(childPid.Value);
            }
            DeleteDirSafe(tempRoot);
        }
    }

    [Fact]
    public async Task BridgeProcess_StalledUiPipeSubscriber_DoesNotPreventBridgeExit()
    {
        if (!File.Exists(Csc64Path))
        {
            return;
        }

        string? bridgeExePath = FindBuiltBridgeExePath();
        if (bridgeExePath is null)
        {
            return;
        }

        string tempRoot = Path.Combine(Path.GetTempPath(), "AppProxyStalledPipeTest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempRoot);

        string csPath = Path.Combine(tempRoot, "StopFileGuiApp.cs");
        string exePath = Path.Combine(tempRoot, "StopFileGuiApp.exe");
        string readyFile = Path.Combine(tempRoot, "app_ready.txt");
        string stopFile = Path.Combine(tempRoot, "app_stop.txt");

        Process? bridgeProc = null;
        try
        {
            File.WriteAllText(csPath, BuildStopFileAppSource(isConsole: false), Encoding.UTF8);
            CompileTestExe(csPath, exePath, target: "winexe");

            var req = new BridgeLaunchRequest
            {
                AppName = "StalledPipeApp",
                ExePath = exePath,
                Arguments = $"\"{readyFile}\" \"{stopFile}\"",
                MaxInstances = 1
            };
            string b64 = BridgeIpcCodec.EncodeLaunchRequestBase64(req);

            bridgeProc = Process.Start(new ProcessStartInfo
            {
                FileName = bridgeExePath,
                Arguments = $"--launch-b64 {b64}",
                WorkingDirectory = Path.GetDirectoryName(bridgeExePath) ?? AppContext.BaseDirectory,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            });
            Assert.NotNull(bridgeProc);

            string? handshakeLine = await bridgeProc!.StandardOutput.ReadLineAsync()
                .WaitAsync(TimeSpan.FromSeconds(10));
            Assert.False(string.IsNullOrWhiteSpace(handshakeLine));
            BridgeHandshakeResponse? handshake =
                BridgeIpcCodec.DeserializeLine<BridgeHandshakeResponse>(handshakeLine!.Trim());
            Assert.NotNull(handshake);
            Assert.True(handshake!.Ok, $"Bridge launch failed: {handshake.Error}");

            await WaitForFileAsync(readyFile, TimeSpan.FromSeconds(5));

            string pipeName = BridgeIpcCodec.GetUiPipeName(handshake.BridgePid);

            // Stalled client: connects and never reads/drains frames
            using var stalledClient = new NamedPipeClientStream(".", pipeName, PipeDirection.In, PipeOptions.Asynchronous);
            await stalledClient.ConnectAsync(3000);

            // Healthy client: reads telemetry continuously and waits for alive=false
            using var healthyClient = new NamedPipeClientStream(".", pipeName, PipeDirection.In, PipeOptions.Asynchronous);
            await healthyClient.ConnectAsync(3000);

            bool sawInitialAlive = false;
            bool sawExitedStatus = false;
            using var readCts = new CancellationTokenSource(TimeSpan.FromSeconds(8));
            Task readHealthyTask = Task.Run(async () =>
            {
                using var reader = new StreamReader(healthyClient, Encoding.UTF8, leaveOpen: true);
                while (!readCts.IsCancellationRequested)
                {
                    string? line = await reader.ReadLineAsync(readCts.Token);
                    if (line is null) break;
                    UiBridgeEnvelope? env = BridgeIpcCodec.DeserializeLine<UiBridgeEnvelope>(line);
                    if (env?.Type == "status" && env.Status is not null)
                    {
                        if (env.Status.Alive) sawInitialAlive = true;
                        else sawExitedStatus = true;
                    }
                }
            }, readCts.Token);

            // Wait briefly for initial snapshot to ensure both clients are registered
            DateTime waitAliveDeadline = DateTime.UtcNow + TimeSpan.FromSeconds(3);
            while (!sawInitialAlive && DateTime.UtcNow < waitAliveDeadline)
            {
                await Task.Delay(30);
            }
            Assert.True(sawInitialAlive);

            // Close target app cleanly; Bridge must NOT hang on stalledClient and must still exit promptly
            File.WriteAllText(stopFile, "stop");
            using var exitCts = new CancellationTokenSource(TimeSpan.FromSeconds(6));
            await bridgeProc.WaitForExitAsync(exitCts.Token);
            Assert.Equal(0, bridgeProc.ExitCode);

            try { await readHealthyTask.WaitAsync(TimeSpan.FromSeconds(2)); } catch { }
            Assert.True(sawExitedStatus, "Healthy UI subscriber should still receive Alive=false status before Bridge exit.");
        }
        finally
        {
            try { File.WriteAllText(stopFile, "stop"); } catch { }
            if (bridgeProc is not null) KillProcessTreeSafe(bridgeProc);
            DeleteDirSafe(tempRoot);
        }
    }

    [Fact]
    public async Task BridgeProcess_ConsoleSubsystemTarget_DoesNotCorruptHandshakeAndExitsCleanly()
    {
        if (!File.Exists(Csc64Path))
        {
            return;
        }

        string? bridgeExePath = FindBuiltBridgeExePath();
        if (bridgeExePath is null)
        {
            return;
        }

        string tempRoot = Path.Combine(Path.GetTempPath(), "AppProxyConsoleTargetTest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempRoot);

        string csPath = Path.Combine(tempRoot, "ConsoleNoiseApp.cs");
        string exePath = Path.Combine(tempRoot, "ConsoleNoiseApp.exe");
        string readyFile = Path.Combine(tempRoot, "cui_ready.txt");
        string stopFile = Path.Combine(tempRoot, "cui_stop.txt");

        Process? bridgeProc = null;
        try
        {
            File.WriteAllText(csPath, BuildStopFileAppSource(isConsole: true), Encoding.UTF8);
            CompileTestExe(csPath, exePath, target: "exe");

            var req = new BridgeLaunchRequest
            {
                AppName = "ConsoleNoiseApp",
                ExePath = exePath,
                Arguments = $"\"{readyFile}\" \"{stopFile}\"",
                MaxInstances = 1
            };
            string b64 = BridgeIpcCodec.EncodeLaunchRequestBase64(req);

            bridgeProc = Process.Start(new ProcessStartInfo
            {
                FileName = bridgeExePath,
                Arguments = $"--launch-b64 {b64}",
                WorkingDirectory = Path.GetDirectoryName(bridgeExePath) ?? AppContext.BaseDirectory,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            });
            Assert.NotNull(bridgeProc);

            // Handshake must return immediately (not wait for the CUI target to exit) and be uncorrupted JSON
            string? handshakeLine = await bridgeProc!.StandardOutput.ReadLineAsync()
                .WaitAsync(TimeSpan.FromSeconds(5));
            Assert.False(string.IsNullOrWhiteSpace(handshakeLine));
            BridgeHandshakeResponse? handshake =
                BridgeIpcCodec.DeserializeLine<BridgeHandshakeResponse>(handshakeLine!.Trim());
            Assert.NotNull(handshake);
            Assert.True(handshake!.Ok, $"Console target bridge handshake failed: {handshake.Error}");
            Assert.True(handshake.TargetPid > 0);

            await WaitForFileAsync(readyFile, TimeSpan.FromSeconds(5));
            File.WriteAllText(stopFile, "stop");

            using var exitCts = new CancellationTokenSource(TimeSpan.FromSeconds(6));
            await bridgeProc.WaitForExitAsync(exitCts.Token);
            Assert.Equal(0, bridgeProc.ExitCode);
        }
        finally
        {
            try { File.WriteAllText(stopFile, "stop"); } catch { }
            if (bridgeProc is not null) KillProcessTreeSafe(bridgeProc);
            DeleteDirSafe(tempRoot);
        }
    }

    private static string BuildOrphanWorkerSource() => """
        using System.Threading;

        internal static class Program
        {
            private static void Main()
            {
                Thread.Sleep(30000);
            }
        }
        """;

    private static string BuildTargetSpawningOrphanSource() => """
        using System;
        using System.IO;
        using System.Runtime.InteropServices;

        internal static class Program
        {
            private const uint CREATE_NO_WINDOW = 0x08000000;

            [StructLayout(LayoutKind.Sequential)]
            private struct STARTUPINFOW
            {
                public int cb;
                public IntPtr lpReserved;
                public IntPtr lpDesktop;
                public IntPtr lpTitle;
                public uint dwX;
                public uint dwY;
                public uint dwXSize;
                public uint dwYSize;
                public uint dwXCountChars;
                public uint dwYCountChars;
                public uint dwFillAttribute;
                public uint dwFlags;
                public ushort wShowWindow;
                public ushort cbReserved2;
                public IntPtr lpReserved2;
                public IntPtr hStdInput;
                public IntPtr hStdOutput;
                public IntPtr hStdError;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct PROCESS_INFORMATION
            {
                public IntPtr hProcess;
                public IntPtr hThread;
                public uint dwProcessId;
                public uint dwThreadId;
            }

            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            private static extern bool CreateProcessW(
                string lpApplicationName,
                string lpCommandLine,
                IntPtr lpProcessAttributes,
                IntPtr lpThreadAttributes,
                bool bInheritHandles,
                uint dwCreationFlags,
                IntPtr lpEnvironment,
                string lpCurrentDirectory,
                ref STARTUPINFOW lpStartupInfo,
                out PROCESS_INFORMATION lpProcessInformation);

            [DllImport("kernel32.dll")]
            private static extern bool CloseHandle(IntPtr hObject);

            private static int Main(string[] args)
            {
                if (args.Length < 2) return 2;
                STARTUPINFOW si = new STARTUPINFOW();
                si.cb = Marshal.SizeOf(typeof(STARTUPINFOW));
                PROCESS_INFORMATION pi;
                string cmd = "\"" + args[0] + "\"";
                if (!CreateProcessW(args[0], cmd, IntPtr.Zero, IntPtr.Zero, false, CREATE_NO_WINDOW, IntPtr.Zero, null, ref si, out pi))
                {
                    return 1;
                }
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                File.WriteAllText(args[1], pi.dwProcessId.ToString());
                return 0;
            }
        }
        """;

    private static string BuildVisibleGuiChildSource() => """
        using System;
        using System.Diagnostics;
        using System.Drawing;
        using System.IO;
        using System.Windows.Forms;

        internal sealed class OffscreenForm : Form
        {
            protected override bool ShowWithoutActivation { get { return true; } }

            public OffscreenForm(string readyFile, string stopFile)
            {
                Text = "AppProxyTestGuiChild";
                StartPosition = FormStartPosition.Manual;
                Location = new Point(-10000, -10000);
                Size = new Size(160, 90);
                ShowInTaskbar = false;

                Shown += delegate { File.WriteAllText(readyFile, Process.GetCurrentProcess().Id.ToString()); };

                Timer t = new Timer();
                t.Interval = 60;
                t.Tick += delegate
                {
                    if (File.Exists(stopFile))
                    {
                        t.Stop();
                        Close();
                    }
                };
                t.Start();
            }
        }

        internal static class Program
        {
            [STAThread]
            private static int Main(string[] args)
            {
                if (args.Length < 2) return 2;
                Application.Run(new OffscreenForm(args[0], args[1]));
                return 0;
            }
        }
        """;

    private static string BuildWrapperSpawningGuiSource() => """
        using System;
        using System.Runtime.InteropServices;

        internal static class Program
        {
            [StructLayout(LayoutKind.Sequential)]
            private struct STARTUPINFOW
            {
                public int cb;
                public IntPtr lpReserved;
                public IntPtr lpDesktop;
                public IntPtr lpTitle;
                public uint dwX;
                public uint dwY;
                public uint dwXSize;
                public uint dwYSize;
                public uint dwXCountChars;
                public uint dwYCountChars;
                public uint dwFillAttribute;
                public uint dwFlags;
                public ushort wShowWindow;
                public ushort cbReserved2;
                public IntPtr lpReserved2;
                public IntPtr hStdInput;
                public IntPtr hStdOutput;
                public IntPtr hStdError;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct PROCESS_INFORMATION
            {
                public IntPtr hProcess;
                public IntPtr hThread;
                public uint dwProcessId;
                public uint dwThreadId;
            }

            [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            private static extern bool CreateProcessW(
                string lpApplicationName,
                string lpCommandLine,
                IntPtr lpProcessAttributes,
                IntPtr lpThreadAttributes,
                bool bInheritHandles,
                uint dwCreationFlags,
                IntPtr lpEnvironment,
                string lpCurrentDirectory,
                ref STARTUPINFOW lpStartupInfo,
                out PROCESS_INFORMATION lpProcessInformation);

            [DllImport("kernel32.dll")]
            private static extern bool CloseHandle(IntPtr hObject);

            private static int Main(string[] args)
            {
                if (args.Length < 3) return 2;
                STARTUPINFOW si = new STARTUPINFOW();
                si.cb = Marshal.SizeOf(typeof(STARTUPINFOW));
                PROCESS_INFORMATION pi;
                string cmd = "\"" + args[0] + "\" \"" + args[1] + "\" \"" + args[2] + "\"";
                if (!CreateProcessW(args[0], cmd, IntPtr.Zero, IntPtr.Zero, false, 0u, IntPtr.Zero, null, ref si, out pi))
                {
                    return 1;
                }
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);
                return 0;
            }
        }
        """;

    private static string BuildStopFileAppSource(bool isConsole) =>
        isConsole
            ? """
              using System;
              using System.Diagnostics;
              using System.IO;
              using System.Threading;

              internal static class Program
              {
                  private static int Main(string[] args)
                  {
                      if (args.Length < 2) return 2;
                      Console.WriteLine("CONSOLE_TARGET_STDOUT_LINE");
                      File.WriteAllText(args[0], Process.GetCurrentProcess().Id.ToString());
                      DateTime deadline = DateTime.UtcNow.AddSeconds(15);
                      while (!File.Exists(args[1]) && DateTime.UtcNow < deadline)
                      {
                          Console.WriteLine("CONSOLE_TARGET_TICK");
                          Thread.Sleep(40);
                      }
                      return 0;
                  }
              }
              """
            : """
              using System;
              using System.Diagnostics;
              using System.IO;
              using System.Threading;

              internal static class Program
              {
                  private static int Main(string[] args)
                  {
                      if (args.Length < 2) return 2;
                      File.WriteAllText(args[0], Process.GetCurrentProcess().Id.ToString());
                      DateTime deadline = DateTime.UtcNow.AddSeconds(15);
                      while (!File.Exists(args[1]) && DateTime.UtcNow < deadline)
                      {
                          Thread.Sleep(40);
                      }
                      return 0;
                  }
              }
              """;

    private static void CompileTestExe(string csPath, string outExePath, string target, string[]? extraRefs = null)
    {
        string refsArg = extraRefs is { Length: > 0 }
            ? " " + string.Join(" ", extraRefs.Select(r => $"/r:{r}"))
            : string.Empty;

        using var proc = Process.Start(new ProcessStartInfo
        {
            FileName = Csc64Path,
            Arguments = $"/nologo /platform:x64 /optimize+ /target:{target}{refsArg} /out:\"{outExePath}\" \"{csPath}\"",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        });
        Assert.NotNull(proc);
        string stdout = proc!.StandardOutput.ReadToEnd();
        string stderr = proc.StandardError.ReadToEnd();
        Assert.True(proc.WaitForExit(15000), "csc.exe timed out");
        Assert.True(proc.ExitCode == 0, $"csc.exe failed ({proc.ExitCode}): {stdout}\n{stderr}");
    }

    private static async Task WaitForFileAsync(string path, TimeSpan timeout)
    {
        DateTime deadline = DateTime.UtcNow + timeout;
        while (!File.Exists(path) && DateTime.UtcNow < deadline)
        {
            await Task.Delay(30);
        }
        Assert.True(File.Exists(path), $"Timed out waiting for marker file {path}");
    }

    private static string? FindBuiltBridgeExePath()
    {
        string local = Path.Combine(AppContext.BaseDirectory, "AppProxy.Bridge.exe");
        if (File.Exists(local)) return local;

        DirectoryInfo? dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            string releaseCandidate = Path.Combine(dir.FullName, "src", "AppProxy.UI", "bin", "Release", "net8.0-windows", "AppProxy.Bridge.exe");
            if (File.Exists(releaseCandidate)) return releaseCandidate;

            string debugCandidate = Path.Combine(dir.FullName, "src", "AppProxy.UI", "bin", "Debug", "net8.0-windows", "AppProxy.Bridge.exe");
            if (File.Exists(debugCandidate)) return debugCandidate;

            dir = dir.Parent;
        }

        return null;
    }

    private static bool IsProcessAlive(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            return !proc.HasExited;
        }
        catch
        {
            return false;
        }
    }

    private static void KillPidSafe(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            KillProcessTreeSafe(proc);
        }
        catch
        {
        }
    }

    private static void KillProcessTreeSafe(Process proc)
    {
        try
        {
            if (!proc.HasExited)
            {
                proc.Kill(entireProcessTree: true);
                proc.WaitForExit(3000);
            }
        }
        catch
        {
        }
        finally
        {
            proc.Dispose();
        }
    }

    private static void DeleteDirSafe(string dir)
    {
        try
        {
            if (Directory.Exists(dir))
            {
                Directory.Delete(dir, recursive: true);
            }
        }
        catch
        {
        }
    }
}

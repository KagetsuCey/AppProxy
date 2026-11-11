using System.Diagnostics;
using System.IO;
using System.Text;
using AppProxy.UI.Interop;
using AppProxy.UI.Models;
using AppProxy.UI.Services;
using Xunit;

namespace AppProxy.Tests;

public class ProcessInstanceCounterTests
{
    private const string Csc64Path = @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe";

    [Fact]
    public void CountRootInstances_MergesSameExeChildTree_AndSeparatesIndependentRoots()
    {
        // Single multi-process instance: root 100 -> children 101, 102 -> grandchild 103
        var singleAppTree = new[]
        {
            new RunningProcessEntry(100, 40, "ChatGPT.exe"),
            new RunningProcessEntry(101, 100, "ChatGPT.exe"),
            new RunningProcessEntry(102, 100, "ChatGPT.exe"),
            new RunningProcessEntry(103, 102, "ChatGPT.exe")
        };
        Assert.Equal(1, ProcessInstanceCounter.CountRootInstances(singleAppTree));

        // Two independent launches (different external parents 40 and 88)
        var twoInstances = singleAppTree.Concat(new[]
        {
            new RunningProcessEntry(200, 88, "ChatGPT.exe"),
            new RunningProcessEntry(201, 200, "ChatGPT.exe")
        }).ToArray();
        Assert.Equal(2, ProcessInstanceCounter.CountRootInstances(twoInstances));

        // Defensive cycle component still counts as 1 rather than 0
        var cycle = new[]
        {
            new RunningProcessEntry(300, 301, "App.exe"),
            new RunningProcessEntry(301, 300, "App.exe")
        };
        Assert.Equal(1, ProcessInstanceCounter.CountRootInstances(cycle));
    }

    [Fact]
    public void CheckCanLaunch_ClampsMinimumLimitToOne_WhenZeroOrNegativeProvided()
    {
        string uniqueMissingExe = Path.Combine(Path.GetTempPath(), $"NonExistent_{Guid.NewGuid():N}.exe");
        InstanceLimitCheckResult res = ProcessInstanceCounter.CheckCanLaunch(uniqueMissingExe, 0, "TestApp");
        Assert.True(res.Allowed);
        Assert.Equal(1, res.MaxInstances);
        Assert.Equal(0, res.RunningCount);

        InstanceLimitCheckResult negRes = ProcessInstanceCounter.CheckCanLaunch(uniqueMissingExe, -10, "TestApp");
        Assert.True(negRes.Allowed);
        Assert.Equal(1, negRes.MaxInstances);
    }

    [Fact]
    public void CrashpadDetection_MatchesCrashpadProcesses_AndIgnoresMonitorSelfSwitchOnMainApp()
    {
        Assert.True(ProcessInspectionHelper.IsCrashpadOrCrashReporterProcess(
            "ChatGPT.exe",
            "\"C:\\Apps\\ChatGPT.exe\" --type=crashpad-handler /prefetch:4 --database=\"C:\\db\""));
        Assert.True(ProcessInspectionHelper.IsCrashpadOrCrashReporterProcess(
            "claude.exe",
            "\"claude.exe\" \"--type=crashpad\""));
        Assert.True(ProcessInspectionHelper.IsCrashpadOrCrashReporterProcess(
            "crashpad_handler.exe",
            "crashpad_handler.exe --database=test"));
        Assert.True(ProcessInspectionHelper.IsCrashpadOrCrashReporterProcess(
            "WerFault.exe",
            null));

        // Main Electron/Chromium or unrelated args mentioning --monitor-self-argument=--type=crashpad-handler must NOT match
        Assert.False(ProcessInspectionHelper.IsCrashpadOrCrashReporterProcess(
            "ChatGPT.exe",
            "\"C:\\Apps\\ChatGPT.exe\" --enable-crashpad --monitor-self-argument=--type=crashpad-handler"));
        Assert.False(ProcessInspectionHelper.IsCrashpadOrCrashReporterProcess(
            "Antigravity.exe",
            "\"C:\\Apps\\Antigravity.exe\" --type=renderer"));
    }

    [Fact]
    public void LiveProcesses_SameExeCrashpadHandler_IsExcludedFromInstanceCount()
    {
        if (!File.Exists(Csc64Path))
        {
            return;
        }

        string tempRoot = Path.Combine(Path.GetTempPath(), "AppProxyCrashpadCountTest_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempRoot);
        string csPath = Path.Combine(tempRoot, "DummySleeper.cs");
        string exePath = Path.Combine(tempRoot, "DummyCrashpadTest.exe");

        var spawned = new List<Process>();
        try
        {
            File.WriteAllText(csPath, BuildDummySleeperSource(), Encoding.UTF8);
            CompileWithCsc(csPath, exePath);

            // Simulate orphaned <App>.exe --type=crashpad-handler left after main app closed
            Process crashpadProc = StartSleeperProcess(exePath, "--type=crashpad-handler --sleep-ms 15000");
            spawned.Add(crashpadProc);
            Assert.Equal(0, ProcessInstanceCounter.CountRunningInstances(exePath));
            Assert.True(ProcessInstanceCounter.CheckCanLaunch(exePath, 1, "DummyCrashpadTest").Allowed);

            // With one normal instance plus one --type=crashpad-handler sibling, count must be 1
            Process mainProc = StartSleeperProcess(exePath, "--sleep-ms 15000");
            spawned.Add(mainProc);
            Assert.Equal(1, ProcessInstanceCounter.CountRunningInstances(exePath));
        }
        finally
        {
            foreach (var p in spawned)
            {
                KillTreeSafe(p);
            }
            try
            {
                if (Directory.Exists(tempRoot))
                {
                    Directory.Delete(tempRoot, recursive: true);
                }
            }
            catch
            {
            }
        }
    }

    [Fact]
    public async Task LiveProcesses_DirectAndChildTrees_CountAndBlockBothUiAndBridgeLaunches()
    {
        if (!File.Exists(Csc64Path))
        {
            return;
        }

        string tempRoot = Path.Combine(Path.GetTempPath(), "AppProxyInstLimitTest_" + Guid.NewGuid().ToString("N"));
        string dirA = Path.Combine(tempRoot, "DirA");
        string dirB = Path.Combine(tempRoot, "DirB");
        Directory.CreateDirectory(dirA);
        Directory.CreateDirectory(dirB);

        string csPath = Path.Combine(tempRoot, "DummySleeper.cs");
        string exeA = Path.Combine(dirA, "DummySleeper.exe");
        string exeB = Path.Combine(dirB, "DummySleeper.exe");

        var spawnedProcesses = new List<Process>();
        using var launcher = new AppLauncherService();

        try
        {
            File.WriteAllText(csPath, BuildDummySleeperSource(), Encoding.UTF8);
            CompileWithCsc(csPath, exeA);
            File.Copy(exeA, exeB, overwrite: true);

            // 1. Launch one direct (non-proxied) tree that internally spawns 1 same-exe child process
            string childReadyFile = Path.Combine(tempRoot, "child_ready.txt");
            var proc1 = StartSleeperProcess(exeA, $"--spawn-child \"{childReadyFile}\"");
            spawnedProcesses.Add(proc1);
            await WaitForFileAsync(childReadyFile, TimeSpan.FromSeconds(5));

            // Multi-process tree under exeA counts as 1 logical instance; same-named exeB stays 0
            Assert.Equal(1, ProcessInstanceCounter.CountRunningInstances(exeA));
            Assert.Equal(0, ProcessInstanceCounter.CountRunningInstances(exeB));

            // 2. With MaxInstances = 1 (including when IsolateProfileDir = true), UI launcher must block
            var profileLimit1 = new AppProfile
            {
                Name = "DummySleeper",
                ExePath = exeA,
                MaxInstances = 1,
                IsolateProfileDir = true
            };

            var (okUi1, pidUi1, msgUi1) = await launcher.LaunchAppAsync(profileLimit1, null);
            Assert.False(okUi1);
            Assert.Equal(0u, pidUi1);
            Assert.Contains("DummySleeper", msgUi1);
            Assert.Contains("超过配置的最大实例数 (1)", msgUi1);
            Assert.Equal(1, ProcessInstanceCounter.CountRunningInstances(exeA));

            // 3. Bridge executable direct invocation (--launch-b64) must also refuse & exit without spawning target
            string? bridgeExePath = FindBuiltBridgeExePath();
            if (bridgeExePath is not null)
            {
                var bridgeReq = new BridgeLaunchRequest
                {
                    AppName = "DummySleeper",
                    ExePath = exeA,
                    MaxInstances = 1,
                    IsolateProfileDir = true
                };
                string payloadB64 = BridgeIpcCodec.EncodeLaunchRequestBase64(bridgeReq);
                var (bridgeExitCode, bridgeStdout) = await RunBridgeAndCaptureAsync(bridgeExePath, $"--launch-b64 {payloadB64}");

                Assert.NotEqual(0, bridgeExitCode);
                BridgeHandshakeResponse? handshake = BridgeIpcCodec.DeserializeLine<BridgeHandshakeResponse>(bridgeStdout.Trim());
                Assert.NotNull(handshake);
                Assert.False(handshake!.Ok);
                Assert.Contains("超过配置的最大实例数 (1)", handshake.Error);
                Assert.Equal(1, ProcessInstanceCounter.CountRunningInstances(exeA));
            }

            // 4. With MaxInstances = 2 while 1 direct instance runs, 2nd launch is allowed
            Assert.True(ProcessInstanceCounter.CheckCanLaunch(exeA, 2, "DummySleeper").Allowed);

            // Launch a 2nd independent direct instance (exceeding nothing at MaxInstances=2)
            string secondReadyFile = Path.Combine(tempRoot, "second_ready.txt");
            var proc2 = StartSleeperProcess(exeA, $"--ready-file \"{secondReadyFile}\"");
            spawnedProcesses.Add(proc2);
            await WaitForFileAsync(secondReadyFile, TimeSpan.FromSeconds(5));

            Assert.Equal(2, ProcessInstanceCounter.CountRunningInstances(exeA));

            // Now 3rd attempt under MaxInstances = 2 must be blocked
            var profileLimit2 = new AppProfile
            {
                Name = "DummySleeper",
                ExePath = exeA,
                MaxInstances = 2
            };
            var (okUi2, _, msgUi2) = await launcher.LaunchAppAsync(profileLimit2, null);
            Assert.False(okUi2);
            Assert.Contains("已有 2 个实例正在运行", msgUi2);
            Assert.Contains("超过配置的最大实例数 (2)", msgUi2);
            Assert.Equal(2, ProcessInstanceCounter.CountRunningInstances(exeA));

            // 5. After processes exit, instance count returns to 0 and MaxInstances = 1 allows launch again
            foreach (var p in spawnedProcesses)
            {
                KillTreeSafe(p);
            }
            spawnedProcesses.Clear();

            Assert.Equal(0, ProcessInstanceCounter.CountRunningInstances(exeA));
            Assert.True(ProcessInstanceCounter.CheckCanLaunch(exeA, 1, "DummySleeper").Allowed);

            // 6. Proxy-launched instance (via real AppProxy.Bridge.exe) also counts toward limit
            if (bridgeExePath is not null)
            {
                var reqAllow = new BridgeLaunchRequest
                {
                    AppName = "DummySleeper",
                    ExePath = exeA,
                    Arguments = "--sleep-ms 15000",
                    MaxInstances = 1
                };
                string allowB64 = BridgeIpcCodec.EncodeLaunchRequestBase64(reqAllow);
                using Process bridgeProc = Process.Start(new ProcessStartInfo
                {
                    FileName = bridgeExePath,
                    Arguments = $"--launch-b64 {allowB64}",
                    WorkingDirectory = Path.GetDirectoryName(bridgeExePath) ?? AppContext.BaseDirectory,
                    UseShellExecute = false,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    CreateNoWindow = true
                })!;

                try
                {
                    string? handshakeLine = await bridgeProc.StandardOutput.ReadLineAsync()
                        .WaitAsync(TimeSpan.FromSeconds(10));
                    Assert.False(string.IsNullOrWhiteSpace(handshakeLine));
                    BridgeHandshakeResponse? firstHandshake =
                        BridgeIpcCodec.DeserializeLine<BridgeHandshakeResponse>(handshakeLine!.Trim());
                    Assert.NotNull(firstHandshake);
                    Assert.True(firstHandshake!.Ok, $"Expected first proxy launch to succeed, got: {firstHandshake.Error}");
                    Assert.True(firstHandshake.TargetPid > 0);

                    Assert.Equal(1, ProcessInstanceCounter.CountRunningInstances(exeA));

                    var (okSecondUi, _, msgSecondUi) = await launcher.LaunchAppAsync(profileLimit1, null);
                    Assert.False(okSecondUi);
                    Assert.Contains("超过配置的最大实例数 (1)", msgSecondUi);

                    var (secondBridgeCode, secondBridgeOut) =
                        await RunBridgeAndCaptureAsync(bridgeExePath, $"--launch-b64 {allowB64}");
                    Assert.NotEqual(0, secondBridgeCode);
                    BridgeHandshakeResponse? secondHandshake =
                        BridgeIpcCodec.DeserializeLine<BridgeHandshakeResponse>(secondBridgeOut.Trim());
                    Assert.NotNull(secondHandshake);
                    Assert.False(secondHandshake!.Ok);
                    Assert.Contains("超过配置的最大实例数 (1)", secondHandshake.Error);
                    Assert.Equal(1, ProcessInstanceCounter.CountRunningInstances(exeA));

                    try
                    {
                        using var proxyTarget = Process.GetProcessById((int)firstHandshake.TargetPid);
                        KillTreeSafe(proxyTarget);
                    }
                    catch
                    {
                    }

                    using var exitCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                    await bridgeProc.WaitForExitAsync(exitCts.Token);
                    Assert.Equal(0, ProcessInstanceCounter.CountRunningInstances(exeA));
                }
                finally
                {
                    KillTreeSafe(bridgeProc);
                }
            }
        }
        finally
        {
            foreach (var p in spawnedProcesses)
            {
                KillTreeSafe(p);
            }

            try
            {
                if (Directory.Exists(tempRoot))
                {
                    Directory.Delete(tempRoot, recursive: true);
                }
            }
            catch
            {
            }
        }
    }

    private static string BuildDummySleeperSource() => """
        using System;
        using System.Diagnostics;
        using System.IO;
        using System.Reflection;
        using System.Threading;

        internal static class Program
        {
            private static void Main(string[] args)
            {
                Process child = null;
                try
                {
                    int sleepMs = 60000;
                    for (int i = 0; i < args.Length - 1; i++)
                    {
                        if (args[i] == "--spawn-child")
                        {
                            string exe = Assembly.GetExecutingAssembly().Location;
                            string readyFile = args[i + 1];
                            child = Process.Start(new ProcessStartInfo
                            {
                                FileName = exe,
                                Arguments = "--ready-file \"" + readyFile + "\"",
                                UseShellExecute = false,
                                CreateNoWindow = true
                            });
                            break;
                        }
                        if (args[i] == "--ready-file")
                        {
                            File.WriteAllText(args[i + 1], Process.GetCurrentProcess().Id.ToString());
                            break;
                        }
                        if (args[i] == "--sleep-ms")
                        {
                            int parsed;
                            if (int.TryParse(args[i + 1], out parsed) && parsed > 0) sleepMs = parsed;
                        }
                    }

                    Thread.Sleep(sleepMs);
                }
                finally
                {
                    if (child != null)
                    {
                        try
                        {
                            if (!child.HasExited) child.Kill();
                        }
                        catch
                        {
                        }
                        child.Dispose();
                    }
                }
            }
        }
        """;

    private static void CompileWithCsc(string csPath, string outExePath)
    {
        using var proc = Process.Start(new ProcessStartInfo
        {
            FileName = Csc64Path,
            Arguments = $"/nologo /optimize+ /target:winexe /out:\"{outExePath}\" \"{csPath}\"",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        });
        Assert.NotNull(proc);
        string stdout = proc!.StandardOutput.ReadToEnd();
        string stderr = proc.StandardError.ReadToEnd();
        proc.WaitForExit(15000);
        Assert.True(proc.ExitCode == 0, $"csc failed ({proc.ExitCode}): {stdout}\n{stderr}");
    }

    private static Process StartSleeperProcess(string exePath, string args)
    {
        var proc = Process.Start(new ProcessStartInfo
        {
            FileName = exePath,
            Arguments = args,
            UseShellExecute = false,
            CreateNoWindow = true
        });
        Assert.NotNull(proc);
        return proc!;
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

    private static async Task<(int ExitCode, string Stdout)> RunBridgeAndCaptureAsync(string bridgeExePath, string args)
    {
        using var proc = Process.Start(new ProcessStartInfo
        {
            FileName = bridgeExePath,
            Arguments = args,
            WorkingDirectory = Path.GetDirectoryName(bridgeExePath) ?? AppContext.BaseDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        });
        Assert.NotNull(proc);
        string stdout = await proc!.StandardOutput.ReadToEndAsync();
        await proc.WaitForExitAsync(new CancellationTokenSource(TimeSpan.FromSeconds(10)).Token);
        return (proc.ExitCode, stdout);
    }

    private static void KillTreeSafe(Process p)
    {
        try
        {
            if (!p.HasExited)
            {
                p.Kill(entireProcessTree: true);
                p.WaitForExit(3000);
            }
        }
        catch
        {
        }
        finally
        {
            p.Dispose();
        }
    }
}

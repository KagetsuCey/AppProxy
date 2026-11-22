using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Text;
using System.Text.Json;
using AppProxy.Core.Services;
using AppProxy.UI.ViewModels;
using Xunit;

namespace AppProxy.Tests;

[Collection("EnvironmentVariables")]
public class StabilityAndSecurityTests
{
    private const string Csc64Path = @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe";

    [Fact]
    public async Task MainViewModel_ConcurrentConnectionUpsertsAndBridgeDisconnects_IsThreadSafeAndPreservesOrder()
    {
        Exception? threadEx = null;
        var tcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

        var staThread = new Thread(() =>
        {
            try
            {
                using var vm = new MainViewModel();
                const uint bridgeA = 50001;
                const uint bridgeB = 50002;
                const int perBridge = 180;

                // Producer 1: Bridge A emits 180 active connections, then disconnects
                Task prodA = Task.Run(() =>
                {
                    for (int i = 1; i <= perBridge; i++)
                    {
                        vm.EnqueueConnectionUpsert(new BridgeConnectionDto
                        {
                            Id = i,
                            BridgePid = bridgeA,
                            StartTimeMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            ProcessName = "appA.exe",
                            Pid = 1001,
                            TargetDisplay = $"a-{i}.example.test:443",
                            ProxyName = "ProxyA",
                            Protocol = "SOCKS5",
                            Status = "Active",
                            BytesUp = 100,
                            BytesDown = 200
                        });
                    }
                    vm.EnqueueBridgeDisconnect(bridgeA);
                });

                // Producer 2: Bridge B concurrently floods active connections without disconnecting
                Task prodB = Task.Run(() =>
                {
                    for (int i = 1; i <= perBridge; i++)
                    {
                        vm.EnqueueConnectionUpsert(new BridgeConnectionDto
                        {
                            Id = i,
                            BridgePid = bridgeB,
                            StartTimeMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            ProcessName = "appB.exe",
                            Pid = 2002,
                            TargetDisplay = $"b-{i}.example.test:443",
                            ProxyName = "ProxyB",
                            Protocol = "HTTP",
                            Status = "Active",
                            BytesUp = 50,
                            BytesDown = 75
                        });
                    }
                });

                // Simulate UI thread periodically draining batches while producers are running
                while (!prodA.IsCompleted || !prodB.IsCompleted)
                {
                    vm.ProcessPendingConnectionOpsBatch(32);
                    Thread.Sleep(2);
                }

                Task.WaitAll(prodA, prodB);

                // Drain all remaining queued operations
                while (vm.ProcessPendingConnectionOpsBatch(64) > 0)
                {
                }

                foreach (var conn in vm.Connections)
                {
                    conn.SyncToUi();
                }

                var bridgeAConns = vm.Connections.Where(c => c.BridgePid == bridgeA).ToList();
                var bridgeBConns = vm.Connections.Where(c => c.BridgePid == bridgeB).ToList();

                Assert.Equal(perBridge, bridgeAConns.Count);
                Assert.Equal(perBridge, bridgeBConns.Count);
                Assert.All(bridgeAConns, c => Assert.Equal("Closed", c.Status));
                Assert.All(bridgeBConns, c => Assert.Equal("Active", c.Status));
            }
            catch (Exception ex)
            {
                threadEx = ex;
            }
            finally
            {
                tcs.TrySetResult();
            }
        });

        staThread.SetApartmentState(ApartmentState.STA);
        staThread.Start();
        await tcs.Task.WaitAsync(TimeSpan.FromSeconds(15));
        staThread.Join(3000);

        if (threadEx is not null)
        {
            throw threadEx;
        }
    }

    [Fact]
    public async Task NativeFakeIp_WhenSharedSlotEvicted_ReallocatesFreshFakeIpInsteadOfStaleCache()
    {
        if (!File.Exists(Csc64Path))
        {
            return;
        }

        string nativeDir = AppPaths.GetNativeDirectory();
        string injectorExe = Path.Combine(nativeDir, "AppProxy.Injector.x64.exe");
        string hookDll = Path.Combine(nativeDir, "AppProxy.Hook.x64.dll");
        Assert.True(File.Exists(injectorExe), $"Missing native injector at {injectorExe}");
        Assert.True(File.Exists(hookDll), $"Missing native hook at {hookDll}");

        string tempDir = Path.Combine(Path.GetTempPath(), "AppProxyFakeIpCoherence_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        string probeCs = Path.Combine(tempDir, "FakeIpProbe.cs");
        string probeExe = Path.Combine(tempDir, "FakeIpProbe.exe");
        string firstReadyFile = Path.Combine(tempDir, "first_ip.txt");
        string continueFile = Path.Combine(tempDir, "continue.txt");
        string secondReadyFile = Path.Combine(tempDir, "second_ip.txt");

        var savedEnv = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["APPPROXY_BRIDGE_PID"] = Environment.GetEnvironmentVariable("APPPROXY_BRIDGE_PID"),
            ["APPPROXY_SESSION_ID"] = Environment.GetEnvironmentVariable("APPPROXY_SESSION_ID"),
            ["APPPROXY_FLAGS"] = Environment.GetEnvironmentVariable("APPPROXY_FLAGS"),
            ["APPPROXY_SELF_DIR"] = Environment.GetEnvironmentVariable("APPPROXY_SELF_DIR")
        };

        int? childPid = null;
        try
        {
            File.WriteAllText(probeCs, BuildFakeIpProbeSource(), Encoding.UTF8);
            CompileWithCsc(probeCs, probeExe);

            uint bridgeId = (uint)Random.Shared.Next(200000, 899999);
            using var shm = new SharedMemoryService(bridgeId);
            const uint sessionId = 1;
            NativeSessionFlags flags = NativeSessionFlags.RemoteDns | NativeSessionFlags.BypassLan;
            shm.RegisterSession(sessionId, flags);

            Environment.SetEnvironmentVariable("APPPROXY_BRIDGE_PID", bridgeId.ToString());
            Environment.SetEnvironmentVariable("APPPROXY_SESSION_ID", sessionId.ToString());
            Environment.SetEnvironmentVariable("APPPROXY_FLAGS", ((uint)flags).ToString());
            Environment.SetEnvironmentVariable("APPPROXY_SELF_DIR", nativeDir);

            string targetArgs = $"\"alpha.evict.test\" \"{firstReadyFile}\" \"{continueFile}\" \"{secondReadyFile}\"";
            childPid = LaunchInjectedAsync(injectorExe, probeExe, targetArgs);

            await WaitForFileAsync(firstReadyFile, TimeSpan.FromSeconds(8));
            string firstIpText = File.ReadAllText(firstReadyFile).Trim();
            IPAddress firstIp = IPAddress.Parse(firstIpText);
            uint firstIpHost = BinaryPrimitives.ReadUInt32BigEndian(firstIp.GetAddressBytes());

            Assert.Equal("alpha.evict.test", shm.LookupFakeDomainForTest(firstIpHost));

            // Simulate another process evicting firstIpHost's slot on ring-buffer wrap-around
            shm.OverwriteFakeIpSlotForTest(firstIpHost, "evicted-by-other.test");
            Assert.Equal("evicted-by-other.test", shm.LookupFakeDomainForTest(firstIpHost));

            // Signal probe to resolve "alpha.evict.test" a second time inside the SAME process
            File.WriteAllText(continueFile, "go");
            await WaitForFileAsync(secondReadyFile, TimeSpan.FromSeconds(8));

            string secondIpText = File.ReadAllText(secondReadyFile).Trim();
            IPAddress secondIp = IPAddress.Parse(secondIpText);
            uint secondIpHost = BinaryPrimitives.ReadUInt32BigEndian(secondIp.GetAddressBytes());

            // Must NOT return the stale cached IP that now maps to "evicted-by-other.test"
            Assert.NotEqual(firstIpHost, secondIpHost);
            Assert.Equal("alpha.evict.test", shm.LookupFakeDomainForTest(secondIpHost));
            Assert.Equal("evicted-by-other.test", shm.LookupFakeDomainForTest(firstIpHost));
        }
        finally
        {
            try { File.WriteAllText(continueFile, "go"); } catch { }
            foreach (var kv in savedEnv)
            {
                Environment.SetEnvironmentVariable(kv.Key, kv.Value);
            }
            if (childPid.HasValue)
            {
                try
                {
                    using var p = Process.GetProcessById(childPid.Value);
                    if (!p.HasExited)
                    {
                        p.WaitForExit(3000);
                        if (!p.HasExited) p.Kill(entireProcessTree: true);
                    }
                }
                catch
                {
                }
            }
            try
            {
                if (Directory.Exists(tempDir)) Directory.Delete(tempDir, recursive: true);
            }
            catch
            {
            }
        }
    }

    private static int LaunchInjectedAsync(string injectorExe, string targetExe, string targetArgs)
    {
        string exeB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(targetExe));
        string argsB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(targetArgs));
        string workDir = Path.GetDirectoryName(targetExe) ?? Environment.SystemDirectory;
        string workDirB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(workDir));

        var psi = new ProcessStartInfo
        {
            FileName = injectorExe,
            Arguments = $"--launch --detach-console --exe-b64 {exeB64} --args-b64 {argsB64} --workdir-b64 {workDirB64}",
            WorkingDirectory = Path.GetDirectoryName(injectorExe) ?? Environment.SystemDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        using Process inj = Process.Start(psi) ?? throw new InvalidOperationException("Failed to start injector.");
        string stdout = inj.StandardOutput.ReadLine() ?? string.Empty;
        Assert.True(inj.WaitForExit(10000), "Injector timed out.");
        Assert.True(inj.ExitCode == 0, $"Injector failed ({inj.ExitCode}): {stdout}");

        using JsonDocument doc = JsonDocument.Parse(stdout.Trim());
        Assert.True(doc.RootElement.GetProperty("ok").GetBoolean(), $"Injector JSON error: {stdout}");
        return doc.RootElement.GetProperty("pid").GetInt32();
    }

    private static void CompileWithCsc(string csPath, string exePath)
    {
        var psi = new ProcessStartInfo
        {
            FileName = Csc64Path,
            Arguments = $"/nologo /target:winexe /platform:x64 /optimize+ /out:\"{exePath}\" \"{csPath}\"",
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        using Process proc = Process.Start(psi) ?? throw new InvalidOperationException("Failed to start csc.exe");
        string stdout = proc.StandardOutput.ReadToEnd();
        string stderr = proc.StandardError.ReadToEnd();
        Assert.True(proc.WaitForExit(15000), "csc.exe timed out");
        Assert.True(proc.ExitCode == 0, $"csc.exe failed ({proc.ExitCode}): {stdout}\n{stderr}");
    }

    private static async Task WaitForFileAsync(string path, TimeSpan timeout)
    {
        DateTime deadline = DateTime.UtcNow + timeout;
        while (DateTime.UtcNow < deadline)
        {
            if (File.Exists(path))
            {
                try
                {
                    if (!string.IsNullOrWhiteSpace(File.ReadAllText(path))) return;
                }
                catch
                {
                }
            }
            await Task.Delay(30);
        }
        throw new TimeoutException($"Timed out waiting for file: {path}");
    }

    private static string BuildFakeIpProbeSource() => """
        using System;
        using System.IO;
        using System.Net;
        using System.Net.Sockets;
        using System.Threading;

        internal static class Program
        {
            private static IPAddress ResolveIpv4(string host)
            {
                IPAddress[] addrs = Dns.GetHostAddresses(host);
                for (int i = 0; i < addrs.Length; i++)
                {
                    if (addrs[i].AddressFamily == AddressFamily.InterNetwork)
                    {
                        return addrs[i];
                    }
                }
                throw new InvalidOperationException("No IPv4 address returned for " + host);
            }

            public static int Main(string[] args)
            {
                if (args.Length < 4) return 2;
                string host = args[0];
                string firstFile = args[1];
                string continueFile = args[2];
                string secondFile = args[3];

                IPAddress first = ResolveIpv4(host);
                File.WriteAllText(firstFile, first.ToString());

                DateTime deadline = DateTime.UtcNow.AddSeconds(10);
                while (!File.Exists(continueFile) && DateTime.UtcNow < deadline)
                {
                    Thread.Sleep(25);
                }

                IPAddress second = ResolveIpv4(host);
                File.WriteAllText(secondFile, second.ToString());
                return 0;
            }
        }
        """;
}

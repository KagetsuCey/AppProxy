using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using AppProxy.Core.Models;
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

    [Fact]
    public async Task NativeGetAddrInfoExW_WithAiExtendedAndFqdn_ReturnsValidExtendedFieldsWithoutCrash()
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

        string tempDir = Path.Combine(Path.GetTempPath(), "AppProxyAddrInfoEx5_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        string probeCs = Path.Combine(tempDir, "AddrInfoExProbe.cs");
        string probeExe = Path.Combine(tempDir, "AddrInfoExProbe.exe");
        string outFile = Path.Combine(tempDir, "result.txt");

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
            File.WriteAllText(probeCs, BuildAddrInfoEx5ProbeSource(), Encoding.UTF8);
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

            childPid = LaunchInjectedAsync(injectorExe, probeExe, $"\"cmp1-hkg1.steamserver.test\" \"{outFile}\"");
            await WaitForProcessExitAsync(childPid.Value, TimeSpan.FromSeconds(8));

            Assert.True(File.Exists(outFile), "AddrInfoExProbe did not produce output file.");
            var dict = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (string line in File.ReadAllLines(outFile, Encoding.UTF8))
            {
                int idx = line.IndexOf('=');
                if (idx > 0) dict[line[..idx]] = line[(idx + 1)..];
            }

            Assert.Equal("0", dict["rc"]);
            Assert.Equal("1", dict["hasExtended"]);
            Assert.Equal("5", dict["version"]);
            Assert.Equal("cmp1-hkg1.steamserver.test", dict["canon"]);
            Assert.Equal("cmp1-hkg1.steamserver.test", dict["fqdn"]);
            Assert.Equal("60", dict["ttl"]);
            Assert.StartsWith("198.18.", dict["ip"], StringComparison.Ordinal);
        }
        finally
        {
            foreach (var kv in savedEnv)
            {
                Environment.SetEnvironmentVariable(kv.Key, kv.Value);
            }
            if (childPid.HasValue) KillPidSafe(childPid.Value);
            try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    [Fact]
    public async Task WinHttpWebioRequest_ThroughInjectedHookAndBridge_SucceedsWithoutCrashAndIsolatesSystemProxy()
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

        string tempDir = Path.Combine(Path.GetTempPath(), "AppProxyWinHttpWebio_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);

        string probeCs = Path.Combine(tempDir, "WinHttpProbe.cs");
        string probeExe = Path.Combine(tempDir, "WinHttpProbe.exe");
        string outFile = Path.Combine(tempDir, "body.txt");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        var savedEnv = new Dictionary<string, string?>(StringComparer.Ordinal)
        {
            ["HTTP_PROXY"] = Environment.GetEnvironmentVariable("HTTP_PROXY"),
            ["HTTPS_PROXY"] = Environment.GetEnvironmentVariable("HTTPS_PROXY"),
            ["APPPROXY_BRIDGE_PID"] = Environment.GetEnvironmentVariable("APPPROXY_BRIDGE_PID"),
            ["APPPROXY_SESSION_ID"] = Environment.GetEnvironmentVariable("APPPROXY_SESSION_ID"),
            ["APPPROXY_FLAGS"] = Environment.GetEnvironmentVariable("APPPROXY_FLAGS"),
            ["APPPROXY_SELF_DIR"] = Environment.GetEnvironmentVariable("APPPROXY_SELF_DIR")
        };

        using var socksListener = new TcpListener(IPAddress.Loopback, 0);
        socksListener.Start();
        int socksPort = ((IPEndPoint)socksListener.LocalEndpoint).Port;
        string? observedDomain = null;
        ushort observedPort = 0;

        Task socksTask = Task.Run(async () =>
        {
            using TcpClient proxyConn = await socksListener.AcceptTcpClientAsync(cts.Token);
            using NetworkStream ns = proxyConn.GetStream();

            byte[] greetHdr = new byte[2];
            await ReadExactAsync(ns, greetHdr, cts.Token);
            byte[] methods = new byte[greetHdr[1]];
            await ReadExactAsync(ns, methods, cts.Token);
            await ns.WriteAsync(new byte[] { 0x05, 0x00 }, cts.Token);

            byte[] reqHdr = new byte[4];
            await ReadExactAsync(ns, reqHdr, cts.Token);
            Assert.Equal(0x03, reqHdr[3]); // Domain resolved from Fake-IP
            byte[] lenBuf = new byte[1];
            await ReadExactAsync(ns, lenBuf, cts.Token);
            byte[] domBuf = new byte[lenBuf[0]];
            await ReadExactAsync(ns, domBuf, cts.Token);
            observedDomain = Encoding.UTF8.GetString(domBuf);

            byte[] portBuf = new byte[2];
            await ReadExactAsync(ns, portBuf, cts.Token);
            observedPort = (ushort)((portBuf[0] << 8) | portBuf[1]);

            await ns.WriteAsync(new byte[] { 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0 }, cts.Token);

            var reqText = new StringBuilder();
            byte[] b = new byte[1];
            while (!cts.IsCancellationRequested)
            {
                int n = await ns.ReadAsync(b, cts.Token);
                if (n <= 0) break;
                reqText.Append((char)b[0]);
                if (reqText.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal)) break;
            }

            byte[] resp = Encoding.ASCII.GetBytes(
                "HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\nwinhttp-webio-ok");
            await ns.WriteAsync(resp, cts.Token);
            await ns.FlushAsync(cts.Token);
        }, cts.Token);

        int? childPid = null;
        try
        {
            File.WriteAllText(probeCs, BuildWinHttpWebioProbeSource(), Encoding.UTF8);
            CompileWithCsc(probeCs, probeExe);

            uint bridgeId = (uint)Random.Shared.Next(200000, 899999);
            using var shm = new SharedMemoryService(bridgeId);
            using var bridge = new LocalProxyBridge(shm);

            const uint sessionId = 1;
            NativeSessionFlags flags =
                NativeSessionFlags.RemoteDns |
                NativeSessionFlags.BypassLan |
                NativeSessionFlags.IgnoreSystemProxy;

            shm.RegisterSession(sessionId, flags);
            bridge.RegisterSession(new SessionContext
            {
                SessionId = sessionId,
                AppName = "WinHttpProbe.exe",
                Proxy = new ProxyProfile
                {
                    Name = "MockSocks5",
                    Protocol = ProxyProtocol.Socks5,
                    Host = "127.0.0.1",
                    Port = socksPort
                },
                RemoteDns = true,
                BypassLan = true
            });

            // Poison proxy env vars to confirm WinHTTP + IgnoreSystemProxy still routes through AppProxy
            Environment.SetEnvironmentVariable("HTTP_PROXY", "http://127.0.0.1:1");
            Environment.SetEnvironmentVariable("HTTPS_PROXY", "http://127.0.0.1:1");
            Environment.SetEnvironmentVariable("APPPROXY_BRIDGE_PID", bridgeId.ToString());
            Environment.SetEnvironmentVariable("APPPROXY_SESSION_ID", sessionId.ToString());
            Environment.SetEnvironmentVariable("APPPROXY_FLAGS", ((uint)flags).ToString());
            Environment.SetEnvironmentVariable("APPPROXY_SELF_DIR", nativeDir);

            childPid = LaunchInjectedAsync(injectorExe, probeExe, $"\"winhttp-webio.appproxy.test\" 8080 \"{outFile}\"");
            int exitCode = await WaitForProcessExitAsync(childPid.Value, TimeSpan.FromSeconds(10));
            Assert.Equal(0, exitCode);

            await socksTask.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.True(File.Exists(outFile), "WinHttpProbe did not write response body.");
            Assert.Equal("winhttp-webio-ok", File.ReadAllText(outFile, Encoding.UTF8).Trim());
            Assert.Equal("winhttp-webio.appproxy.test", observedDomain);
            Assert.Equal((ushort)8080, observedPort);
        }
        finally
        {
            cts.Cancel();
            try { socksListener.Stop(); } catch { }
            foreach (var kv in savedEnv)
            {
                Environment.SetEnvironmentVariable(kv.Key, kv.Value);
            }
            if (childPid.HasValue) KillPidSafe(childPid.Value);
            try { if (Directory.Exists(tempDir)) Directory.Delete(tempDir, recursive: true); } catch { }
        }
    }

    private static async Task<int> WaitForProcessExitAsync(int pid, TimeSpan timeout)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            using var cts = new CancellationTokenSource(timeout);
            await proc.WaitForExitAsync(cts.Token);
            return proc.ExitCode;
        }
        catch (ArgumentException)
        {
            return 0;
        }
    }

    private static void KillPidSafe(int pid)
    {
        try
        {
            using var proc = Process.GetProcessById(pid);
            if (!proc.HasExited)
            {
                proc.Kill(entireProcessTree: true);
                proc.WaitForExit(3000);
            }
        }
        catch
        {
        }
    }

    private static async Task ReadExactAsync(Stream s, byte[] buf, CancellationToken ct)
    {
        int read = 0;
        while (read < buf.Length)
        {
            int n = await s.ReadAsync(buf.AsMemory(read, buf.Length - read), ct);
            if (n <= 0) throw new EndOfStreamException();
            read += n;
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

    private static string BuildAddrInfoEx5ProbeSource() => """
        using System;
        using System.Collections.Generic;
        using System.IO;
        using System.Net;
        using System.Runtime.InteropServices;

        internal static class Program
        {
            private const uint NS_DNS = 12;
            private const int AF_UNSPEC = 0;
            private const int SOCK_STREAM = 1;
            private const int IPPROTO_TCP = 6;
            private const int AI_CANONNAME = 0x00000002;
            private const int AI_FQDN = 0x00020000;
            private const int AI_EXTENDED = unchecked((int)0x80000000);

            [StructLayout(LayoutKind.Sequential)]
            private struct WSADATA
            {
                public ushort wVersion;
                public ushort wHighVersion;
                public ushort iMaxSockets;
                public ushort iMaxUdpDg;
                public IntPtr lpVendorInfo;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 257)]
                public byte[] szDescription;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 129)]
                public byte[] szSystemStatus;
            }

            [StructLayout(LayoutKind.Sequential)]
            private struct ADDRINFOEX5
            {
                public int ai_flags;
                public int ai_family;
                public int ai_socktype;
                public int ai_protocol;
                public UIntPtr ai_addrlen;
                public IntPtr ai_canonname;
                public IntPtr ai_addr;
                public IntPtr ai_blob;
                public UIntPtr ai_bloblen;
                public IntPtr ai_provider;
                public IntPtr ai_next;
                public int ai_version;
                public IntPtr ai_fqdn;
                public int ai_interfaceindex;
                public IntPtr ai_resolutionhandle;
                public uint ai_ttl;
            }

            [DllImport("ws2_32.dll")]
            private static extern int WSAStartup(ushort wVersionRequested, out WSADATA lpWSAData);

            [DllImport("ws2_32.dll")]
            private static extern int WSACleanup();

            [DllImport("ws2_32.dll", CharSet = CharSet.Unicode)]
            private static extern int GetAddrInfoExW(
                string pName,
                string pServiceName,
                uint dwNameSpace,
                IntPtr lpNspId,
                ref ADDRINFOEX5 pHints,
                out IntPtr ppResult,
                IntPtr timeout,
                IntPtr lpOverlapped,
                IntPtr lpCompletionRoutine,
                IntPtr lpHandle);

            [DllImport("ws2_32.dll")]
            private static extern void FreeAddrInfoExW(IntPtr pAddrInfo);

            public static int Main(string[] args)
            {
                if (args.Length < 2) return 2;
                string host = args[0];
                string outFile = args[1];

                WSADATA wsa;
                WSAStartup(0x0202, out wsa);
                try
                {
                    ADDRINFOEX5 hints = new ADDRINFOEX5();
                    hints.ai_flags = AI_EXTENDED | AI_FQDN | AI_CANONNAME;
                    hints.ai_family = AF_UNSPEC;
                    hints.ai_socktype = SOCK_STREAM;
                    hints.ai_protocol = IPPROTO_TCP;
                    hints.ai_version = 5;

                    IntPtr resultPtr;
                    int rc = GetAddrInfoExW(host, "443", NS_DNS, IntPtr.Zero, ref hints, out resultPtr, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                    List<string> lines = new List<string>();
                    lines.Add("rc=" + rc);
                    if (rc == 0 && resultPtr != IntPtr.Zero)
                    {
                        ADDRINFOEX5 res = (ADDRINFOEX5)Marshal.PtrToStructure(resultPtr, typeof(ADDRINFOEX5));
                        bool hasExtended = (((uint)res.ai_flags) & 0x80000000u) != 0;
                        string canon = res.ai_canonname != IntPtr.Zero ? Marshal.PtrToStringUni(res.ai_canonname) : string.Empty;
                        string fqdn = res.ai_fqdn != IntPtr.Zero ? Marshal.PtrToStringUni(res.ai_fqdn) : string.Empty;
                        byte[] ipBytes = new byte[4];
                        Marshal.Copy(new IntPtr(res.ai_addr.ToInt64() + 4), ipBytes, 0, 4);
                        string ipStr = new IPAddress(ipBytes).ToString();

                        lines.Add("hasExtended=" + (hasExtended ? "1" : "0"));
                        lines.Add("version=" + res.ai_version);
                        lines.Add("canon=" + canon);
                        lines.Add("fqdn=" + fqdn);
                        lines.Add("ttl=" + res.ai_ttl);
                        lines.Add("ip=" + ipStr);

                        FreeAddrInfoExW(resultPtr);
                    }
                    File.WriteAllLines(outFile, lines.ToArray());
                    return rc == 0 ? 0 : 1;
                }
                finally
                {
                    WSACleanup();
                }
            }
        }
        """;

    private static string BuildWinHttpWebioProbeSource() => """
        using System;
        using System.IO;
        using System.Runtime.InteropServices;
        using System.Text;

        internal static class Program
        {
            private const uint WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY = 4;

            [DllImport("winhttp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            private static extern IntPtr WinHttpOpen(string pszAgentW, uint dwAccessType, string pszProxyW, string pszProxyBypassW, uint dwFlags);

            [DllImport("winhttp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            private static extern IntPtr WinHttpConnect(IntPtr hSession, string pswzServerName, ushort nServerPort, uint dwReserved);

            [DllImport("winhttp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            private static extern IntPtr WinHttpOpenRequest(IntPtr hConnect, string pwszVerb, string pwszObjectName, string pwszVersion, string pwszReferrer, IntPtr ppwszAcceptTypes, uint dwFlags);

            [DllImport("winhttp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            private static extern bool WinHttpSendRequest(IntPtr hRequest, string lpszHeaders, uint dwHeadersLength, IntPtr lpOptional, uint dwOptionalLength, uint dwTotalLength, IntPtr dwContext);

            [DllImport("winhttp.dll", SetLastError = true)]
            private static extern bool WinHttpReceiveResponse(IntPtr hRequest, IntPtr lpReserved);

            [DllImport("winhttp.dll", SetLastError = true)]
            private static extern bool WinHttpReadData(IntPtr hRequest, byte[] lpBuffer, uint dwNumberOfBytesToRead, out uint lpdwNumberOfBytesRead);

            [DllImport("winhttp.dll", SetLastError = true)]
            private static extern bool WinHttpCloseHandle(IntPtr hInternet);

            public static int Main(string[] args)
            {
                if (args.Length < 3) return 2;
                string host = args[0];
                ushort port = ushort.Parse(args[1]);
                string outFile = args[2];

                IntPtr hSession = IntPtr.Zero;
                IntPtr hConnect = IntPtr.Zero;
                IntPtr hRequest = IntPtr.Zero;
                try
                {
                    hSession = WinHttpOpen("AppProxyWinHttpProbe/1.0", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY, null, null, 0);
                    if (hSession == IntPtr.Zero) return 10;

                    hConnect = WinHttpConnect(hSession, host, port, 0);
                    if (hConnect == IntPtr.Zero) return 11;

                    hRequest = WinHttpOpenRequest(hConnect, "GET", "/check", null, null, IntPtr.Zero, 0);
                    if (hRequest == IntPtr.Zero) return 12;

                    if (!WinHttpSendRequest(hRequest, null, 0, IntPtr.Zero, 0, 0, IntPtr.Zero)) return 13;
                    if (!WinHttpReceiveResponse(hRequest, IntPtr.Zero)) return 14;

                    using (MemoryStream ms = new MemoryStream())
                    {
                        byte[] buf = new byte[4096];
                        uint read;
                        while (WinHttpReadData(hRequest, buf, (uint)buf.Length, out read) && read > 0)
                        {
                            ms.Write(buf, 0, (int)read);
                        }
                        File.WriteAllText(outFile, Encoding.UTF8.GetString(ms.ToArray()), Encoding.UTF8);
                    }
                    return 0;
                }
                finally
                {
                    if (hRequest != IntPtr.Zero) WinHttpCloseHandle(hRequest);
                    if (hConnect != IntPtr.Zero) WinHttpCloseHandle(hConnect);
                    if (hSession != IntPtr.Zero) WinHttpCloseHandle(hSession);
                }
            }
        }
        """;
}

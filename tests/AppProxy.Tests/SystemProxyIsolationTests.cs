using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using AppProxy.UI.Models;
using AppProxy.UI.Services;
using Microsoft.Win32;
using Xunit;

namespace AppProxy.Tests;

[Collection("EnvironmentVariables")]
public class SystemProxyIsolationTests
{
    private const string Csc64Path = @"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe";

    [Fact]
    public void SystemProxyHooks_WhenEnabled_IsolatesEnvWinHttpWinInetAndRegistry_AndPreservesWhenDisabled()
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

        string testId = Guid.NewGuid().ToString("N");
        string tempDir = Path.Combine(Path.GetTempPath(), "AppProxySysProxyTest_" + testId);
        Directory.CreateDirectory(tempDir);

        string sandboxRootSubKey = @"Software\AppProxySysProxyTest_" + testId;
        string sandboxSettingsSubKey = sandboxRootSubKey + @"\Microsoft\Windows\CurrentVersion\Internet Settings";
        string sandboxConnSubKey = sandboxSettingsSubKey + @"\Connections";

        string probeCs = Path.Combine(tempDir, "SysProxyProbe.cs");
        string probeExe = Path.Combine(tempDir, "SysProxyProbe.exe");
        string outIsolated = Path.Combine(tempDir, "out_isolated.txt");
        string outUnisolated = Path.Combine(tempDir, "out_unisolated.txt");

        using var envGuard = new ScopedEnvGuard(
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "FTP_PROXY",
            "SOCKS_PROXY",
            "http_proxy",
            "https_proxy",
            "APPPROXY_BRIDGE_PID",
            "APPPROXY_SESSION_ID",
            "APPPROXY_FLAGS",
            "APPPROXY_SELF_DIR");

        try
        {
            // Populate isolated HKCU subkey tree (never touching real Internet Settings!)
            using (RegistryKey settingsKey = Registry.CurrentUser.CreateSubKey(sandboxSettingsSubKey, writable: true))
            {
                settingsKey.SetValue("ProxyEnable", 1, RegistryValueKind.DWord);
                settingsKey.SetValue("ProxyServer", "127.0.0.1:10809", RegistryValueKind.String);
                settingsKey.SetValue("AutoConfigURL", "http://127.0.0.1:10809/pac", RegistryValueKind.String);
                settingsKey.SetValue("ProxyOverride", "<local>", RegistryValueKind.String);
            }

            byte[] connBlob = new byte[24];
            BitConverter.GetBytes(0x46u).CopyTo(connBlob, 0);
            BitConverter.GetBytes(1u).CopyTo(connBlob, 4);
            BitConverter.GetBytes(3u).CopyTo(connBlob, 8); // PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY
            using (RegistryKey connKey = Registry.CurrentUser.CreateSubKey(sandboxConnSubKey, writable: true))
            {
                connKey.SetValue("DefaultConnectionSettings", connBlob, RegistryValueKind.Binary);
            }

            File.WriteAllText(probeCs, BuildCSharp5ProbeSource(), Encoding.UTF8);
            CompileWithCsc(probeCs, probeExe);

            uint bridgeId = (uint)Random.Shared.Next(200000, 899999);
            using var shm = new SharedMemoryService(bridgeId);
            shm.RegisterSession(
                1,
                NativeSessionFlags.RemoteDns | NativeSessionFlags.BypassLan | NativeSessionFlags.IgnoreSystemProxy);
            shm.RegisterSession(
                2,
                NativeSessionFlags.RemoteDns | NativeSessionFlags.BypassLan);

            Environment.SetEnvironmentVariable("HTTP_PROXY", "http://127.0.0.1:10809");
            Environment.SetEnvironmentVariable("HTTPS_PROXY", "http://127.0.0.1:10809");
            Environment.SetEnvironmentVariable("ALL_PROXY", "socks5://127.0.0.1:10808");
            Environment.SetEnvironmentVariable("http_proxy", "http://127.0.0.1:10809");
            Environment.SetEnvironmentVariable("APPPROXY_BRIDGE_PID", bridgeId.ToString());
            Environment.SetEnvironmentVariable("APPPROXY_SELF_DIR", nativeDir);

            // Case A: IgnoreSystemProxy = true (FLAG_IGNORE_SYSTEM_PROXY set)
            uint isolatedFlags = (uint)(NativeSessionFlags.RemoteDns | NativeSessionFlags.BypassLan | NativeSessionFlags.IgnoreSystemProxy);
            Environment.SetEnvironmentVariable("APPPROXY_SESSION_ID", "1");
            Environment.SetEnvironmentVariable("APPPROXY_FLAGS", isolatedFlags.ToString());

            RunInjectedExecutableAndWait(injectorExe, probeExe, $"\"{sandboxSettingsSubKey}\" \"{outIsolated}\"");
            Dictionary<string, string> resA = ParseKeyValueFile(outIsolated);

            Assert.Equal(string.Empty, resA["env:HTTP_PROXY"]);
            Assert.Equal(string.Empty, resA["env:HTTPS_PROXY"]);
            Assert.Equal(string.Empty, resA["env:ALL_PROXY"]);
            Assert.Equal(string.Empty, resA["env:http_proxy"]);
            Assert.Equal("NONE", resA["child:HTTP_PROXY"]);

            Assert.Equal("0:0", resA["reg:GetValueW:ProxyEnable"]);
            Assert.Equal("2:", resA["reg:GetValueW:ProxyServer"]);
            Assert.Equal("2:", resA["reg:GetValueW:AutoConfigURL"]);
            Assert.Equal("0:0", resA["reg:QueryExW:ProxyEnable"]);
            Assert.Equal("2:", resA["reg:QueryExA:ProxyServer"]);
            Assert.Equal("0:1", resA["reg:DefaultConnFlags"]);

            Assert.Equal("True:False::", resA["winhttp:IE"]);
            Assert.Equal("True:1:", resA["winhttp:GetProxyForUrl"]);

            Assert.Equal("True:1:", resA["wininet:GlobalQuery"]);
            Assert.Equal("True:1:", resA["wininet:SessionQuery"]);
            Assert.Equal("True:1:", resA["wininet:PerConn"]);

            // Case B: IgnoreSystemProxy = false (flag not set) -> preserves proxy env & registry reads
            uint unisolatedFlags = (uint)(NativeSessionFlags.RemoteDns | NativeSessionFlags.BypassLan);
            Environment.SetEnvironmentVariable("APPPROXY_SESSION_ID", "2");
            Environment.SetEnvironmentVariable("APPPROXY_FLAGS", unisolatedFlags.ToString());

            RunInjectedExecutableAndWait(injectorExe, probeExe, $"\"{sandboxSettingsSubKey}\" \"{outUnisolated}\"");
            Dictionary<string, string> resB = ParseKeyValueFile(outUnisolated);

            Assert.Equal("http://127.0.0.1:10809", resB["env:HTTP_PROXY"]);
            Assert.Equal("0:1", resB["reg:GetValueW:ProxyEnable"]);
            Assert.Equal("0:127.0.0.1:10809", resB["reg:GetValueW:ProxyServer"]);
        }
        finally
        {
            try
            {
                Registry.CurrentUser.DeleteSubKeyTree(sandboxRootSubKey, throwOnMissingSubKey: false);
            }
            catch
            {
            }

            if (Directory.Exists(tempDir))
            {
                try { Directory.Delete(tempDir, recursive: true); } catch { }
            }
        }
    }

    [Fact]
    public async Task CurlWithFakeSystemProxyEnv_IgnoresV2rayPort_AndRoutesThroughAppProxyBridge()
    {
        string curlExe = Path.Combine(Environment.SystemDirectory, "curl.exe");
        if (!File.Exists(curlExe))
        {
            return;
        }

        string nativeDir = AppPaths.GetNativeDirectory();
        string injectorExe = Path.Combine(nativeDir, "AppProxy.Injector.x64.exe");
        Assert.True(File.Exists(injectorExe), $"Missing native injector at {injectorExe}");

        string tempDir = Path.Combine(Path.GetTempPath(), "AppProxyCurlIsolation_" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(tempDir);
        string curlOutFile = Path.Combine(tempDir, "response.txt");

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var envGuard = new ScopedEnvGuard(
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "APPPROXY_BRIDGE_PID",
            "APPPROXY_SESSION_ID",
            "APPPROXY_FLAGS",
            "APPPROXY_SELF_DIR");

        // Mock v2rayN local HTTP proxy that must NEVER be hit
        using var mockV2rayListener = new TcpListener(IPAddress.Loopback, 0);
        mockV2rayListener.Start();
        int mockV2rayPort = ((IPEndPoint)mockV2rayListener.LocalEndpoint).Port;
        int v2rayConnectionCount = 0;

        Task acceptV2rayLoop = Task.Run(async () =>
        {
            while (!cts.IsCancellationRequested)
            {
                try
                {
                    using TcpClient c = await mockV2rayListener.AcceptTcpClientAsync(cts.Token);
                    Interlocked.Increment(ref v2rayConnectionCount);
                }
                catch
                {
                    break;
                }
            }
        }, cts.Token);

        // Mock AppProxy upstream SOCKS5 node ("Japan node")
        using var mockJapanSocks5 = new TcpListener(IPAddress.Loopback, 0);
        mockJapanSocks5.Start();
        int japanPort = ((IPEndPoint)mockJapanSocks5.LocalEndpoint).Port;
        string? observedTargetDomain = null;
        ushort observedTargetPort = 0;

        Task acceptJapanTask = Task.Run(async () =>
        {
            using TcpClient proxyConn = await mockJapanSocks5.AcceptTcpClientAsync(cts.Token);
            using NetworkStream ns = proxyConn.GetStream();

            byte[] greetHdr = new byte[2];
            await ReadExactAsync(ns, greetHdr, cts.Token);
            byte[] methods = new byte[greetHdr[1]];
            await ReadExactAsync(ns, methods, cts.Token);
            await ns.WriteAsync(new byte[] { 0x05, 0x00 }, cts.Token);

            byte[] reqHdr = new byte[4];
            await ReadExactAsync(ns, reqHdr, cts.Token);
            Assert.Equal(0x03, reqHdr[3]); // Domain address from Fake-IP resolution
            byte[] lenBuf = new byte[1];
            await ReadExactAsync(ns, lenBuf, cts.Token);
            byte[] domBuf = new byte[lenBuf[0]];
            await ReadExactAsync(ns, domBuf, cts.Token);
            observedTargetDomain = Encoding.UTF8.GetString(domBuf);

            byte[] portBuf = new byte[2];
            await ReadExactAsync(ns, portBuf, cts.Token);
            observedTargetPort = (ushort)((portBuf[0] << 8) | portBuf[1]);

            await ns.WriteAsync(new byte[] { 0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0 }, cts.Token);

            // Drain HTTP request headers until \r\n\r\n
            var reqText = new StringBuilder();
            byte[] b = new byte[1];
            while (!cts.IsCancellationRequested)
            {
                int n = await ns.ReadAsync(b, cts.Token);
                if (n <= 0) break;
                reqText.Append((char)b[0]);
                if (reqText.ToString().EndsWith("\r\n\r\n", StringComparison.Ordinal))
                {
                    break;
                }
            }

            byte[] httpResp = Encoding.ASCII.GetBytes(
                "HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\njapan-node-ok");
            await ns.WriteAsync(httpResp, cts.Token);
            await ns.FlushAsync(cts.Token);
        }, cts.Token);

        try
        {
            uint bridgeId = (uint)Random.Shared.Next(200000, 899999);
            using var shm = new SharedMemoryService(bridgeId);
            using var bridge = new LocalProxyBridge(shm);

            var japanProxy = new ProxyProfile
            {
                Name = "JapanNode",
                Protocol = ProxyProtocol.Socks5,
                Host = "127.0.0.1",
                Port = japanPort
            };

            const uint sessionId = 1;
            NativeSessionFlags flags =
                NativeSessionFlags.RemoteDns |
                NativeSessionFlags.BypassLan |
                NativeSessionFlags.IgnoreSystemProxy;

            shm.RegisterSession(sessionId, flags);
            bridge.RegisterSession(new SessionContext
            {
                SessionId = sessionId,
                AppName = "curl.exe",
                Proxy = japanProxy,
                RemoteDns = true,
                BypassLan = true
            });

            // Simulate v2rayN proxy env vars present before launch (explicitly testing native Hook sanitization)
            Environment.SetEnvironmentVariable("HTTP_PROXY", $"http://127.0.0.1:{mockV2rayPort}");
            Environment.SetEnvironmentVariable("http_proxy", $"http://127.0.0.1:{mockV2rayPort}");
            Environment.SetEnvironmentVariable("HTTPS_PROXY", $"http://127.0.0.1:{mockV2rayPort}");
            Environment.SetEnvironmentVariable("APPPROXY_BRIDGE_PID", bridgeId.ToString());
            Environment.SetEnvironmentVariable("APPPROXY_SESSION_ID", sessionId.ToString());
            Environment.SetEnvironmentVariable("APPPROXY_FLAGS", ((uint)flags).ToString());
            Environment.SetEnvironmentVariable("APPPROXY_SELF_DIR", nativeDir);

            RunInjectedExecutableAndWait(
                injectorExe,
                curlExe,
                $"-sS -m 5 -o \"{curlOutFile}\" http://isolated.appproxy.test:8080/check");

            await acceptJapanTask;
            Assert.True(File.Exists(curlOutFile), "curl output file was not produced.");
            Assert.Equal("japan-node-ok", File.ReadAllText(curlOutFile));
            Assert.Equal("isolated.appproxy.test", observedTargetDomain);
            Assert.Equal((ushort)8080, observedTargetPort);
            Assert.Equal(0, Volatile.Read(ref v2rayConnectionCount));
        }
        finally
        {
            cts.Cancel();
            try { mockV2rayListener.Stop(); } catch { }
            try { await acceptV2rayLoop; } catch { }
            if (Directory.Exists(tempDir))
            {
                try { Directory.Delete(tempDir, recursive: true); } catch { }
            }
        }
    }

    private static void CompileWithCsc(string csPath, string exePath)
    {
        var psi = new ProcessStartInfo
        {
            FileName = Csc64Path,
            Arguments = $"/nologo /platform:x64 /optimize+ /out:\"{exePath}\" \"{csPath}\"",
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

    private static void RunInjectedExecutableAndWait(string injectorExe, string targetExe, string targetArgs)
    {
        string exeB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(targetExe));
        string argsB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(targetArgs));
        string workDir = Path.GetDirectoryName(targetExe) ?? Environment.SystemDirectory;
        string workDirB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(workDir));

        var psi = new ProcessStartInfo
        {
            FileName = injectorExe,
            Arguments = $"--launch --exe-b64 {exeB64} --args-b64 {argsB64} --workdir-b64 {workDirB64}",
            WorkingDirectory = Path.GetDirectoryName(injectorExe) ?? Environment.SystemDirectory,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        using Process injProc = Process.Start(psi) ?? throw new InvalidOperationException("Failed to start injector.");
        string stdout = injProc.StandardOutput.ReadToEnd();
        string stderr = injProc.StandardError.ReadToEnd();
        Assert.True(injProc.WaitForExit(10000), "Injector timed out.");
        Assert.True(injProc.ExitCode == 0, $"Injector exited with {injProc.ExitCode}: {stdout} {stderr}");

        using JsonDocument doc = JsonDocument.Parse(stdout.Trim());
        Assert.True(doc.RootElement.GetProperty("ok").GetBoolean(), $"Injector JSON failed: {stdout}");
        int childPid = doc.RootElement.GetProperty("pid").GetInt32();

        try
        {
            using Process childProc = Process.GetProcessById(childPid);
            Assert.True(childProc.WaitForExit(10000), $"Injected child PID {childPid} timed out.");
            Assert.Equal(0, childProc.ExitCode);
        }
        catch (ArgumentException)
        {
            // Fast target exited before GetProcessById was called
        }
    }

    private static Dictionary<string, string> ParseKeyValueFile(string path)
    {
        Assert.True(File.Exists(path), $"Expected probe output file at {path}");
        var dict = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (string line in File.ReadAllLines(path, Encoding.UTF8))
        {
            int idx = line.IndexOf('=');
            if (idx > 0)
            {
                dict[line[..idx]] = line[(idx + 1)..];
            }
        }
        return dict;
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

    private sealed class ScopedEnvGuard : IDisposable
    {
        private readonly Dictionary<string, string?> _saved = new(StringComparer.Ordinal);

        public ScopedEnvGuard(params string[] keys)
        {
            foreach (string key in keys)
            {
                _saved[key] = Environment.GetEnvironmentVariable(key);
            }
        }

        public void Dispose()
        {
            foreach (var kv in _saved)
            {
                Environment.SetEnvironmentVariable(kv.Key, kv.Value);
            }
        }
    }

    private static string BuildCSharp5ProbeSource() => """
        using System;
        using System.Collections.Generic;
        using System.Diagnostics;
        using System.IO;
        using System.Runtime.InteropServices;
        using System.Text;

        namespace SysProxyProbe
        {
            internal static class Program
            {
                private static readonly IntPtr HKEY_CURRENT_USER = new IntPtr(unchecked((int)0x80000001));
                private const uint KEY_READ = 0x20019;
                private const uint RRF_RT_ANY = 0x0000FFFF;
                private const uint WINHTTP_ACCESS_TYPE_DEFAULT_PROXY = 0;
                private const uint WINHTTP_AUTOPROXY_CONFIG_URL = 0x00000002;
                private const uint INTERNET_OPEN_TYPE_PRECONFIG = 0;
                private const uint INTERNET_OPTION_PROXY = 38;
                private const uint INTERNET_OPTION_PER_CONNECTION_OPTION = 75;
                private const uint INTERNET_PER_CONN_FLAGS = 1;
                private const uint INTERNET_PER_CONN_PROXY_SERVER = 2;

                [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
                private struct WINHTTP_CURRENT_USER_IE_PROXY_CONFIG
                {
                    [MarshalAs(UnmanagedType.Bool)]
                    public bool fAutoDetect;
                    public IntPtr lpszAutoConfigUrl;
                    public IntPtr lpszProxy;
                    public IntPtr lpszProxyBypass;
                }

                [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
                private struct WINHTTP_AUTOPROXY_OPTIONS
                {
                    public uint dwFlags;
                    public uint dwAutoDetectFlags;
                    public string lpszAutoConfigUrl;
                    public IntPtr lpvReserved;
                    public uint dwReserved;
                    [MarshalAs(UnmanagedType.Bool)]
                    public bool fAutoLogonIfChallenged;
                }

                [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
                private struct WINHTTP_PROXY_INFO
                {
                    public uint dwAccessType;
                    public IntPtr lpszProxy;
                    public IntPtr lpszProxyBypass;
                }

                [StructLayout(LayoutKind.Sequential)]
                private struct INTERNET_PROXY_INFO
                {
                    public uint dwAccessType;
                    public IntPtr lpszProxy;
                    public IntPtr lpszProxyBypass;
                }

                [StructLayout(LayoutKind.Explicit)]
                private struct INTERNET_PER_CONN_OPTION_VALUE
                {
                    [FieldOffset(0)]
                    public uint dwValue;
                    [FieldOffset(0)]
                    public IntPtr pszValue;
                    [FieldOffset(0)]
                    public ulong ftValue;
                }

                [StructLayout(LayoutKind.Sequential)]
                private struct INTERNET_PER_CONN_OPTIONW
                {
                    public uint dwOption;
                    public INTERNET_PER_CONN_OPTION_VALUE Value;
                }

                [StructLayout(LayoutKind.Sequential)]
                private struct INTERNET_PER_CONN_OPTION_LISTW
                {
                    public uint dwSize;
                    public IntPtr pszConnection;
                    public uint dwOptionCount;
                    public uint dwOptionError;
                    public IntPtr pOptions;
                }

                [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
                private static extern int RegOpenKeyExW(IntPtr hKey, string lpSubKey, uint ulOptions, uint samDesired, out IntPtr phkResult);

                [DllImport("advapi32.dll")]
                private static extern int RegCloseKey(IntPtr hKey);

                [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
                private static extern int RegGetValueW(IntPtr hkey, string lpSubKey, string lpValue, uint dwFlags, out uint pdwType, byte[] pvData, ref uint pcbData);

                [DllImport("advapi32.dll", CharSet = CharSet.Unicode)]
                private static extern int RegQueryValueExW(IntPtr hKey, string lpValueName, IntPtr lpReserved, out uint lpType, byte[] lpData, ref uint lpcbData);

                [DllImport("advapi32.dll", CharSet = CharSet.Ansi)]
                private static extern int RegQueryValueExA(IntPtr hKey, string lpValueName, IntPtr lpReserved, out uint lpType, byte[] lpData, ref uint lpcbData);

                [DllImport("winhttp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
                private static extern IntPtr WinHttpOpen(string pwszUserAgent, uint dwAccessType, string pwszProxyName, string pwszProxyBypass, uint dwFlags);

                [DllImport("winhttp.dll", SetLastError = true)]
                private static extern bool WinHttpCloseHandle(IntPtr hInternet);

                [DllImport("winhttp.dll", SetLastError = true)]
                private static extern bool WinHttpGetIEProxyConfigForCurrentUser(ref WINHTTP_CURRENT_USER_IE_PROXY_CONFIG pProxyConfig);

                [DllImport("winhttp.dll", CharSet = CharSet.Unicode, SetLastError = true)]
                private static extern bool WinHttpGetProxyForUrl(IntPtr hSession, string lpcwszUrl, ref WINHTTP_AUTOPROXY_OPTIONS pAutoProxyOptions, out WINHTTP_PROXY_INFO pProxyInfo);

                [DllImport("wininet.dll", CharSet = CharSet.Unicode, SetLastError = true)]
                private static extern IntPtr InternetOpenW(string lpszAgent, uint dwAccessType, string lpszProxy, string lpszProxyBypass, uint dwFlags);

                [DllImport("wininet.dll", SetLastError = true)]
                private static extern bool InternetCloseHandle(IntPtr hInternet);

                [DllImport("wininet.dll", CharSet = CharSet.Unicode, SetLastError = true)]
                private static extern bool InternetQueryOptionW(IntPtr hInternet, uint dwOption, IntPtr lpBuffer, ref uint lpdwBufferLength);

                private static string ReadChildHttpProxy()
                {
                    ProcessStartInfo psi = new ProcessStartInfo();
                    psi.FileName = Path.Combine(Environment.SystemDirectory, "cmd.exe");
                    psi.Arguments = "/c \"if defined HTTP_PROXY (echo %HTTP_PROXY%) else (echo NONE)\"";
                    psi.UseShellExecute = false;
                    psi.RedirectStandardOutput = true;
                    psi.CreateNoWindow = true;
                    Process p = Process.Start(psi);
                    string output = p.StandardOutput.ReadToEnd().Trim();
                    p.WaitForExit(5000);
                    return output;
                }

                public static int Main(string[] args)
                {
                    if (args.Length < 2) return 2;
                    string settingsSubKey = args[0];
                    string outPath = args[1];
                    List<string> lines = new List<string>();

                    lines.Add("env:HTTP_PROXY=" + (Environment.GetEnvironmentVariable("HTTP_PROXY") ?? string.Empty));
                    lines.Add("env:HTTPS_PROXY=" + (Environment.GetEnvironmentVariable("HTTPS_PROXY") ?? string.Empty));
                    lines.Add("env:ALL_PROXY=" + (Environment.GetEnvironmentVariable("ALL_PROXY") ?? string.Empty));
                    lines.Add("env:http_proxy=" + (Environment.GetEnvironmentVariable("http_proxy") ?? string.Empty));
                    lines.Add("child:HTTP_PROXY=" + ReadChildHttpProxy());

                    uint valType;
                    byte[] buf = new byte[512];
                    uint cb = (uint)buf.Length;
                    int rc = RegGetValueW(HKEY_CURRENT_USER, settingsSubKey, "ProxyEnable", RRF_RT_ANY, out valType, buf, ref cb);
                    lines.Add("reg:GetValueW:ProxyEnable=" + rc + ":" + (rc == 0 ? BitConverter.ToUInt32(buf, 0).ToString() : string.Empty));

                    cb = (uint)buf.Length;
                    rc = RegGetValueW(HKEY_CURRENT_USER, settingsSubKey, "ProxyServer", RRF_RT_ANY, out valType, buf, ref cb);
                    string psStr = (rc == 0 && cb >= 2) ? Encoding.Unicode.GetString(buf, 0, (int)cb).TrimEnd('\0') : string.Empty;
                    lines.Add("reg:GetValueW:ProxyServer=" + rc + ":" + psStr);

                    cb = (uint)buf.Length;
                    rc = RegGetValueW(HKEY_CURRENT_USER, settingsSubKey, "AutoConfigURL", RRF_RT_ANY, out valType, buf, ref cb);
                    lines.Add("reg:GetValueW:AutoConfigURL=" + rc + ":" + (rc == 0 ? "FOUND" : string.Empty));

                    IntPtr hSettings;
                    rc = RegOpenKeyExW(HKEY_CURRENT_USER, settingsSubKey, 0, KEY_READ, out hSettings);
                    if (rc == 0)
                    {
                        cb = (uint)buf.Length;
                        int qW = RegQueryValueExW(hSettings, "ProxyEnable", IntPtr.Zero, out valType, buf, ref cb);
                        lines.Add("reg:QueryExW:ProxyEnable=" + qW + ":" + (qW == 0 ? BitConverter.ToUInt32(buf, 0).ToString() : string.Empty));

                        cb = (uint)buf.Length;
                        int qA = RegQueryValueExA(hSettings, "ProxyServer", IntPtr.Zero, out valType, buf, ref cb);
                        lines.Add("reg:QueryExA:ProxyServer=" + qA + ":" + (qA == 0 ? "FOUND" : string.Empty));
                        RegCloseKey(hSettings);
                    }
                    else
                    {
                        lines.Add("reg:QueryExW:ProxyEnable=" + rc + ":");
                        lines.Add("reg:QueryExA:ProxyServer=" + rc + ":");
                    }

                    IntPtr hConn;
                    rc = RegOpenKeyExW(HKEY_CURRENT_USER, settingsSubKey + "\\Connections", 0, KEY_READ, out hConn);
                    if (rc == 0)
                    {
                        cb = (uint)buf.Length;
                        int qConn = RegQueryValueExW(hConn, "DefaultConnectionSettings", IntPtr.Zero, out valType, buf, ref cb);
                        uint connFlags = (qConn == 0 && cb >= 12) ? BitConverter.ToUInt32(buf, 8) : 0;
                        lines.Add("reg:DefaultConnFlags=" + qConn + ":" + connFlags);
                        RegCloseKey(hConn);
                    }
                    else
                    {
                        lines.Add("reg:DefaultConnFlags=" + rc + ":");
                    }

                    WINHTTP_CURRENT_USER_IE_PROXY_CONFIG ieCfg = new WINHTTP_CURRENT_USER_IE_PROXY_CONFIG();
                    bool ieOk = WinHttpGetIEProxyConfigForCurrentUser(ref ieCfg);
                    string ieProxy = ieCfg.lpszProxy != IntPtr.Zero ? Marshal.PtrToStringUni(ieCfg.lpszProxy) : string.Empty;
                    string iePac = ieCfg.lpszAutoConfigUrl != IntPtr.Zero ? Marshal.PtrToStringUni(ieCfg.lpszAutoConfigUrl) : string.Empty;
                    lines.Add("winhttp:IE=" + ieOk + ":" + ieCfg.fAutoDetect + ":" + ieProxy + ":" + iePac);

                    IntPtr hWinHttp = WinHttpOpen("AppProxyProbe/1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, null, null, 0);
                    WINHTTP_AUTOPROXY_OPTIONS autoOpts = new WINHTTP_AUTOPROXY_OPTIONS();
                    autoOpts.dwFlags = WINHTTP_AUTOPROXY_CONFIG_URL;
                    autoOpts.lpszAutoConfigUrl = "http://127.0.0.1:10809/pac";
                    WINHTTP_PROXY_INFO whInfo;
                    bool whProxyOk = WinHttpGetProxyForUrl(hWinHttp, "https://example.com", ref autoOpts, out whInfo);
                    string whProxyStr = whInfo.lpszProxy != IntPtr.Zero ? Marshal.PtrToStringUni(whInfo.lpszProxy) : string.Empty;
                    lines.Add("winhttp:GetProxyForUrl=" + whProxyOk + ":" + whInfo.dwAccessType + ":" + whProxyStr);
                    if (hWinHttp != IntPtr.Zero) WinHttpCloseHandle(hWinHttp);

                    uint infoSize = (uint)Marshal.SizeOf(typeof(INTERNET_PROXY_INFO));
                    IntPtr pGlobalInfo = Marshal.AllocHGlobal((int)infoSize);
                    bool inetGlobalOk = InternetQueryOptionW(IntPtr.Zero, INTERNET_OPTION_PROXY, pGlobalInfo, ref infoSize);
                    INTERNET_PROXY_INFO gInfo = (INTERNET_PROXY_INFO)Marshal.PtrToStructure(pGlobalInfo, typeof(INTERNET_PROXY_INFO));
                    string gProxy = gInfo.lpszProxy != IntPtr.Zero ? Marshal.PtrToStringUni(gInfo.lpszProxy) : string.Empty;
                    lines.Add("wininet:GlobalQuery=" + inetGlobalOk + ":" + gInfo.dwAccessType + ":" + gProxy);
                    Marshal.FreeHGlobal(pGlobalInfo);

                    IntPtr hInet = InternetOpenW("AppProxyProbe/1.0", INTERNET_OPEN_TYPE_PRECONFIG, null, null, 0);
                    infoSize = (uint)Marshal.SizeOf(typeof(INTERNET_PROXY_INFO));
                    IntPtr pSessInfo = Marshal.AllocHGlobal((int)infoSize);
                    bool inetSessOk = InternetQueryOptionW(hInet, INTERNET_OPTION_PROXY, pSessInfo, ref infoSize);
                    INTERNET_PROXY_INFO sInfo = (INTERNET_PROXY_INFO)Marshal.PtrToStructure(pSessInfo, typeof(INTERNET_PROXY_INFO));
                    string sProxy = sInfo.lpszProxy != IntPtr.Zero ? Marshal.PtrToStringUni(sInfo.lpszProxy) : string.Empty;
                    lines.Add("wininet:SessionQuery=" + inetSessOk + ":" + sInfo.dwAccessType + ":" + sProxy);
                    Marshal.FreeHGlobal(pSessInfo);
                    if (hInet != IntPtr.Zero) InternetCloseHandle(hInet);

                    int optSize = Marshal.SizeOf(typeof(INTERNET_PER_CONN_OPTIONW));
                    IntPtr pOpts = Marshal.AllocHGlobal(optSize * 2);
                    INTERNET_PER_CONN_OPTIONW opt0 = new INTERNET_PER_CONN_OPTIONW();
                    opt0.dwOption = INTERNET_PER_CONN_FLAGS;
                    INTERNET_PER_CONN_OPTIONW opt1 = new INTERNET_PER_CONN_OPTIONW();
                    opt1.dwOption = INTERNET_PER_CONN_PROXY_SERVER;
                    Marshal.StructureToPtr(opt0, pOpts, false);
                    Marshal.StructureToPtr(opt1, new IntPtr(pOpts.ToInt64() + optSize), false);

                    INTERNET_PER_CONN_OPTION_LISTW list = new INTERNET_PER_CONN_OPTION_LISTW();
                    uint listSize = (uint)Marshal.SizeOf(typeof(INTERNET_PER_CONN_OPTION_LISTW));
                    list.dwSize = listSize;
                    list.pszConnection = IntPtr.Zero;
                    list.dwOptionCount = 2;
                    list.dwOptionError = 0;
                    list.pOptions = pOpts;

                    IntPtr pList = Marshal.AllocHGlobal((int)listSize);
                    Marshal.StructureToPtr(list, pList, false);
                    bool perConnOk = InternetQueryOptionW(IntPtr.Zero, INTERNET_OPTION_PER_CONNECTION_OPTION, pList, ref listSize);
                    INTERNET_PER_CONN_OPTIONW res0 = (INTERNET_PER_CONN_OPTIONW)Marshal.PtrToStructure(pOpts, typeof(INTERNET_PER_CONN_OPTIONW));
                    INTERNET_PER_CONN_OPTIONW res1 = (INTERNET_PER_CONN_OPTIONW)Marshal.PtrToStructure(new IntPtr(pOpts.ToInt64() + optSize), typeof(INTERNET_PER_CONN_OPTIONW));
                    string perProxy = res1.Value.pszValue != IntPtr.Zero ? Marshal.PtrToStringUni(res1.Value.pszValue) : string.Empty;
                    lines.Add("wininet:PerConn=" + perConnOk + ":" + res0.Value.dwValue + ":" + perProxy);
                    Marshal.FreeHGlobal(pList);
                    Marshal.FreeHGlobal(pOpts);

                    File.WriteAllLines(outPath, lines.ToArray(), Encoding.UTF8);
                    return 0;
                }
            }
        }
        """;
}

using System.IO;
using AppProxy.UI.Interop;
using AppProxy.UI.Models;
using AppProxy.UI.Services;
using Xunit;

namespace AppProxy.Tests;

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
        Assert.NotNull(decoded.Proxy);
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
        Assert.Contains(@"--user-data-dir=""D:\Apps\AppProxy\profiles\Microsoft Edge""", effective);

        // Must not duplicate --user-data-dir if user already supplied one
        req.Arguments = @"--user-data-dir=""D:\CustomEdgeProfile""";
        Assert.Equal(@"--user-data-dir=""D:\CustomEdgeProfile""", req.BuildEffectiveArguments(@"D:\Apps\AppProxy"));
    }
}

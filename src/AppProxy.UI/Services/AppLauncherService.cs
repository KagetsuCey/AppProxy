using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Text;
using AppProxy.UI.Interop;
using AppProxy.UI.Models;

namespace AppProxy.UI.Services;

public sealed class AppLauncherService : IDisposable
{
    private readonly CancellationTokenSource _cts = new();
    private readonly ConcurrentDictionary<uint, BridgeStatusDto> _activeBridges = new();
    private readonly ConcurrentDictionary<uint, byte> _attachedPipes = new();
    private bool _disposed;

    public event Action<ProcessEventRecord>? ProcessEventReceived;
    public event Action<BridgeConnectionDto>? ConnectionUpserted;
    public event Action<BridgeStatusDto>? BridgeStatusUpdated;
    public event Action<uint>? BridgeDisconnected;

    public IReadOnlyCollection<BridgeStatusDto> ActiveBridges => _activeBridges.Values.ToArray();

    public AppLauncherService()
    {
        StartBridgeDiscoveryLoop();
    }

    public async Task<(bool Ok, uint Pid, string Message)> LaunchAppAsync(AppProfile app, ProxyProfile? proxy)
    {
        if (string.IsNullOrWhiteSpace(app.ExePath) || !File.Exists(app.ExePath))
        {
            return (false, 0, $"Executable not found: {app.ExePath}");
        }

        string baseDir = AppContext.BaseDirectory;
        string bridgeExePath = Path.Combine(baseDir, "AppProxy.Bridge.exe");
        if (!File.Exists(bridgeExePath))
        {
            return (false, 0, $"Background bridge executable missing at {bridgeExePath}. Please build AppProxy.Bridge.");
        }

        var request = new BridgeLaunchRequest
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
            IsolateProfileDir = app.GetEffectiveIsolateProfileDir(),
            Proxy = proxy is not null ? BridgeProxyConfig.FromProfile(proxy) : null
        };

        string payloadB64 = BridgeIpcCodec.EncodeLaunchRequestBase64(request);
        uint spawnedBridgePid;
        string handshakeLine;
        try
        {
            (spawnedBridgePid, handshakeLine) = await DetachedProcessLauncher.StartDetachedAndReadFirstLineAsync(
                bridgeExePath,
                $"--launch-b64 {payloadB64}",
                baseDir,
                TimeSpan.FromSeconds(12));
        }
        catch (Exception ex)
        {
            return (false, 0, $"Failed to start background bridge process: {ex.Message}");
        }

        BridgeHandshakeResponse? handshake = null;
        try
        {
            if (!string.IsNullOrWhiteSpace(handshakeLine))
            {
                handshake = BridgeIpcCodec.DeserializeLine<BridgeHandshakeResponse>(handshakeLine.Trim());
            }
        }
        catch
        {
        }

        uint effectiveBridgePid = handshake?.BridgePid is > 0 ? handshake.BridgePid : spawnedBridgePid;
        if (handshake is null || !handshake.Ok)
        {
            string errMsg = handshake?.Error ?? (string.IsNullOrWhiteSpace(handshakeLine)
                ? "Background bridge exited without handshake response."
                : handshakeLine.Trim());
            return (false, 0, errMsg);
        }

        var initialStatus = new BridgeStatusDto
        {
            BridgePid = effectiveBridgePid,
            AppName = request.AppName,
            TargetPid = handshake.TargetPid,
            PortV4 = handshake.PortV4,
            PortV6 = handshake.PortV6,
            ActiveConnections = 0,
            Alive = true
        };
        _activeBridges[effectiveBridgePid] = initialStatus;
        BridgeStatusUpdated?.Invoke(initialStatus);

        EnsureAttachedToBridgePipe(effectiveBridgePid);

        string statusOut = !string.IsNullOrWhiteSpace(handshake.Warning)
            ? $"Launched PID {handshake.TargetPid} ({handshake.Arch}) via Bridge #{effectiveBridgePid} - {handshake.Warning}"
            : $"Launched PID {handshake.TargetPid} ({handshake.Arch}) via Bridge #{effectiveBridgePid}";
        return (true, handshake.TargetPid, statusOut);
    }

    private void StartBridgeDiscoveryLoop()
    {
        _ = Task.Run(async () =>
        {
            while (!_cts.IsCancellationRequested)
            {
                try
                {
                    DiscoverRunningBridges();
                    await Task.Delay(2000, _cts.Token);
                }
                catch (OperationCanceledException)
                {
                    break;
                }
                catch
                {
                }
            }
        });
    }

    private void DiscoverRunningBridges()
    {
        var livePids = new HashSet<uint>();
        try
        {
            foreach (var proc in Process.GetProcessesByName("AppProxy.Bridge"))
            {
                using (proc)
                {
                    try
                    {
                        if (!proc.HasExited)
                        {
                            uint pid = (uint)proc.Id;
                            livePids.Add(pid);
                            EnsureAttachedToBridgePipe(pid);
                        }
                    }
                    catch
                    {
                    }
                }
            }
        }
        catch
        {
        }

        foreach (uint trackedPid in _activeBridges.Keys)
        {
            if (!livePids.Contains(trackedPid) && _activeBridges.TryRemove(trackedPid, out _))
            {
                BridgeDisconnected?.Invoke(trackedPid);
            }
        }
    }

    private void EnsureAttachedToBridgePipe(uint bridgePid)
    {
        if (bridgePid == 0 || !_attachedPipes.TryAdd(bridgePid, 1))
        {
            return;
        }

        _ = Task.Run(async () =>
        {
            try
            {
                await ConnectAndReadBridgePipeAsync(bridgePid, _cts.Token);
            }
            finally
            {
                _attachedPipes.TryRemove(bridgePid, out _);
                if (!IsProcessAlive(bridgePid) && _activeBridges.TryRemove(bridgePid, out _))
                {
                    BridgeDisconnected?.Invoke(bridgePid);
                }
            }
        });
    }

    private async Task ConnectAndReadBridgePipeAsync(uint bridgePid, CancellationToken ct)
    {
        string pipeName = BridgeIpcCodec.GetUiPipeName(bridgePid);
        using var client = new NamedPipeClientStream(
            ".",
            pipeName,
            PipeDirection.In,
            PipeOptions.Asynchronous);

        try
        {
            await client.ConnectAsync(2000, ct);
        }
        catch
        {
            return;
        }

        using var reader = new StreamReader(client, Encoding.UTF8);
        while (!ct.IsCancellationRequested && client.IsConnected)
        {
            string? line;
            try
            {
                line = await reader.ReadLineAsync(ct);
            }
            catch
            {
                break;
            }

            if (line is null) break;
            if (string.IsNullOrWhiteSpace(line)) continue;

            try
            {
                var env = BridgeIpcCodec.DeserializeLine<UiBridgeEnvelope>(line);
                if (env is null) continue;

                switch (env.Type)
                {
                    case "status" when env.Status is not null:
                        if (env.Status.Alive)
                        {
                            _activeBridges[env.Status.BridgePid] = env.Status;
                            BridgeStatusUpdated?.Invoke(env.Status);
                        }
                        else if (_activeBridges.TryRemove(env.Status.BridgePid, out _))
                        {
                            BridgeDisconnected?.Invoke(env.Status.BridgePid);
                        }
                        break;

                    case "event" when env.Event is not null:
                        ProcessEventReceived?.Invoke(env.Event.ToRecord());
                        break;

                    case "conn" when env.Connection is not null:
                        ConnectionUpserted?.Invoke(env.Connection);
                        break;
                }
            }
            catch
            {
            }
        }
    }

    private static bool IsProcessAlive(uint pid)
    {
        try
        {
            using var p = Process.GetProcessById((int)pid);
            return !p.HasExited;
        }
        catch
        {
            return false;
        }
    }

    public void Dispose()
    {
        // Only detach UI pipe subscriptions; never terminate running AppProxy.Bridge.exe processes.
        if (_disposed) return;
        _disposed = true;
        _cts.Cancel();
        _cts.Dispose();
    }
}

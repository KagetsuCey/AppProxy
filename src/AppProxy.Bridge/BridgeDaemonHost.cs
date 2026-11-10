using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.IO.Pipes;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using AppProxy.UI.Interop;
using AppProxy.UI.Models;
using AppProxy.UI.Services;

namespace AppProxy.Bridge;

internal sealed class BridgeDaemonHost : IDisposable
{
    private sealed class InjectorOutput
    {
        [JsonPropertyName("ok")]
        public bool Ok { get; set; }

        [JsonPropertyName("pid")]
        public uint Pid { get; set; }

        [JsonPropertyName("arch")]
        public string? Arch { get; set; }

        [JsonPropertyName("error")]
        public string? Error { get; set; }
    }

    private sealed class PipeLogPayload
    {
        [JsonPropertyName("ts")]
        public long Ts { get; set; }

        [JsonPropertyName("sessionId")]
        public uint SessionId { get; set; }

        [JsonPropertyName("pid")]
        public uint Pid { get; set; }

        [JsonPropertyName("parentPid")]
        public uint ParentPid { get; set; }

        [JsonPropertyName("arch")]
        public string? Arch { get; set; }

        [JsonPropertyName("process")]
        public string? Process { get; set; }

        [JsonPropertyName("event")]
        public string? Event { get; set; }

        [JsonPropertyName("message")]
        public string? Message { get; set; }
    }

    private sealed class UiSubscriber : IDisposable
    {
        private readonly NamedPipeServerStream _pipe;
        private readonly StreamWriter _writer;
        private readonly SemaphoreSlim _writeLock = new(1, 1);
        private int _disposed;

        public UiSubscriber(NamedPipeServerStream pipe)
        {
            _pipe = pipe;
            _writer = new StreamWriter(pipe, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false))
            {
                AutoFlush = true
            };
        }

        public async Task<bool> TrySendLineAsync(string line, CancellationToken ct)
        {
            if (Volatile.Read(ref _disposed) != 0 || !_pipe.IsConnected)
            {
                return false;
            }

            await _writeLock.WaitAsync(ct);
            try
            {
                if (Volatile.Read(ref _disposed) != 0 || !_pipe.IsConnected)
                {
                    return false;
                }
                await _writer.WriteLineAsync(line.AsMemory(), ct);
                return true;
            }
            catch
            {
                return false;
            }
            finally
            {
                _writeLock.Release();
            }
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0) return;
            try { _writer.Dispose(); } catch { }
            try { _pipe.Dispose(); } catch { }
            _writeLock.Dispose();
        }
    }

    private readonly BridgeLaunchRequest _request;
    private readonly uint _bridgePid;
    private readonly SharedMemoryService _shm;
    private readonly LocalProxyBridge _bridge;
    private readonly JobObjectTracker _jobTracker;
    private readonly CancellationTokenSource _cts = new();

    private readonly ConcurrentQueue<BridgeEventDto> _recentEvents = new();
    private readonly ConcurrentDictionary<long, ConnectionRecord> _trackedConnections = new();
    private readonly ConcurrentDictionary<long, (string Status, long Up, long Down)> _lastBroadcastConnState = new();
    private readonly ConcurrentDictionary<int, UiSubscriber> _uiSubscribers = new();
    private int _nextSubscriberId;
    private uint _targetPid;
    private string _appDisplayName = string.Empty;
    private bool _disposed;

    public BridgeDaemonHost(BridgeLaunchRequest request)
    {
        _request = request;
        _bridgePid = (uint)Environment.ProcessId;
        _shm = new SharedMemoryService(_bridgePid);
        _bridge = new LocalProxyBridge(_shm);
        _jobTracker = new JobObjectTracker();

        _bridge.ConnectionCreated += OnBridgeConnectionCreated;
        _bridge.ConnectionUpdated += OnBridgeConnectionUpdated;
    }

    public async Task<int> RunAsync(Action<BridgeHandshakeResponse> sendHandshake)
    {
        if (!File.Exists(_request.ExePath))
        {
            sendHandshake(new BridgeHandshakeResponse
            {
                Ok = false,
                BridgePid = _bridgePid,
                Error = $"Executable not found: {_request.ExePath}"
            });
            return 1;
        }

        string baseDir = AppContext.BaseDirectory;
        string nativeDir = Path.Combine(baseDir, "native");
        string detectedArch = DetectPeArchitecture(_request.ExePath);
        string injectorName = detectedArch == "x86" ? "AppProxy.Injector.x86.exe" : "AppProxy.Injector.x64.exe";
        string injectorPath = Path.Combine(nativeDir, injectorName);

        if (!File.Exists(injectorPath))
        {
            string fallback = Path.Combine(nativeDir, "AppProxy.Injector.x64.exe");
            if (File.Exists(fallback))
            {
                injectorPath = fallback;
            }
            else
            {
                sendHandshake(new BridgeHandshakeResponse
                {
                    Ok = false,
                    BridgePid = _bridgePid,
                    Error = $"Native injector missing at {injectorPath}. Please build native x86/x64 projects."
                });
                return 1;
            }
        }

        const uint sessionId = 1;
        ProxyProfile? proxyProfile = _request.Proxy?.ToProfile();

        NativeSessionFlags flags = NativeSessionFlags.None;
        if (proxyProfile is null) flags |= NativeSessionFlags.DirectMode;
        if (_request.RemoteDns) flags |= NativeSessionFlags.RemoteDns;
        if (_request.BypassLan) flags |= NativeSessionFlags.BypassLan;
        if (_request.InjectChildren) flags |= NativeSessionFlags.InjectChildren;

        _appDisplayName = string.IsNullOrWhiteSpace(_request.AppName)
            ? Path.GetFileName(_request.ExePath)
            : _request.AppName;

        _shm.RegisterSession(sessionId, flags);
        _bridge.RegisterSession(new SessionContext
        {
            SessionId = sessionId,
            AppName = Path.GetFileName(_request.ExePath),
            Proxy = proxyProfile,
            BypassLan = _request.BypassLan,
            RemoteDns = _request.RemoteDns
        });

        StartNativeLogPipeServer();
        StartUiTelemetryPipeServer();
        _ = TelemetryTickerLoopAsync(_cts.Token);

        string exeB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(_request.ExePath));
        string argsB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(_request.Arguments ?? string.Empty));
        string workDir = string.IsNullOrWhiteSpace(_request.WorkingDirectory)
            ? (Path.GetDirectoryName(_request.ExePath) ?? string.Empty)
            : _request.WorkingDirectory;
        string workDirB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(workDir));

        var injectorArgs = new StringBuilder($"--launch --exe-b64 {exeB64}");
        if (!string.IsNullOrEmpty(argsB64))
        {
            injectorArgs.Append($" --args-b64 {argsB64}");
        }
        if (!string.IsNullOrEmpty(workDirB64))
        {
            injectorArgs.Append($" --workdir-b64 {workDirB64}");
        }

        var extraEnv = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["APPPROXY_BRIDGE_PID"] = _bridgePid.ToString(),
            ["APPPROXY_SESSION_ID"] = sessionId.ToString(),
            ["APPPROXY_FLAGS"] = ((uint)flags).ToString(),
            ["APPPROXY_SELF_DIR"] = nativeDir
        };

        string exeNameNoExt = Path.GetFileNameWithoutExtension(_request.ExePath);
        int existingInstances = CountRunningInstances(_request.ExePath, exeNameNoExt);

        int exitCode;
        string stdout;
        string stderr;
        try
        {
            (exitCode, stdout, stderr) = await _jobTracker.RunInJobAndCaptureAsync(
                injectorPath,
                injectorArgs.ToString(),
                nativeDir,
                extraEnv,
                _cts.Token);
        }
        catch (Exception ex)
        {
            sendHandshake(new BridgeHandshakeResponse
            {
                Ok = false,
                BridgePid = _bridgePid,
                Error = $"Failed to launch native injector: {ex.Message}"
            });
            return 1;
        }

        InjectorOutput? result = null;
        try
        {
            result = JsonSerializer.Deserialize<InjectorOutput>(stdout.Trim());
        }
        catch
        {
        }

        if (exitCode != 0 || result is null || !result.Ok)
        {
            string errMsg = result?.Error ?? (string.IsNullOrWhiteSpace(stderr) ? stdout : stderr);
            sendHandshake(new BridgeHandshakeResponse
            {
                Ok = false,
                BridgePid = _bridgePid,
                Error = $"Launch injection failed: {errMsg.Trim()}"
            });
            return 1;
        }

        _targetPid = result.Pid;
        _jobTracker.TrackPidFallback(_targetPid);

        string launchMsg = proxyProfile is not null
            ? $"Launched via {proxyProfile.Name} ({proxyProfile.ProtocolDisplay} {proxyProfile.EndpointDisplay}) [Bridge #{_bridgePid}]"
            : $"Launched in Direct mode [Bridge #{_bridgePid}]";
        if (existingInstances > 0)
        {
            launchMsg += $" [Warning: {existingInstances} existing instance(s) detected; single-instance apps may hand off to the un-injected process]";
        }

        RecordAndBroadcastEvent(new ProcessEventRecord
        {
            Timestamp = DateTime.Now,
            BridgePid = _bridgePid,
            SessionId = sessionId,
            Pid = _targetPid,
            ParentPid = _bridgePid,
            Arch = result.Arch ?? detectedArch,
            ProcessName = Path.GetFileName(_request.ExePath),
            EventType = "Launched",
            Message = launchMsg
        });

        _ = MonitorEarlySingleInstanceExitAsync(_targetPid, sessionId, Path.GetFileName(_request.ExePath), existingInstances > 0);

        sendHandshake(new BridgeHandshakeResponse
        {
            Ok = true,
            BridgePid = _bridgePid,
            PortV4 = _bridge.PortV4,
            PortV6 = _bridge.PortV6,
            TargetPid = _targetPid,
            Arch = result.Arch ?? detectedArch,
            Warning = existingInstances > 0
                ? $"Note: {existingInstances} existing instance(s) detected; close background instances if traffic is not captured"
                : null
        });

        await BroadcastStatusAsync(alive: true);

        // Block until the entire target process tree (root + all children in the Job Object) exits
        await _jobTracker.AllProcessesExited;

        RecordAndBroadcastEvent(new ProcessEventRecord
        {
            Timestamp = DateTime.Now,
            BridgePid = _bridgePid,
            SessionId = sessionId,
            Pid = _targetPid,
            ParentPid = _bridgePid,
            Arch = result.Arch ?? detectedArch,
            ProcessName = Path.GetFileName(_request.ExePath),
            EventType = "BridgeExited",
            Message = $"Target process tree exited; releasing background bridge #{_bridgePid}"
        });

        await BroadcastStatusAsync(alive: false);
        await Task.Delay(250);
        return 0;
    }

    private void OnBridgeConnectionCreated(ConnectionRecord record)
    {
        _trackedConnections[record.Id] = record;
        while (_trackedConnections.Count > 1500)
        {
            long oldest = _trackedConnections.Keys.Min();
            _trackedConnections.TryRemove(oldest, out _);
            _lastBroadcastConnState.TryRemove(oldest, out _);
        }
        _ = BroadcastConnectionAsync(record);
    }

    private void OnBridgeConnectionUpdated(ConnectionRecord record)
    {
        _trackedConnections[record.Id] = record;
        _ = BroadcastConnectionAsync(record);
    }

    private async Task TelemetryTickerLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(250, ct);
                if (_uiSubscribers.IsEmpty) continue;

                foreach (var kv in _trackedConnections)
                {
                    var rec = kv.Value;
                    string status = rec.RawStatus;
                    long up = rec.RawBytesUp;
                    long down = rec.RawBytesDown;

                    if (_lastBroadcastConnState.TryGetValue(rec.Id, out var prev) &&
                        prev.Status == status &&
                        prev.Up == up &&
                        prev.Down == down)
                    {
                        continue;
                    }

                    await BroadcastConnectionAsync(rec);
                }

                await BroadcastStatusAsync(alive: true);
            }
        }
        catch (OperationCanceledException)
        {
        }
    }

    private void RecordAndBroadcastEvent(ProcessEventRecord record)
    {
        var dto = BridgeEventDto.FromRecord(record);
        _recentEvents.Enqueue(dto);
        while (_recentEvents.Count > 500)
        {
            _recentEvents.TryDequeue(out _);
        }

        if (_uiSubscribers.IsEmpty) return;

        string line = BridgeIpcCodec.SerializeLine(new UiBridgeEnvelope
        {
            Type = "event",
            BridgePid = _bridgePid,
            Event = dto
        });
        _ = BroadcastLineToUiSubscribersAsync(line);
    }

    private Task BroadcastConnectionAsync(ConnectionRecord record)
    {
        _lastBroadcastConnState[record.Id] = (record.RawStatus, record.RawBytesUp, record.RawBytesDown);
        if (_uiSubscribers.IsEmpty) return Task.CompletedTask;

        string line = BridgeIpcCodec.SerializeLine(new UiBridgeEnvelope
        {
            Type = "conn",
            BridgePid = _bridgePid,
            Connection = BridgeConnectionDto.FromRecord(record)
        });
        return BroadcastLineToUiSubscribersAsync(line);
    }

    private Task BroadcastStatusAsync(bool alive)
    {
        if (_uiSubscribers.IsEmpty) return Task.CompletedTask;

        string line = BridgeIpcCodec.SerializeLine(new UiBridgeEnvelope
        {
            Type = "status",
            BridgePid = _bridgePid,
            Status = BuildStatusDto(alive)
        });
        return BroadcastLineToUiSubscribersAsync(line);
    }

    private BridgeStatusDto BuildStatusDto(bool alive) => new()
    {
        BridgePid = _bridgePid,
        AppName = _appDisplayName,
        TargetPid = _targetPid,
        PortV4 = _bridge.PortV4,
        PortV6 = _bridge.PortV6,
        ActiveConnections = alive ? _bridge.ActiveConnections : 0,
        Alive = alive
    };

    private async Task BroadcastLineToUiSubscribersAsync(string line)
    {
        foreach (var kv in _uiSubscribers)
        {
            bool ok = await kv.Value.TrySendLineAsync(line, CancellationToken.None);
            if (!ok && _uiSubscribers.TryRemove(kv.Key, out var removed))
            {
                removed.Dispose();
            }
        }
    }

    private void StartUiTelemetryPipeServer()
    {
        string pipeName = BridgeIpcCodec.GetUiPipeName(_bridgePid);
        _ = Task.Run(async () =>
        {
            while (!_cts.IsCancellationRequested)
            {
                NamedPipeServerStream? server = null;
                try
                {
                    server = new NamedPipeServerStream(
                        pipeName,
                        PipeDirection.Out,
                        NamedPipeServerStream.MaxAllowedServerInstances,
                        PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous);

                    await server.WaitForConnectionAsync(_cts.Token);
                    var sub = new UiSubscriber(server);
                    server = null;

                    int id = Interlocked.Increment(ref _nextSubscriberId);
                    _uiSubscribers[id] = sub;
                    _ = SendInitialSnapshotAsync(id, sub);
                }
                catch (OperationCanceledException)
                {
                    server?.Dispose();
                    break;
                }
                catch
                {
                    server?.Dispose();
                    await Task.Delay(100, _cts.Token);
                }
            }
        });
    }

    private async Task SendInitialSnapshotAsync(int subscriberId, UiSubscriber sub)
    {
        try
        {
            string statusLine = BridgeIpcCodec.SerializeLine(new UiBridgeEnvelope
            {
                Type = "status",
                BridgePid = _bridgePid,
                Status = BuildStatusDto(alive: true)
            });
            if (!await sub.TrySendLineAsync(statusLine, CancellationToken.None))
            {
                if (_uiSubscribers.TryRemove(subscriberId, out var rem)) rem.Dispose();
                return;
            }

            foreach (var ev in _recentEvents.ToArray())
            {
                string evLine = BridgeIpcCodec.SerializeLine(new UiBridgeEnvelope
                {
                    Type = "event",
                    BridgePid = _bridgePid,
                    Event = ev
                });
                if (!await sub.TrySendLineAsync(evLine, CancellationToken.None))
                {
                    if (_uiSubscribers.TryRemove(subscriberId, out var rem)) rem.Dispose();
                    return;
                }
            }

            foreach (var conn in _trackedConnections.Values.OrderBy(c => c.Id))
            {
                string connLine = BridgeIpcCodec.SerializeLine(new UiBridgeEnvelope
                {
                    Type = "conn",
                    BridgePid = _bridgePid,
                    Connection = BridgeConnectionDto.FromRecord(conn)
                });
                if (!await sub.TrySendLineAsync(connLine, CancellationToken.None))
                {
                    if (_uiSubscribers.TryRemove(subscriberId, out var rem)) rem.Dispose();
                    return;
                }
            }
        }
        catch
        {
            if (_uiSubscribers.TryRemove(subscriberId, out var rem)) rem.Dispose();
        }
    }

    private void StartNativeLogPipeServer()
    {
        string pipeName = $"AppProxy_Log_{_bridgePid}";
        _ = Task.Run(async () =>
        {
            while (!_cts.IsCancellationRequested)
            {
                NamedPipeServerStream? server = null;
                try
                {
                    server = new NamedPipeServerStream(
                        pipeName,
                        PipeDirection.In,
                        NamedPipeServerStream.MaxAllowedServerInstances,
                        PipeTransmissionMode.Byte,
                        PipeOptions.Asynchronous);

                    await server.WaitForConnectionAsync(_cts.Token);
                    var connectedPipe = server;
                    server = null;
                    _ = Task.Run(() => ReadNativeLogClientAsync(connectedPipe, _cts.Token), _cts.Token);
                }
                catch (OperationCanceledException)
                {
                    server?.Dispose();
                    break;
                }
                catch
                {
                    server?.Dispose();
                    await Task.Delay(100, _cts.Token);
                }
            }
        });
    }

    private async Task ReadNativeLogClientAsync(NamedPipeServerStream pipe, CancellationToken ct)
    {
        await using (pipe)
        using (var reader = new StreamReader(pipe, Encoding.UTF8))
        {
            while (!ct.IsCancellationRequested && pipe.IsConnected)
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
                    var payload = JsonSerializer.Deserialize<PipeLogPayload>(line);
                    if (payload is not null)
                    {
                        TryTrackChildPidFromMessage(payload.Event, payload.Message);

                        var record = new ProcessEventRecord
                        {
                            Timestamp = payload.Ts > 0
                                ? DateTimeOffset.FromUnixTimeMilliseconds(payload.Ts).LocalDateTime
                                : DateTime.Now,
                            BridgePid = _bridgePid,
                            SessionId = payload.SessionId,
                            Pid = payload.Pid,
                            ParentPid = payload.ParentPid,
                            Arch = payload.Arch ?? string.Empty,
                            ProcessName = payload.Process ?? string.Empty,
                            EventType = payload.Event ?? "Log",
                            Message = payload.Message ?? string.Empty
                        };
                        RecordAndBroadcastEvent(record);
                    }
                }
                catch
                {
                }
            }
        }
    }

    private void TryTrackChildPidFromMessage(string? eventType, string? message)
    {
        if (!string.Equals(eventType, "ChildSpawned", StringComparison.OrdinalIgnoreCase) ||
            string.IsNullOrWhiteSpace(message))
        {
            return;
        }

        const string prefix = "Child PID ";
        if (message.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            int start = prefix.Length;
            int end = start;
            while (end < message.Length && char.IsDigit(message[end]))
            {
                end++;
            }
            if (end > start && uint.TryParse(message.AsSpan(start, end - start), out uint childPid) && childPid != 0)
            {
                _jobTracker.TrackPidFallback(childPid);
            }
        }
    }

    private async Task MonitorEarlySingleInstanceExitAsync(uint pid, uint sessionId, string processName, bool hadExisting)
    {
        try
        {
            using var target = Process.GetProcessById((int)pid);
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            await target.WaitForExitAsync(cts.Token);

            string hint = hadExisting
                ? $"PID {pid} exited immediately (ExitCode={target.ExitCode}) because an existing {processName} instance took over. Close all existing {processName} windows/tray processes first."
                : $"PID {pid} exited shortly after launch (ExitCode={target.ExitCode}).";

            RecordAndBroadcastEvent(new ProcessEventRecord
            {
                Timestamp = DateTime.Now,
                BridgePid = _bridgePid,
                SessionId = sessionId,
                Pid = pid,
                ParentPid = _bridgePid,
                Arch = string.Empty,
                ProcessName = processName,
                EventType = "Warning",
                Message = hint
            });
        }
        catch
        {
        }
    }

    private static int CountRunningInstances(string fullExePath, string processNameNoExt)
    {
        int count = 0;
        try
        {
            foreach (var p in Process.GetProcessesByName(processNameNoExt))
            {
                using (p)
                {
                    try
                    {
                        string? runningPath = p.MainModule?.FileName;
                        if (string.IsNullOrEmpty(runningPath) ||
                            string.Equals(runningPath, fullExePath, StringComparison.OrdinalIgnoreCase))
                        {
                            count++;
                        }
                    }
                    catch
                    {
                        count++;
                    }
                }
            }
        }
        catch
        {
        }
        return count;
    }

    private static string DetectPeArchitecture(string exePath)
    {
        try
        {
            using var fs = new FileStream(exePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var br = new BinaryReader(fs);
            if (fs.Length < 64 || br.ReadUInt16() != 0x5A4D) return "x64";

            fs.Seek(0x3C, SeekOrigin.Begin);
            int peOffset = br.ReadInt32();
            if (peOffset <= 0 || peOffset + 24 > fs.Length) return "x64";

            fs.Seek(peOffset, SeekOrigin.Begin);
            if (br.ReadUInt32() != 0x00004550) return "x64";

            ushort machine = br.ReadUInt16();
            if (machine == 0x8664 || machine == 0xAA64) return "x64";
            if (machine != 0x014C) return "x64";

            ushort numberOfSections = br.ReadUInt16();
            fs.Seek(12, SeekOrigin.Current);
            ushort sizeOfOptionalHeader = br.ReadUInt16();
            br.ReadUInt16();

            long optionalStart = fs.Position;
            if (sizeOfOptionalHeader >= 216 && optionalStart + sizeOfOptionalHeader <= fs.Length)
            {
                if (br.ReadUInt16() == 0x010B)
                {
                    fs.Seek(optionalStart + 92, SeekOrigin.Begin);
                    if (br.ReadUInt32() > 14)
                    {
                        fs.Seek(optionalStart + 96 + (14 * 8), SeekOrigin.Begin);
                        uint clrRva = br.ReadUInt32();
                        uint clrSize = br.ReadUInt32();
                        if (clrRva != 0 && clrSize >= 72)
                        {
                            long sectionsStart = optionalStart + sizeOfOptionalHeader;
                            for (int i = 0; i < numberOfSections; i++)
                            {
                                long secOffset = sectionsStart + (i * 40L);
                                if (secOffset + 40 > fs.Length) break;
                                fs.Seek(secOffset + 8, SeekOrigin.Begin);
                                uint virtualSize = br.ReadUInt32();
                                uint virtualAddr = br.ReadUInt32();
                                uint rawSize = br.ReadUInt32();
                                uint rawPtr = br.ReadUInt32();
                                uint span = Math.Max(virtualSize, rawSize);
                                if (clrRva >= virtualAddr && clrRva < virtualAddr + span)
                                {
                                    long clrFileOffset = rawPtr + (clrRva - virtualAddr);
                                    if (clrFileOffset > 0 && clrFileOffset + 20 <= fs.Length)
                                    {
                                        fs.Seek(clrFileOffset + 16, SeekOrigin.Begin);
                                        uint corFlags = br.ReadUInt32();
                                        if ((corFlags & 0x00000002u) == 0 && Environment.Is64BitOperatingSystem)
                                        {
                                            return "x64";
                                        }
                                    }
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            return "x86";
        }
        catch
        {
            return "x64";
        }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cts.Cancel();

        foreach (var kv in _uiSubscribers)
        {
            if (_uiSubscribers.TryRemove(kv.Key, out var sub))
            {
                sub.Dispose();
            }
        }

        _bridge.Dispose();
        _shm.Dispose();
        _jobTracker.Dispose();
        _cts.Dispose();
    }
}

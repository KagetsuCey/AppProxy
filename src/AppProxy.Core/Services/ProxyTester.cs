using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using AppProxy.Core.Models;

namespace AppProxy.Core.Services;

public static class ProxyTester
{
    public static async Task TestProxyAsync(
        ProxyProfile proxy,
        string probeHost = "www.gstatic.com",
        int probePort = 80,
        CancellationToken ct = default,
        bool bypassGlobalTun = true,
        string? preferredOutboundInterface = null,
        string? xrayCorePath = null,
        ProxyProfile? resolvedTransportOverride = null)
    {
        proxy.IsTesting = true;
        proxy.LastLatencyMs = null;
        proxy.LastTestStatus = "Testing...";

        XraySidecarSession? sidecar = null;
        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(10));

            ProxyProfile transportProxy = proxy;
            bool effectiveBypass = bypassGlobalTun;

            if (proxy.RequiresXrayCore)
            {
                if (resolvedTransportOverride is not null)
                {
                    transportProxy = resolvedTransportOverride;
                }
                else
                {
                    string? xrayExe = XrayCoreManager.ResolveXrayPath(xrayCorePath);
                    if (xrayExe is null)
                    {
                        proxy.LastTestStatus = "Error: 未配置 Xray-core 内核";
                        return;
                    }

                    sidecar = await XraySidecarSession.StartSingleAsync(
                        xrayExe,
                        proxy,
                        bypassGlobalTun,
                        preferredOutboundInterface,
                        timeoutCts.Token);
                    transportProxy = sidecar.PrimaryLocalSocksProfile;
                }
                effectiveBypass = false;
            }

            bool requireEndToEndProbe =
                proxy.RequiresXrayCore ||
                resolvedTransportOverride is not null ||
                IsLoopbackHost(transportProxy.Host);

            var sw = Stopwatch.StartNew();
            using TcpClient tcp = await OutboundSocketConnector.ConnectAsync(
                transportProxy.Host,
                transportProxy.Port,
                null,
                effectiveBypass,
                preferredOutboundInterface,
                timeoutCts.Token);

            Stream stream = tcp.GetStream();
            if (transportProxy.Protocol == ProxyProtocol.Socks5)
            {
                await Socks5TunnelClient.ConnectAsync(stream, transportProxy, probeHost, probePort, null, timeoutCts.Token);
            }
            else
            {
                stream = await HttpConnectTunnelClient.ConnectAsync(stream, transportProxy, probeHost, probePort, timeoutCts.Token);
            }

            if (requireEndToEndProbe)
            {
                await SendEndToEndProbeAsync(stream, probeHost, probePort, timeoutCts.Token);
            }
            sw.Stop();

            if (stream != tcp.GetStream())
            {
                await stream.DisposeAsync();
            }

            proxy.LastLatencyMs = Math.Max(1, (int)sw.ElapsedMilliseconds);
            proxy.LastTestStatus = "OK";
        }
        catch (OperationCanceledException)
        {
            proxy.LastLatencyMs = null;
            proxy.LastTestStatus = "Timeout";
        }
        catch (Exception ex)
        {
            proxy.LastLatencyMs = null;
            proxy.LastTestStatus = $"Error: {ex.Message}";
        }
        finally
        {
            sidecar?.Dispose();
            proxy.IsTesting = false;
        }
    }

    private static async Task SendEndToEndProbeAsync(Stream tunnelStream, string probeHost, int probePort, CancellationToken ct)
    {
        bool useTls = probePort is 443 or 8443;
        SslStream? ssl = null;
        Stream ioStream = tunnelStream;

        try
        {
            if (useTls)
            {
                ssl = new SslStream(tunnelStream, leaveInnerStreamOpen: true);
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = probeHost
                }, ct);
                ioStream = ssl;
            }

            string hostHeader = probePort is 80 or 443
                ? probeHost
                : $"{probeHost}:{probePort}";
            string req =
                $"GET /generate_204 HTTP/1.1\r\n" +
                $"Host: {hostHeader}\r\n" +
                "User-Agent: AppProxy-Probe/1.0\r\n" +
                "Accept: */*\r\n" +
                "Connection: close\r\n\r\n";

            byte[] reqBytes = Encoding.ASCII.GetBytes(req);
            await ioStream.WriteAsync(reqBytes, ct);
            await ioStream.FlushAsync(ct);

            byte[] buf = new byte[256];
            int read = await ioStream.ReadAsync(buf, ct);
            if (read <= 0)
            {
                throw new IOException("远端节点未返回响应（节点不可达或握手失败）");
            }

            if (probePort is 80 or 443 or 8080 or 8443)
            {
                string prefix = Encoding.ASCII.GetString(buf, 0, Math.Min(read, 16));
                if (!prefix.StartsWith("HTTP/", StringComparison.OrdinalIgnoreCase))
                {
                    throw new IOException("远端探测未返回有效 HTTP 响应");
                }
            }
        }
        finally
        {
            if (ssl is not null)
            {
                await ssl.DisposeAsync();
            }
        }
    }

    private static bool IsLoopbackHost(string? host)
    {
        if (string.IsNullOrWhiteSpace(host)) return false;
        string trimmed = host.Trim();
        if (string.Equals(trimmed, "localhost", StringComparison.OrdinalIgnoreCase)) return true;
        return IPAddress.TryParse(trimmed, out IPAddress? ip) && IPAddress.IsLoopback(ip);
    }
}

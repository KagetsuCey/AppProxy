using System.Diagnostics;
using System.IO;
using System.Net.Sockets;
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
}

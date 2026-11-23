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
        string? preferredOutboundInterface = null)
    {
        proxy.IsTesting = true;
        proxy.LastLatencyMs = null;
        proxy.LastTestStatus = "Testing...";

        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(8));

            var sw = Stopwatch.StartNew();
            using TcpClient tcp = await OutboundSocketConnector.ConnectAsync(
                proxy.Host,
                proxy.Port,
                null,
                bypassGlobalTun,
                preferredOutboundInterface,
                timeoutCts.Token);

            Stream stream = tcp.GetStream();
            if (proxy.Protocol == ProxyProtocol.Socks5)
            {
                await Socks5TunnelClient.ConnectAsync(stream, proxy, probeHost, probePort, null, timeoutCts.Token);
            }
            else
            {
                stream = await HttpConnectTunnelClient.ConnectAsync(stream, proxy, probeHost, probePort, timeoutCts.Token);
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
            proxy.IsTesting = false;
        }
    }
}

using System.Text;
using AppProxy.UI.Services;

namespace AppProxy.Bridge;

internal static class Program
{
    [STAThread]
    private static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        string? launchB64 = null;
        for (int i = 0; i < args.Length; i++)
        {
            if (args[i] == "--launch-b64" && i + 1 < args.Length)
            {
                launchB64 = args[++i];
            }
        }

        if (string.IsNullOrWhiteSpace(launchB64))
        {
            WriteHandshakeAndCloseStdout(new BridgeHandshakeResponse
            {
                Ok = false,
                BridgePid = (uint)Environment.ProcessId,
                Error = "Missing --launch-b64 argument."
            });
            return 2;
        }

        BridgeLaunchRequest? request;
        try
        {
            request = BridgeIpcCodec.DecodeLaunchRequestBase64(launchB64);
        }
        catch (Exception ex)
        {
            WriteHandshakeAndCloseStdout(new BridgeHandshakeResponse
            {
                Ok = false,
                BridgePid = (uint)Environment.ProcessId,
                Error = $"Invalid launch payload: {ex.Message}"
            });
            return 2;
        }

        if (request is null || string.IsNullOrWhiteSpace(request.ExePath))
        {
            WriteHandshakeAndCloseStdout(new BridgeHandshakeResponse
            {
                Ok = false,
                BridgePid = (uint)Environment.ProcessId,
                Error = "Launch request missing target executable path."
            });
            return 2;
        }

        using var host = new BridgeDaemonHost(request);
        return await host.RunAsync(WriteHandshakeAndCloseStdout);
    }

    private static void WriteHandshakeAndCloseStdout(BridgeHandshakeResponse response)
    {
        try
        {
            string line = BridgeIpcCodec.SerializeLine(response);
            Console.Out.WriteLine(line);
            Console.Out.Flush();
            Console.Out.Close();
        }
        catch
        {
            // Parent UI may have timed out or closed pipe
        }
    }
}

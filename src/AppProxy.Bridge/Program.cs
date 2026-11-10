using System.IO;
using System.Text;
using AppProxy.UI.Services;

namespace AppProxy.Bridge;

internal static class Program
{
    [STAThread]
    private static async Task<int> Main(string[] args)
    {
        try
        {
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

            BridgeLaunchRequest? request = BridgeIpcCodec.DecodeLaunchRequestBase64(launchB64);
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
        catch (Exception ex)
        {
            WriteHandshakeAndCloseStdout(new BridgeHandshakeResponse
            {
                Ok = false,
                BridgePid = (uint)Environment.ProcessId,
                Error = $"Bridge startup error: {ex.Message}"
            });
            return 1;
        }
    }

    private static void WriteHandshakeAndCloseStdout(BridgeHandshakeResponse response)
    {
        try
        {
            string line = BridgeIpcCodec.SerializeLine(response);
            using Stream stdout = Console.OpenStandardOutput();
            using var writer = new StreamWriter(stdout, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
            writer.WriteLine(line);
            writer.Flush();
        }
        catch
        {
            // Parent UI may have timed out or closed pipe
        }
    }
}

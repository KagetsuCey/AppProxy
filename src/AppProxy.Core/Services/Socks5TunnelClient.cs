using System.Buffers.Binary;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using AppProxy.UI.Models;

namespace AppProxy.UI.Services;

public static class Socks5TunnelClient
{
    public static async Task ConnectAsync(
        Stream stream,
        ProxyProfile proxy,
        string targetHost,
        int targetPort,
        IPAddress? targetIp,
        CancellationToken ct)
    {
        bool useAuth = !string.IsNullOrEmpty(proxy.Username);
        byte[] greeting = useAuth
            ? new byte[] { 0x05, 0x02, 0x00, 0x02 }
            : new byte[] { 0x05, 0x01, 0x00 };

        await stream.WriteAsync(greeting, ct);
        byte[] methodResp = new byte[2];
        await ReadExactAsync(stream, methodResp, ct);
        if (methodResp[0] != 0x05)
        {
            throw new IOException($"Invalid SOCKS5 version reply: 0x{methodResp[0]:X2}");
        }

        if (methodResp[1] == 0x02)
        {
            if (!useAuth)
            {
                throw new IOException("SOCKS5 proxy requires authentication but no credentials configured.");
            }
            byte[] userBytes = Encoding.UTF8.GetBytes(proxy.Username);
            byte[] passBytes = Encoding.UTF8.GetBytes(proxy.Password ?? string.Empty);
            if (userBytes.Length > 255 || passBytes.Length > 255)
            {
                throw new InvalidOperationException("SOCKS5 username/password exceeds 255 bytes.");
            }

            byte[] authReq = new byte[3 + userBytes.Length + passBytes.Length];
            authReq[0] = 0x01;
            authReq[1] = (byte)userBytes.Length;
            Buffer.BlockCopy(userBytes, 0, authReq, 2, userBytes.Length);
            authReq[2 + userBytes.Length] = (byte)passBytes.Length;
            Buffer.BlockCopy(passBytes, 0, authReq, 3 + userBytes.Length, passBytes.Length);

            await stream.WriteAsync(authReq, ct);
            byte[] authResp = new byte[2];
            await ReadExactAsync(stream, authResp, ct);
            if (authResp[1] != 0x00)
            {
                throw new IOException("SOCKS5 authentication rejected.");
            }
        }
        else if (methodResp[1] != 0x00)
        {
            throw new IOException($"SOCKS5 unsupported auth method: 0x{methodResp[1]:X2}");
        }

        byte[] addrPayload;
        byte atyp;
        if (targetIp is not null)
        {
            byte[] rawIp = targetIp.GetAddressBytes();
            atyp = targetIp.AddressFamily == AddressFamily.InterNetwork ? (byte)0x01 : (byte)0x04;
            addrPayload = rawIp;
        }
        else if (IPAddress.TryParse(targetHost, out var parsedIp))
        {
            byte[] rawIp = parsedIp.GetAddressBytes();
            atyp = parsedIp.AddressFamily == AddressFamily.InterNetwork ? (byte)0x01 : (byte)0x04;
            addrPayload = rawIp;
        }
        else
        {
            byte[] domainBytes = Encoding.UTF8.GetBytes(targetHost);
            if (domainBytes.Length == 0 || domainBytes.Length > 255)
            {
                throw new InvalidOperationException($"Invalid SOCKS5 target domain length: {targetHost}");
            }
            atyp = 0x03;
            addrPayload = new byte[1 + domainBytes.Length];
            addrPayload[0] = (byte)domainBytes.Length;
            Buffer.BlockCopy(domainBytes, 0, addrPayload, 1, domainBytes.Length);
        }

        byte[] connectReq = new byte[4 + addrPayload.Length + 2];
        connectReq[0] = 0x05; // VER
        connectReq[1] = 0x01; // CMD = CONNECT
        connectReq[2] = 0x00; // RSV
        connectReq[3] = atyp;
        Buffer.BlockCopy(addrPayload, 0, connectReq, 4, addrPayload.Length);
        BinaryPrimitives.WriteUInt16BigEndian(connectReq.AsSpan(4 + addrPayload.Length, 2), (ushort)targetPort);

        await stream.WriteAsync(connectReq, ct);

        byte[] replyHeader = new byte[4];
        await ReadExactAsync(stream, replyHeader, ct);
        if (replyHeader[0] != 0x05)
        {
            throw new IOException($"Invalid SOCKS5 reply version: 0x{replyHeader[0]:X2}");
        }
        if (replyHeader[1] != 0x00)
        {
            throw new IOException($"SOCKS5 CONNECT failed with reply code 0x{replyHeader[1]:X2} ({DescribeReply(replyHeader[1])})");
        }

        int discardLen = replyHeader[3] switch
        {
            0x01 => 4 + 2,
            0x04 => 16 + 2,
            0x03 => await ReadDomainLenAsync(stream, ct) + 2,
            _ => throw new IOException($"Unknown SOCKS5 reply ATYP: 0x{replyHeader[3]:X2}")
        };

        byte[] discard = new byte[discardLen];
        await ReadExactAsync(stream, discard, ct);
    }

    private static async Task<int> ReadDomainLenAsync(Stream stream, CancellationToken ct)
    {
        byte[] lenBuf = new byte[1];
        await ReadExactAsync(stream, lenBuf, ct);
        return lenBuf[0];
    }

    private static async Task ReadExactAsync(Stream stream, byte[] buffer, CancellationToken ct)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            int n = await stream.ReadAsync(buffer.AsMemory(read, buffer.Length - read), ct);
            if (n <= 0)
            {
                throw new EndOfStreamException("Unexpected EOF from SOCKS5 proxy.");
            }
            read += n;
        }
    }

    private static string DescribeReply(byte code) => code switch
    {
        0x01 => "General failure",
        0x02 => "Connection not allowed",
        0x03 => "Network unreachable",
        0x04 => "Host unreachable",
        0x05 => "Connection refused",
        0x06 => "TTL expired",
        0x07 => "Command not supported",
        0x08 => "Address type not supported",
        _ => "Unknown error"
    };
}

using System.Text.Json;
using System.Text.Json.Nodes;
using AppProxy.Core.Models;

namespace AppProxy.Core.Services;

public sealed record XrayInboundMapping(
    int LocalPort,
    string InboundTag,
    string OutboundTag,
    ProxyProfile Proxy);

/// <summary>
/// Builds minimal, in-memory Xray-core JSON configurations for VLESS / REALITY / TLS outbounds
/// with optional dialerProxy chaining into AppProxy's physical-NIC direct SOCKS5 listener.
/// </summary>
public static class XrayConfigBuilder
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false
    };

    public static string BuildSingleProxyConfigJson(
        int localSocksPort,
        string socksUser,
        string socksPass,
        ProxyProfile proxy,
        int? physicalDialerPort = null,
        string? physicalDialerUser = null,
        string? physicalDialerPass = null)
    {
        ArgumentNullException.ThrowIfNull(proxy);
        var mapping = new XrayInboundMapping(localSocksPort, "socks-in-0", "vless-out-0", proxy);
        return BuildMultiProxyConfigJson(
            [mapping],
            socksUser,
            socksPass,
            physicalDialerPort,
            physicalDialerUser,
            physicalDialerPass);
    }

    public static string BuildMultiProxyConfigJson(
        IReadOnlyList<XrayInboundMapping> mappings,
        string socksUser,
        string socksPass,
        int? physicalDialerPort = null,
        string? physicalDialerUser = null,
        string? physicalDialerPass = null)
    {
        ArgumentNullException.ThrowIfNull(mappings);
        if (mappings.Count == 0)
        {
            throw new ArgumentException("At least one Xray inbound mapping is required.", nameof(mappings));
        }

        var inbounds = new JsonArray();
        var outbounds = new JsonArray();
        var rules = new JsonArray();
        const string physicalDialerTag = "physical-direct";
        bool usePhysicalDialer = physicalDialerPort is > 0;

        foreach (XrayInboundMapping m in mappings)
        {
            inbounds.Add(BuildSocksInbound(m.LocalPort, m.InboundTag, socksUser, socksPass));
            outbounds.Add(BuildVlessOutbound(m.OutboundTag, m.Proxy, usePhysicalDialer ? physicalDialerTag : null));
            rules.Add(new JsonObject
            {
                ["type"] = "field",
                ["inboundTag"] = new JsonArray(m.InboundTag),
                ["outboundTag"] = m.OutboundTag
            });
        }

        if (usePhysicalDialer)
        {
            outbounds.Add(BuildPhysicalDialerOutbound(
                physicalDialerTag,
                physicalDialerPort!.Value,
                physicalDialerUser,
                physicalDialerPass));
        }

        outbounds.Add(new JsonObject
        {
            ["tag"] = "direct",
            ["protocol"] = "freedom"
        });

        var root = new JsonObject
        {
            ["log"] = new JsonObject
            {
                ["loglevel"] = "warning"
            },
            ["inbounds"] = inbounds,
            ["outbounds"] = outbounds,
            ["routing"] = new JsonObject
            {
                ["domainStrategy"] = "AsIs",
                ["rules"] = rules
            }
        };

        return root.ToJsonString(JsonOptions);
    }

    private static JsonObject BuildSocksInbound(int port, string tag, string user, string pass)
    {
        var settings = new JsonObject
        {
            ["udp"] = false
        };

        if (!string.IsNullOrEmpty(user))
        {
            settings["auth"] = "password";
            settings["accounts"] = new JsonArray
            {
                new JsonObject
                {
                    ["user"] = user,
                    ["pass"] = pass ?? string.Empty
                }
            };
        }
        else
        {
            settings["auth"] = "noauth";
        }

        return new JsonObject
        {
            ["tag"] = tag,
            ["listen"] = "127.0.0.1",
            ["port"] = port,
            ["protocol"] = "socks",
            ["settings"] = settings
        };
    }

    private static JsonObject BuildVlessOutbound(string tag, ProxyProfile proxy, string? dialerProxyTag)
    {
        if (proxy.Protocol != ProxyProtocol.Vless || proxy.Vless is null)
        {
            throw new InvalidOperationException($"Proxy '{proxy.Name}' is not a valid VLESS profile.");
        }

        VlessSettings v = proxy.Vless;
        if (!v.Validate(out string validationError))
        {
            throw new InvalidOperationException(validationError);
        }

        var userObj = new JsonObject
        {
            ["id"] = v.Uuid.Trim(),
            ["encryption"] = string.IsNullOrWhiteSpace(v.Encryption) ? "none" : v.Encryption.Trim()
        };
        if (!string.IsNullOrWhiteSpace(v.Flow))
        {
            userObj["flow"] = v.Flow.Trim();
        }

        string network = v.NormalizedNetwork;
        string security = v.NormalizedSecurity;

        var streamSettings = new JsonObject
        {
            ["network"] = network,
            ["security"] = security
        };

        if (security == "reality")
        {
            var realityObj = new JsonObject
            {
                ["show"] = false,
                ["fingerprint"] = string.IsNullOrWhiteSpace(v.Fingerprint) ? "chrome" : v.Fingerprint.Trim(),
                ["serverName"] = v.Sni.Trim(),
                ["publicKey"] = v.PublicKey.Trim(),
                ["shortId"] = v.ShortId.Trim(),
                ["spiderX"] = string.IsNullOrEmpty(v.SpiderX) ? string.Empty : v.SpiderX.Trim()
            };
            streamSettings["realitySettings"] = realityObj;
        }
        else if (security == "tls")
        {
            var tlsObj = new JsonObject
            {
                ["allowInsecure"] = v.AllowInsecure
            };
            if (!string.IsNullOrWhiteSpace(v.Sni))
            {
                tlsObj["serverName"] = v.Sni.Trim();
            }
            else if (!string.IsNullOrWhiteSpace(proxy.Host))
            {
                tlsObj["serverName"] = proxy.Host.Trim();
            }
            if (!string.IsNullOrWhiteSpace(v.Fingerprint))
            {
                tlsObj["fingerprint"] = v.Fingerprint.Trim();
            }
            if (!string.IsNullOrWhiteSpace(v.Alpn))
            {
                var alpnArray = new JsonArray();
                foreach (string item in v.Alpn.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                {
                    alpnArray.Add(item);
                }
                if (alpnArray.Count > 0)
                {
                    tlsObj["alpn"] = alpnArray;
                }
            }
            streamSettings["tlsSettings"] = tlsObj;
        }

        ApplyTransportSettings(streamSettings, network, v);

        if (!string.IsNullOrWhiteSpace(dialerProxyTag))
        {
            streamSettings["sockopt"] = new JsonObject
            {
                ["dialerProxy"] = dialerProxyTag
            };
        }

        return new JsonObject
        {
            ["tag"] = tag,
            ["protocol"] = "vless",
            ["settings"] = new JsonObject
            {
                ["vnext"] = new JsonArray
                {
                    new JsonObject
                    {
                        ["address"] = proxy.Host.Trim(),
                        ["port"] = proxy.Port,
                        ["users"] = new JsonArray { userObj }
                    }
                }
            },
            ["streamSettings"] = streamSettings
        };
    }

    private static void ApplyTransportSettings(JsonObject streamSettings, string network, VlessSettings v)
    {
        switch (network)
        {
            case "ws":
            {
                var wsObj = new JsonObject();
                if (!string.IsNullOrWhiteSpace(v.Path))
                {
                    wsObj["path"] = v.Path.Trim();
                }
                if (!string.IsNullOrWhiteSpace(v.HostHeader))
                {
                    wsObj["host"] = v.HostHeader.Trim();
                }
                streamSettings["wsSettings"] = wsObj;
                break;
            }
            case "grpc":
            {
                var grpcObj = new JsonObject();
                if (!string.IsNullOrWhiteSpace(v.ServiceName))
                {
                    grpcObj["serviceName"] = v.ServiceName.Trim();
                }
                if (string.Equals(v.Mode?.Trim(), "multi", StringComparison.OrdinalIgnoreCase))
                {
                    grpcObj["multiMode"] = true;
                }
                streamSettings["grpcSettings"] = grpcObj;
                break;
            }
            case "httpupgrade":
            {
                var huObj = new JsonObject();
                if (!string.IsNullOrWhiteSpace(v.Path))
                {
                    huObj["path"] = v.Path.Trim();
                }
                if (!string.IsNullOrWhiteSpace(v.HostHeader))
                {
                    huObj["host"] = v.HostHeader.Trim();
                }
                streamSettings["httpupgradeSettings"] = huObj;
                break;
            }
            case "xhttp":
            case "splithttp":
            {
                var xhttpObj = new JsonObject();
                if (!string.IsNullOrWhiteSpace(v.Path))
                {
                    xhttpObj["path"] = v.Path.Trim();
                }
                if (!string.IsNullOrWhiteSpace(v.HostHeader))
                {
                    xhttpObj["host"] = v.HostHeader.Trim();
                }
                if (!string.IsNullOrWhiteSpace(v.Mode))
                {
                    xhttpObj["mode"] = v.Mode.Trim();
                }
                streamSettings["xhttpSettings"] = xhttpObj;
                break;
            }
            case "tcp":
            case "raw":
            {
                if (string.Equals(v.HeaderType?.Trim(), "http", StringComparison.OrdinalIgnoreCase))
                {
                    var headerReq = new JsonObject();
                    if (!string.IsNullOrWhiteSpace(v.Path))
                    {
                        headerReq["path"] = new JsonArray(v.Path.Trim());
                    }
                    if (!string.IsNullOrWhiteSpace(v.HostHeader))
                    {
                        headerReq["headers"] = new JsonObject
                        {
                            ["Host"] = new JsonArray(v.HostHeader.Trim())
                        };
                    }
                    streamSettings["tcpSettings"] = new JsonObject
                    {
                        ["header"] = new JsonObject
                        {
                            ["type"] = "http",
                            ["request"] = headerReq
                        }
                    };
                }
                break;
            }
        }
    }

    private static JsonObject BuildPhysicalDialerOutbound(string tag, int port, string? user, string? pass)
    {
        var serverObj = new JsonObject
        {
            ["address"] = "127.0.0.1",
            ["port"] = port
        };

        if (!string.IsNullOrEmpty(user))
        {
            serverObj["users"] = new JsonArray
            {
                new JsonObject
                {
                    ["user"] = user,
                    ["pass"] = pass ?? string.Empty
                }
            };
        }

        return new JsonObject
        {
            ["tag"] = tag,
            ["protocol"] = "socks",
            ["settings"] = new JsonObject
            {
                ["servers"] = new JsonArray { serverObj }
            }
        };
    }
}

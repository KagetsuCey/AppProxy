using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using AppProxy.Core.Models;

namespace AppProxy.Core.Services;

public sealed record ProxyBatchParseError(int LineNumber, string RawLine, string Reason);

public sealed record ProxyBatchParseResult(
    IReadOnlyList<ProxyProfile> Proxies,
    IReadOnlyList<ProxyBatchParseError> Errors);

/// <summary>
/// Parses batch proxy definitions from URIs, residential host:port:user:pass lines,
/// user:pass@host:port lines, IPv6 endpoints, or AppProxy JSON configs, and exports URIs.
/// </summary>
public static class ProxyBatchParser
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private static readonly JsonSerializerOptions IndentedJsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private sealed record ExportProxyDto(
        string Name,
        ProxyProtocol Protocol,
        string Host,
        int Port,
        string Username,
        string Password,
        [property: JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        VlessSettings? Vless = null);

    public static ProxyBatchParseResult Parse(
        string? input,
        ProxyProtocol defaultProtocol = ProxyProtocol.Socks5,
        bool allowXrayProtocols = true)
    {
        if (string.IsNullOrWhiteSpace(input))
        {
            return new ProxyBatchParseResult([], []);
        }

        string trimmedWhole = input.Trim();
        if ((trimmedWhole.StartsWith('[') || trimmedWhole.StartsWith('{')) &&
            TryParseJson(trimmedWhole, allowXrayProtocols, out ProxyBatchParseResult? jsonResult))
        {
            return jsonResult!;
        }

        var proxies = new List<ProxyProfile>();
        var errors = new List<ProxyBatchParseError>();
        string[] lines = input.Split(["\r\n", "\n", "\r"], StringSplitOptions.None);

        for (int i = 0; i < lines.Length; i++)
        {
            int lineNo = i + 1;
            string line = lines[i].Trim();
            if (string.IsNullOrEmpty(line) || line.StartsWith('#') || line.StartsWith("//", StringComparison.Ordinal))
            {
                continue;
            }

            if (TryParseSingleLine(line, defaultProtocol, allowXrayProtocols, out ProxyProfile? proxy, out string error))
            {
                proxies.Add(proxy!);
            }
            else
            {
                string preview = line.Length > 80 ? line[..80] + "..." : line;
                errors.Add(new ProxyBatchParseError(lineNo, preview, error));
            }
        }

        return new ProxyBatchParseResult(proxies, errors);
    }

    public static bool TryParseSingle(
        string? input,
        ProxyProtocol defaultProtocol,
        bool allowXrayProtocols,
        out ProxyProfile? proxy,
        out string error,
        out int totalParsedCount)
    {
        ProxyBatchParseResult result = Parse(input, defaultProtocol, allowXrayProtocols);
        totalParsedCount = result.Proxies.Count;
        if (result.Proxies.Count > 0)
        {
            proxy = result.Proxies[0];
            error = string.Empty;
            return true;
        }

        proxy = null;
        error = result.Errors.FirstOrDefault()?.Reason ?? "未能解析出有效的代理链接，请检查格式。";
        return false;
    }

    public static string ExportSingleUri(ProxyProfile proxy)
    {
        ArgumentNullException.ThrowIfNull(proxy);
        return ExportToUriLines([proxy]);
    }

    public static string BuildDedupeKey(ProxyProfile proxy)
    {
        string host = (proxy.Host ?? string.Empty).Trim().ToLowerInvariant();
        if (proxy.Protocol == ProxyProtocol.Vless && proxy.Vless is { } v)
        {
            return string.Join(
                '|',
                proxy.Protocol,
                host,
                proxy.Port,
                v.Uuid.Trim().ToLowerInvariant(),
                v.NormalizedSecurity,
                v.Sni.Trim().ToLowerInvariant(),
                v.PublicKey.Trim(),
                v.ShortId.Trim(),
                v.NormalizedNetwork,
                v.Flow.Trim());
        }

        string user = (proxy.Username ?? string.Empty).Trim();
        return $"{proxy.Protocol}|{host}|{proxy.Port}|{user}";
    }

    public static string ExportToUriLines(IEnumerable<ProxyProfile> proxies)
    {
        var lines = new List<string>();
        foreach (ProxyProfile proxy in proxies)
        {
            string host = (proxy.Host ?? string.Empty).Trim();
            string formattedHost = IPAddress.TryParse(host, out var ip) &&
                                   ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
                ? $"[{host}]"
                : host;

            var sb = new StringBuilder();
            if (proxy.Protocol == ProxyProtocol.Vless && proxy.Vless is not null)
            {
                AppendVlessUri(sb, proxy, formattedHost);
            }
            else
            {
                string scheme = proxy.Protocol switch
                {
                    ProxyProtocol.Socks5 => "socks5",
                    ProxyProtocol.Http => "http",
                    ProxyProtocol.Https => "https",
                    _ => "socks5"
                };

                sb.Append(scheme).Append("://");
                if (!string.IsNullOrEmpty(proxy.Username))
                {
                    sb.Append(Uri.EscapeDataString(proxy.Username));
                    if (!string.IsNullOrEmpty(proxy.Password))
                    {
                        sb.Append(':').Append(Uri.EscapeDataString(proxy.Password));
                    }
                    sb.Append('@');
                }
                sb.Append(formattedHost).Append(':').Append(proxy.Port);

                if (!string.IsNullOrWhiteSpace(proxy.Name))
                {
                    sb.Append('#').Append(Uri.EscapeDataString(proxy.Name.Trim()));
                }
            }

            lines.Add(sb.ToString());
        }

        return string.Join(Environment.NewLine, lines);
    }

    private static void AppendVlessUri(StringBuilder sb, ProxyProfile proxy, string formattedHost)
    {
        VlessSettings v = proxy.Vless!;
        sb.Append("vless://");
        if (!string.IsNullOrEmpty(v.Uuid))
        {
            sb.Append(Uri.EscapeDataString(v.Uuid.Trim())).Append('@');
        }
        sb.Append(formattedHost).Append(':').Append(proxy.Port);

        var queryPairs = new List<(string Key, string Value)>
        {
            ("encryption", string.IsNullOrWhiteSpace(v.Encryption) ? "none" : v.Encryption.Trim()),
            ("security", v.NormalizedSecurity)
        };

        void AddIfNonEmpty(string key, string? val)
        {
            if (!string.IsNullOrWhiteSpace(val))
            {
                queryPairs.Add((key, val.Trim()));
            }
        }

        AddIfNonEmpty("sni", v.Sni);
        AddIfNonEmpty("fp", v.Fingerprint);
        AddIfNonEmpty("pbk", v.PublicKey);
        AddIfNonEmpty("sid", v.ShortId);
        AddIfNonEmpty("spx", v.SpiderX);
        AddIfNonEmpty("flow", v.Flow);
        queryPairs.Add(("type", v.NormalizedNetwork));
        AddIfNonEmpty("headerType", v.HeaderType);
        AddIfNonEmpty("path", v.Path);
        AddIfNonEmpty("host", v.HostHeader);
        AddIfNonEmpty("serviceName", v.ServiceName);
        AddIfNonEmpty("mode", v.Mode);
        AddIfNonEmpty("alpn", v.Alpn);
        if (v.AllowInsecure)
        {
            queryPairs.Add(("allowInsecure", "1"));
        }

        sb.Append('?');
        for (int i = 0; i < queryPairs.Count; i++)
        {
            if (i > 0) sb.Append('&');
            sb.Append(Uri.EscapeDataString(queryPairs[i].Key))
              .Append('=')
              .Append(Uri.EscapeDataString(queryPairs[i].Value));
        }

        if (!string.IsNullOrWhiteSpace(proxy.Name))
        {
            sb.Append('#').Append(Uri.EscapeDataString(proxy.Name.Trim()));
        }
    }

    public static string ExportToJson(IEnumerable<ProxyProfile> proxies)
    {
        ArgumentNullException.ThrowIfNull(proxies);
        var items = proxies
            .Select(p => new ExportProxyDto(
                p.Name ?? string.Empty,
                p.Protocol,
                (p.Host ?? string.Empty).Trim(),
                p.Port,
                p.Username ?? string.Empty,
                p.Password ?? string.Empty,
                p.Protocol == ProxyProtocol.Vless ? p.Vless?.Clone() : null))
            .ToList();
        return JsonSerializer.Serialize(items, IndentedJsonOptions);
    }

    private static bool TryParseJson(string json, bool allowXrayProtocols, out ProxyBatchParseResult? result)
    {
        result = null;
        try
        {
            List<ProxyProfile>? rawList = null;
            if (json.StartsWith('['))
            {
                rawList = JsonSerializer.Deserialize<List<ProxyProfile>>(json, JsonOptions);
            }
            else if (json.StartsWith('{'))
            {
                AppConfig? cfg = JsonSerializer.Deserialize<AppConfig>(json, JsonOptions);
                if (cfg?.Proxies is { Count: > 0 })
                {
                    rawList = cfg.Proxies;
                }
                else
                {
                    ProxyProfile? single = JsonSerializer.Deserialize<ProxyProfile>(json, JsonOptions);
                    if (single is not null && !string.IsNullOrWhiteSpace(single.Host))
                    {
                        rawList = [single];
                    }
                }
            }

            if (rawList is null)
            {
                return false;
            }

            var valid = new List<ProxyProfile>();
            var errors = new List<ProxyBatchParseError>();
            for (int i = 0; i < rawList.Count; i++)
            {
                ProxyProfile item = rawList[i];
                string host = NormalizeHost(item.Host);
                if (string.IsNullOrWhiteSpace(host) || item.Port is < 1 or > 65535)
                {
                    errors.Add(new ProxyBatchParseError(i + 1, $"{item.Host}:{item.Port}", "JSON 节点地址或端口无效"));
                    continue;
                }

                if (item.Protocol == ProxyProtocol.Vless)
                {
                    if (!allowXrayProtocols)
                    {
                        errors.Add(new ProxyBatchParseError(i + 1, $"{host}:{item.Port}", "检测到 VLESS 节点，请先在「系统设置 → Xray-core 托管内核」中配置路径或一键下载 xray.exe"));
                        continue;
                    }
                    string vlessErr = string.Empty;
                    if (item.Vless is null || !item.Vless.Validate(out vlessErr))
                    {
                        errors.Add(new ProxyBatchParseError(i + 1, $"{host}:{item.Port}", item.Vless is null ? "VLESS 节点缺少 vless 参数对象" : vlessErr));
                        continue;
                    }
                }

                var fresh = new ProxyProfile
                {
                    Id = Guid.NewGuid(),
                    Protocol = item.Protocol,
                    Host = host,
                    Port = item.Port,
                    Username = item.Protocol == ProxyProtocol.Vless ? string.Empty : (item.Username?.Trim() ?? string.Empty),
                    Password = item.Protocol == ProxyProtocol.Vless ? string.Empty : (item.Password ?? string.Empty),
                    Vless = item.Protocol == ProxyProtocol.Vless ? item.Vless!.Clone() : null
                };
                fresh.Name = string.IsNullOrWhiteSpace(item.Name)
                    ? $"{fresh.ProtocolDisplay} {fresh.Host}:{fresh.Port}"
                    : item.Name.Trim();
                valid.Add(fresh);
            }

            if (valid.Count > 0 || errors.Count > 0)
            {
                result = new ProxyBatchParseResult(valid, errors);
                return true;
            }
        }
        catch
        {
            // Fall back to line parser if JSON failed
        }

        return false;
    }

    private static bool TryParseSingleLine(
        string line,
        ProxyProtocol defaultProtocol,
        bool allowXrayProtocols,
        out ProxyProfile? proxy,
        out string error)
    {
        proxy = null;
        error = string.Empty;

        int schemeIdx = line.IndexOf("://", StringComparison.Ordinal);
        if (schemeIdx > 0 && schemeIdx <= 10)
        {
            string prefix = line[..schemeIdx];
            if (prefix.All(char.IsLetterOrDigit))
            {
                return TryParseUriLine(line, allowXrayProtocols, out proxy, out error);
            }
        }

        return TryParsePlainLine(line, defaultProtocol, out proxy, out error);
    }

    private static bool TryParseUriLine(string line, bool allowXrayProtocols, out ProxyProfile? proxy, out string error)
    {
        proxy = null;
        error = string.Empty;

        if (!Uri.TryCreate(line, UriKind.Absolute, out Uri? uri))
        {
            error = "无效的代理 URI 格式";
            return false;
        }

        ProxyProtocol protocol;
        switch (uri.Scheme.ToLowerInvariant())
        {
            case "socks":
            case "socks5":
            case "socks5h":
                protocol = ProxyProtocol.Socks5;
                break;
            case "http":
                protocol = ProxyProtocol.Http;
                break;
            case "https":
                protocol = ProxyProtocol.Https;
                break;
            case "vless":
                if (!allowXrayProtocols)
                {
                    error = "检测到 VLESS 节点，请先在「系统设置 → Xray-core 托管内核」中配置路径或一键下载 xray.exe";
                    return false;
                }
                protocol = ProxyProtocol.Vless;
                break;
            default:
                error = allowXrayProtocols
                    ? $"不支持的代理协议 '{uri.Scheme}'（当前支持 socks5/http/https/vless）"
                    : $"不支持的代理协议 '{uri.Scheme}'（仅支持 socks5/http/https）";
                return false;
        }

        string host = NormalizeHost(uri.Host);
        if (string.IsNullOrWhiteSpace(host))
        {
            error = "缺少代理服务器地址";
            return false;
        }

        int port = uri.Port;
        if (port is < 1 or > 65535)
        {
            error = "URI 缺少有效端口号 (1-65535)";
            return false;
        }

        string remark = string.Empty;
        if (!string.IsNullOrEmpty(uri.Fragment) && uri.Fragment.Length > 1)
        {
            remark = Uri.UnescapeDataString(uri.Fragment[1..]).Trim();
        }

        if (protocol == ProxyProtocol.Vless)
        {
            string uuid = Uri.UnescapeDataString(uri.UserInfo ?? string.Empty).Trim();
            Dictionary<string, string> query = ParseQueryString(uri.Query);

            string GetQuery(string key, string fallback = "") =>
                query.TryGetValue(key, out string? val) ? val : fallback;

            string allowInsecRaw = GetQuery("allowInsecure");
            if (string.IsNullOrEmpty(allowInsecRaw)) allowInsecRaw = GetQuery("insecure");
            bool allowInsecure = allowInsecRaw == "1" || string.Equals(allowInsecRaw, "true", StringComparison.OrdinalIgnoreCase);

            var vless = new VlessSettings
            {
                Uuid = uuid,
                Encryption = string.IsNullOrWhiteSpace(GetQuery("encryption")) ? "none" : GetQuery("encryption"),
                Flow = GetQuery("flow"),
                Network = string.IsNullOrWhiteSpace(GetQuery("type")) ? "tcp" : GetQuery("type"),
                HeaderType = string.IsNullOrWhiteSpace(GetQuery("headerType")) ? "none" : GetQuery("headerType"),
                Security = string.IsNullOrWhiteSpace(GetQuery("security")) ? "none" : GetQuery("security"),
                Sni = GetQuery("sni"),
                Fingerprint = GetQuery("fp"),
                PublicKey = GetQuery("pbk"),
                ShortId = GetQuery("sid"),
                SpiderX = GetQuery("spx"),
                Alpn = GetQuery("alpn"),
                AllowInsecure = allowInsecure,
                Path = GetQuery("path"),
                HostHeader = GetQuery("host"),
                ServiceName = GetQuery("serviceName"),
                Mode = GetQuery("mode")
            };

            if (!vless.Validate(out error))
            {
                return false;
            }

            var vlessProfile = new ProxyProfile
            {
                Id = Guid.NewGuid(),
                Protocol = ProxyProtocol.Vless,
                Host = host,
                Port = port,
                Vless = vless
            };
            vlessProfile.Name = string.IsNullOrEmpty(remark)
                ? $"{vlessProfile.ProtocolDisplay} {vlessProfile.Host}:{vlessProfile.Port}"
                : remark;

            proxy = vlessProfile;
            return true;
        }

        string username = string.Empty;
        string password = string.Empty;
        if (!string.IsNullOrEmpty(uri.UserInfo))
        {
            int colon = uri.UserInfo.IndexOf(':');
            if (colon >= 0)
            {
                username = Uri.UnescapeDataString(uri.UserInfo[..colon]);
                password = Uri.UnescapeDataString(uri.UserInfo[(colon + 1)..]);
            }
            else if (TryDecodeBase64UserPass(Uri.UnescapeDataString(uri.UserInfo), out string decUser, out string decPass))
            {
                username = decUser;
                password = decPass;
            }
            else
            {
                username = Uri.UnescapeDataString(uri.UserInfo);
            }
        }

        var result = new ProxyProfile
        {
            Id = Guid.NewGuid(),
            Protocol = protocol,
            Host = host,
            Port = port,
            Username = username.Trim(),
            Password = password
        };
        result.Name = string.IsNullOrEmpty(remark)
            ? $"{result.ProtocolDisplay} {result.Host}:{result.Port}"
            : remark;

        proxy = result;
        return true;
    }

    private static Dictionary<string, string> ParseQueryString(string rawQuery)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (string.IsNullOrWhiteSpace(rawQuery)) return map;

        string trimmed = rawQuery.StartsWith('?') ? rawQuery[1..] : rawQuery;
        foreach (string part in trimmed.Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            int eq = part.IndexOf('=');
            if (eq < 0)
            {
                string keyOnly = Uri.UnescapeDataString(part.Replace('+', ' ')).Trim();
                if (!string.IsNullOrEmpty(keyOnly))
                {
                    map[keyOnly] = string.Empty;
                }
                continue;
            }

            string key = Uri.UnescapeDataString(part[..eq].Replace('+', ' ')).Trim();
            string val = Uri.UnescapeDataString(part[(eq + 1)..].Replace('+', ' '));
            if (!string.IsNullOrEmpty(key))
            {
                map[key] = val;
            }
        }

        return map;
    }

    private static bool TryParsePlainLine(
        string line,
        ProxyProtocol defaultProtocol,
        out ProxyProfile? proxy,
        out string error)
    {
        proxy = null;
        error = string.Empty;

        string working = line.Trim();
        string remark = string.Empty;

        // Extract whitespace-prefixed #remark safely without breaking '#' inside passwords
        int wsHashIdx = FindWhitespaceHashIndex(working);
        if (wsHashIdx >= 0)
        {
            remark = working[(wsHashIdx + 1)..].Trim();
            working = working[..wsHashIdx].Trim();
        }

        string username = string.Empty;
        string password = string.Empty;
        string endpointPart = working;

        int atIdx = working.LastIndexOf('@');
        if (atIdx >= 0)
        {
            string authPart = working[..atIdx];
            endpointPart = working[(atIdx + 1)..].Trim();
            if (string.IsNullOrEmpty(endpointPart))
            {
                error = "缺少服务器地址与端口";
                return false;
            }

            int colon = authPart.IndexOf(':');
            if (colon >= 0)
            {
                username = authPart[..colon].Trim();
                password = authPart[(colon + 1)..];
            }
            else
            {
                username = authPart.Trim();
            }

            // For user:pass@host:port#remark without space before '#'
            if (string.IsNullOrEmpty(remark))
            {
                int hashIdx = endpointPart.IndexOf('#');
                if (hashIdx >= 0)
                {
                    remark = endpointPart[(hashIdx + 1)..].Trim();
                    endpointPart = endpointPart[..hashIdx].Trim();
                }
            }

            if (!TryParseHostAndPort(endpointPart, out string parsedHost, out int parsedPort, out error))
            {
                return false;
            }

            proxy = CreatePlainProxy(defaultProtocol, parsedHost, parsedPort, username, password, remark);
            return true;
        }

        // Support [ipv6]:port[:user:pass]
        if (endpointPart.StartsWith('['))
        {
            int closeBracket = endpointPart.IndexOf(']');
            if (closeBracket <= 1)
            {
                error = "IPv6 地址括号格式无效";
                return false;
            }

            string ipv6Host = endpointPart[1..closeBracket].Trim();
            if (!IPAddress.TryParse(ipv6Host, out _))
            {
                error = $"无效的 IPv6 地址 '{ipv6Host}'";
                return false;
            }

            string rest = endpointPart[(closeBracket + 1)..];
            if (!rest.StartsWith(':'))
            {
                error = "IPv6 地址后缺少端口 (:port)";
                return false;
            }

            string afterColon = rest[1..];
            if (!TryParsePortAndOptionalAuth(afterColon, ref remark, out int portV6, out username, out password, out error))
            {
                return false;
            }

            proxy = CreatePlainProxy(defaultProtocol, ipv6Host, portV6, username, password, remark);
            return true;
        }

        // Standard host:port or host:port:user:pass
        int firstColon = endpointPart.IndexOf(':');
        if (firstColon <= 0)
        {
            error = "缺少端口号 (期望 host:port 或 URI)";
            return false;
        }

        string host = NormalizeHost(endpointPart[..firstColon]);
        string remainder = endpointPart[(firstColon + 1)..];
        if (!TryParsePortAndOptionalAuth(remainder, ref remark, out int port, out username, out password, out error))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(host))
        {
            error = "代理服务器地址不能为空";
            return false;
        }

        proxy = CreatePlainProxy(defaultProtocol, host, port, username, password, remark);
        return true;
    }

    private static bool TryParsePortAndOptionalAuth(
        string afterFirstColon,
        ref string remark,
        out int port,
        out string username,
        out string password,
        out string error)
    {
        port = 0;
        username = string.Empty;
        password = string.Empty;
        error = string.Empty;

        int secondColon = afterFirstColon.IndexOf(':');
        if (secondColon < 0)
        {
            // No auth part -> safe to treat trailing #remark as comment
            string portPart = afterFirstColon;
            if (string.IsNullOrEmpty(remark))
            {
                int hashIdx = portPart.IndexOf('#');
                if (hashIdx >= 0)
                {
                    remark = portPart[(hashIdx + 1)..].Trim();
                    portPart = portPart[..hashIdx].Trim();
                }
            }

            if (!int.TryParse(portPart.Trim(), out port) || port is < 1 or > 65535)
            {
                error = $"无效端口号 '{portPart}'";
                return false;
            }
            return true;
        }

        string rawPort = afterFirstColon[..secondColon].Trim();
        if (!int.TryParse(rawPort, out port) || port is < 1 or > 65535)
        {
            error = $"无效端口号 '{rawPort}'";
            return false;
        }

        string authTail = afterFirstColon[(secondColon + 1)..];
        int thirdColon = authTail.IndexOf(':');
        if (thirdColon < 0)
        {
            error = "格式不完整，认证格式应为 host:port:user:pass";
            return false;
        }

        username = authTail[..thirdColon].Trim();
        password = authTail[(thirdColon + 1)..];
        return true;
    }

    private static bool TryParseHostAndPort(string hostPort, out string host, out int port, out string error)
    {
        host = string.Empty;
        port = 0;
        error = string.Empty;

        if (hostPort.StartsWith('['))
        {
            int close = hostPort.IndexOf(']');
            if (close <= 1 || close + 1 >= hostPort.Length || hostPort[close + 1] != ':')
            {
                error = "IPv6 主机与端口格式应为 [ipv6]:port";
                return false;
            }

            host = hostPort[1..close].Trim();
            string portStr = hostPort[(close + 2)..].Trim();
            if (!IPAddress.TryParse(host, out _))
            {
                error = $"无效的 IPv6 地址 '{host}'";
                return false;
            }
            if (!int.TryParse(portStr, out port) || port is < 1 or > 65535)
            {
                error = $"无效端口号 '{portStr}'";
                return false;
            }
            return true;
        }

        int colon = hostPort.LastIndexOf(':');
        if (colon <= 0)
        {
            error = "缺少端口号 (期望 host:port)";
            return false;
        }

        host = NormalizeHost(hostPort[..colon]);
        string portText = hostPort[(colon + 1)..].Trim();
        if (string.IsNullOrWhiteSpace(host))
        {
            error = "代理服务器地址不能为空";
            return false;
        }
        if (!int.TryParse(portText, out port) || port is < 1 or > 65535)
        {
            error = $"无效端口号 '{portText}'";
            return false;
        }
        return true;
    }

    private static ProxyProfile CreatePlainProxy(
        ProxyProtocol protocol,
        string host,
        int port,
        string username,
        string password,
        string remark)
    {
        var profile = new ProxyProfile
        {
            Id = Guid.NewGuid(),
            Protocol = protocol,
            Host = host,
            Port = port,
            Username = username,
            Password = password
        };
        profile.Name = string.IsNullOrWhiteSpace(remark)
            ? $"{profile.ProtocolDisplay} {profile.Host}:{profile.Port}"
            : remark.Trim();
        return profile;
    }

    private static int FindWhitespaceHashIndex(string text)
    {
        for (int i = 1; i < text.Length; i++)
        {
            if (text[i] == '#' && char.IsWhiteSpace(text[i - 1]))
            {
                return i;
            }
        }
        return -1;
    }

    private static bool TryDecodeBase64UserPass(string raw, out string user, out string pass)
    {
        user = string.Empty;
        pass = string.Empty;
        if (string.IsNullOrWhiteSpace(raw)) return false;

        try
        {
            string padded = raw.Replace('-', '+').Replace('_', '/');
            int mod = padded.Length % 4;
            if (mod > 0) padded = padded.PadRight(padded.Length + (4 - mod), '=');

            byte[] bytes = Convert.FromBase64String(padded);
            string decoded = Encoding.UTF8.GetString(bytes);
            int colon = decoded.IndexOf(':');
            if (colon > 0)
            {
                user = decoded[..colon];
                pass = decoded[(colon + 1)..];
                return true;
            }
        }
        catch
        {
        }

        return false;
    }

    private static string NormalizeHost(string? raw) =>
        (raw ?? string.Empty).Trim().Trim('[', ']');
}

using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using AppProxy.UI.Models;

namespace AppProxy.UI.Services;

public sealed class ConfigService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly string _configPath;
    private readonly object _fileLock = new();

    public ConfigService(string? customPath = null)
    {
        if (!string.IsNullOrWhiteSpace(customPath))
        {
            _configPath = customPath;
            return;
        }

        string portablePath = Path.Combine(AppContext.BaseDirectory, "config.json");
        if (File.Exists(portablePath))
        {
            _configPath = portablePath;
        }
        else
        {
            string appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            _configPath = Path.Combine(appData, "AppProxy", "config.json");
        }
    }

    public AppConfig Load()
    {
        lock (_fileLock)
        {
            try
            {
                if (!File.Exists(_configPath))
                {
                    return CreateDefaultConfig();
                }

                string json = File.ReadAllText(_configPath);
                var cfg = JsonSerializer.Deserialize<AppConfig>(json, JsonOptions);
                return cfg ?? CreateDefaultConfig();
            }
            catch
            {
                return CreateDefaultConfig();
            }
        }
    }

    public void Save(AppConfig config)
    {
        lock (_fileLock)
        {
            string? dir = Path.GetDirectoryName(_configPath);
            if (!string.IsNullOrEmpty(dir))
            {
                Directory.CreateDirectory(dir);
            }

            string json = JsonSerializer.Serialize(config, JsonOptions);
            string tempPath = _configPath + ".tmp";
            File.WriteAllText(tempPath, json);
            File.Move(tempPath, _configPath, overwrite: true);
        }
    }

    private static AppConfig CreateDefaultConfig() => new()
    {
        IsDarkTheme = true,
        Proxies = new List<ProxyProfile>
        {
            new()
            {
                Name = "Local SOCKS5 (1080)",
                Protocol = ProxyProtocol.Socks5,
                Host = "127.0.0.1",
                Port = 1080
            },
            new()
            {
                Name = "Local HTTP (7890)",
                Protocol = ProxyProtocol.Http,
                Host = "127.0.0.1",
                Port = 7890
            }
        }
    };
}

using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;

namespace AppProxy.Core.Services;

public sealed record XrayDownloadProgress(
    string Stage,
    long BytesReceived,
    long? TotalBytes);

public sealed record XrayDownloadResult(
    string ExePath,
    string VersionTag,
    string DetectedVersion);

/// <summary>
/// Resolves, validates, and optionally downloads the managed Xray-core binary (xray.exe).
/// </summary>
public static class XrayCoreManager
{
    private const string LatestReleaseApiUrl = "https://api.github.com/repos/XTLS/Xray-core/releases/latest";

    public static string? ResolveXrayPath(string? configuredPath, string? baseDir = null) =>
        AppPaths.ResolveXrayExePath(configuredPath, baseDir);

    public static async Task<string?> DetectVersionAsync(string? xrayExePath, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(xrayExePath) || !File.Exists(xrayExePath))
        {
            return null;
        }

        try
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(TimeSpan.FromSeconds(3));

            var psi = new ProcessStartInfo
            {
                FileName = xrayExePath,
                Arguments = "version",
                WorkingDirectory = Path.GetDirectoryName(xrayExePath) ?? AppPaths.ResolveBaseDirectory(),
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true
            };

            using var proc = Process.Start(psi);
            if (proc is null) return null;

            string stdout = await proc.StandardOutput.ReadToEndAsync(timeoutCts.Token);
            await proc.WaitForExitAsync(timeoutCts.Token);

            if (proc.ExitCode != 0) return null;

            foreach (string rawLine in stdout.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
            {
                string line = rawLine.Trim();
                if (line.StartsWith("Xray", StringComparison.OrdinalIgnoreCase))
                {
                    return line;
                }
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    public static async Task<XrayDownloadResult> DownloadLatestAsync(
        string? baseDir = null,
        IProgress<XrayDownloadProgress>? progress = null,
        CancellationToken ct = default)
    {
        string coresDir = AppPaths.GetCoresDirectory(baseDir);
        Directory.CreateDirectory(coresDir);

        string assetName = Environment.Is64BitOperatingSystem
            ? "Xray-windows-64.zip"
            : "Xray-windows-32.zip";

        using var http = new HttpClient
        {
            Timeout = TimeSpan.FromMinutes(5)
        };
        http.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("AppProxy", "1.0"));
        http.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));

        progress?.Report(new XrayDownloadProgress("正在获取 Xray-core 最新版本信息...", 0, null));

        string releaseJson = await http.GetStringAsync(LatestReleaseApiUrl, ct);
        string versionTag = string.Empty;
        string? downloadUrl = null;

        using (JsonDocument doc = JsonDocument.Parse(releaseJson))
        {
            JsonElement root = doc.RootElement;
            if (root.TryGetProperty("tag_name", out JsonElement tagElem) &&
                tagElem.ValueKind == JsonValueKind.String)
            {
                versionTag = tagElem.GetString() ?? string.Empty;
            }

            if (root.TryGetProperty("assets", out JsonElement assetsElem) &&
                assetsElem.ValueKind == JsonValueKind.Array)
            {
                foreach (JsonElement asset in assetsElem.EnumerateArray())
                {
                    string? name = asset.TryGetProperty("name", out JsonElement n) ? n.GetString() : null;
                    if (string.Equals(name, assetName, StringComparison.OrdinalIgnoreCase))
                    {
                        downloadUrl = asset.TryGetProperty("browser_download_url", out JsonElement url)
                            ? url.GetString()
                            : null;
                        break;
                    }
                }
            }
        }

        if (string.IsNullOrWhiteSpace(downloadUrl))
        {
            throw new InvalidOperationException($"未在 GitHub Release 中找到 {assetName} 下载资源。");
        }

        string tempZipPath = Path.Combine(coresDir, $"xray-download-{Guid.NewGuid():N}.zip");
        string targetExePath = AppPaths.GetDefaultXrayExePath(baseDir);
        string tempExePath = targetExePath + ".tmp";

        try
        {
            using (HttpResponseMessage resp = await http.GetAsync(downloadUrl, HttpCompletionOption.ResponseHeadersRead, ct))
            {
                resp.EnsureSuccessStatusCode();
                long? totalBytes = resp.Content.Headers.ContentLength;

                await using Stream netStream = await resp.Content.ReadAsStreamAsync(ct);
                await using var fileStream = new FileStream(tempZipPath, FileMode.Create, FileAccess.Write, FileShare.None, 81920, useAsync: true);

                byte[] buffer = new byte[81920];
                long received = 0;
                progress?.Report(new XrayDownloadProgress($"正在下载 {assetName} ({versionTag})...", 0, totalBytes));

                while (true)
                {
                    int read = await netStream.ReadAsync(buffer.AsMemory(0, buffer.Length), ct);
                    if (read <= 0) break;
                    await fileStream.WriteAsync(buffer.AsMemory(0, read), ct);
                    received += read;
                    progress?.Report(new XrayDownloadProgress($"正在下载 {assetName} ({versionTag})...", received, totalBytes));
                }
            }

            progress?.Report(new XrayDownloadProgress("正在解压 xray.exe...", 0, null));

            using (ZipArchive archive = ZipFile.OpenRead(tempZipPath))
            {
                ZipArchiveEntry? exeEntry = archive.Entries.FirstOrDefault(e =>
                    string.Equals(Path.GetFileName(e.FullName), AppPaths.XrayExecutableName, StringComparison.OrdinalIgnoreCase));
                if (exeEntry is null)
                {
                    throw new InvalidOperationException($"压缩包 {assetName} 中未包含 xray.exe。");
                }

                exeEntry.ExtractToFile(tempExePath, overwrite: true);
            }

            File.Move(tempExePath, targetExePath, overwrite: true);

            progress?.Report(new XrayDownloadProgress("正在校验 xray.exe 版本...", 0, null));
            string? detected = await DetectVersionAsync(targetExePath, ct);
            if (string.IsNullOrWhiteSpace(detected))
            {
                throw new InvalidOperationException("下载的 xray.exe 无法正常执行版本检查。");
            }

            return new XrayDownloadResult(targetExePath, versionTag, detected);
        }
        finally
        {
            try { if (File.Exists(tempZipPath)) File.Delete(tempZipPath); } catch { }
            try { if (File.Exists(tempExePath)) File.Delete(tempExePath); } catch { }
        }
    }
}

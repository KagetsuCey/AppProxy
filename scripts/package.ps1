[CmdletBinding()]
param(
    [string]$Version = "",
    [switch]$SkipNative,
    [switch]$SkipTests,
    [switch]$PortableOnly,
    [string]$IsccPath = ""
)

$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
Set-Location $Root

function Resolve-Version {
    param([string]$RequestedVersion)
    if (-not [string]::IsNullOrWhiteSpace($RequestedVersion)) {
        $trimmed = $RequestedVersion.Trim()
        if ($trimmed -notmatch '^\d+\.\d+\.\d+$') {
            throw "Invalid -Version '$trimmed'. Expected three-part numeric version like 1.0.0."
        }
        return $trimmed
    }

    $propsPath = Join-Path $Root "Directory.Build.props"
    if (Test-Path $propsPath) {
        [xml]$propsXml = Get-Content $propsPath -Raw
        $nodes = $propsXml.SelectNodes("//PropertyGroup/AppProxyVersion")
        foreach ($node in $nodes) {
            $v = "$($node.InnerText)".Trim()
            if ($v -match '^\d+\.\d+\.\d+$') {
                return $v
            }
        }
    }

    return "1.0.0"
}

function Resolve-MsBuildPath {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path $vswhere) {
        $found = & $vswhere -latest -products * -requires Microsoft.Component.MSBuild -find "MSBuild\**\Bin\MSBuild.exe" | Select-Object -First 1
        if (-not [string]::IsNullOrWhiteSpace($found) -and (Test-Path $found)) {
            return "$found".Trim()
        }
    }

    $cmd = Get-Command MSBuild.exe -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source -and (Test-Path $cmd.Source)) {
        return $cmd.Source
    }

    throw "MSBuild.exe not found. Run from an environment with Visual Studio 2022+ Build Tools / MSBuild."
}

function Copy-DirectoryMerged {
    param(
        [Parameter(Mandatory = $true)][string]$SourceDir,
        [Parameter(Mandatory = $true)][string]$DestDir
    )

    $sourceResolved = (Resolve-Path $SourceDir).Path.TrimEnd('\', '/')
    foreach ($file in [System.IO.Directory]::GetFiles($sourceResolved, "*", [System.IO.SearchOption]::AllDirectories)) {
        $rel = $file.Substring($sourceResolved.Length).TrimStart('\', '/')
        $target = Join-Path $DestDir $rel
        $targetParent = Split-Path -Path $target -Parent
        if (-not (Test-Path $targetParent)) {
            New-Item -ItemType Directory -Path $targetParent -Force | Out-Null
        }
        [System.IO.File]::Copy($file, $target, $true)
    }
}

function Get-IsccMajorVersion {
    param([string]$ExePath)
    try {
        $vi = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($ExePath)
        return [Math]::Max($vi.ProductMajorPart, $vi.FileMajorPart)
    }
    catch {
        return 0
    }
}

function Resolve-IsccPath {
    param([string]$ExplicitPath)

    if (-not [string]::IsNullOrWhiteSpace($ExplicitPath)) {
        if (-not (Test-Path $ExplicitPath)) {
            throw "Specified -IsccPath does not exist: $ExplicitPath"
        }
        $resolvedExplicit = (Resolve-Path $ExplicitPath).Path
        $major = Get-IsccMajorVersion -ExePath $resolvedExplicit
        if ($major -ge 1 -and $major -lt 7) {
            throw "Specified ISCC.exe ($resolvedExplicit) is major version $major, but installer\AppProxy.iss requires Inno Setup 7+."
        }
        return $resolvedExplicit
    }

    $candidates = @()
    if (-not [string]::IsNullOrWhiteSpace($env:INNO_SETUP_ISCC)) {
        $candidates += $env:INNO_SETUP_ISCC
    }
    $candidates += @(
        (Join-Path $Root "tools\InnoSetup7\ISCC.exe"),
        (Join-Path $Root "tools\InnoSetup\ISCC.exe"),
        (Join-Path $Root "third_party\InnoSetup\ISCC.exe")
    )
    if ($env:ProgramFiles) {
        $candidates += (Join-Path $env:ProgramFiles "Inno Setup 7\ISCC.exe")
    }
    if (${env:ProgramFiles(x86)}) {
        $candidates += (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 7\ISCC.exe")
    }
    if ($env:LOCALAPPDATA) {
        $candidates += (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 7\ISCC.exe")
    }

    foreach ($regKey in @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 7_is1",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 7_is1",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\Inno Setup 7_is1"
    )) {
        if (Test-Path $regKey) {
            try {
                $installLoc = (Get-ItemProperty -Path $regKey -ErrorAction SilentlyContinue).InstallLocation
                if (-not [string]::IsNullOrWhiteSpace($installLoc)) {
                    $candidates += (Join-Path $installLoc "ISCC.exe")
                }
            }
            catch {
            }
        }
    }

    if ($env:USERPROFILE) {
        $candidates += (Join-Path $env:USERPROFILE "scoop\apps\inno-setup\current\ISCC.exe")
        $candidates += (Join-Path $env:USERPROFILE "scoop\apps\innosetup\current\ISCC.exe")
    }
    $candidates += "C:\ProgramData\chocolatey\lib\InnoSetup\tools\ISCC.exe"

    $cmd = Get-Command ISCC.exe -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source -and (Test-Path $cmd.Source)) {
        $candidates += $cmd.Source
    }

    $foundLegacyPath = $null
    foreach ($candidate in $candidates) {
        if (-not [string]::IsNullOrWhiteSpace($candidate) -and (Test-Path $candidate)) {
            $resolved = (Resolve-Path $candidate).Path
            $major = Get-IsccMajorVersion -ExePath $resolved
            if ($major -eq 0 -or $major -ge 7) {
                return $resolved
            }
            if (-not $foundLegacyPath) {
                $foundLegacyPath = $resolved
            }
        }
    }

    if ($foundLegacyPath) {
        Write-Warning "Found older Inno Setup compiler at '$foundLegacyPath', but Inno Setup 7+ is required."
    }
    return $null
}

$AppVersion = Resolve-Version -RequestedVersion $Version
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " AppProxy Release Packaging (v$AppVersion win-x64)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# 1. Build Native Hook & Injector (x86 + x64 Release)
if (-not $SkipNative) {
    $msbuild = Resolve-MsBuildPath
    Write-Host "`n[1/6] Building Native Hook & Injector (Win32 & x64 Release)..." -ForegroundColor Yellow

    & $msbuild "src\native\AppProxy.Hook\AppProxy.Hook.vcxproj" /p:Configuration=Release /p:Platform=Win32 /m
    if ($LASTEXITCODE -ne 0) { throw "Native Hook (Win32) build failed." }

    & $msbuild "src\native\AppProxy.Injector\AppProxy.Injector.vcxproj" /p:Configuration=Release /p:Platform=Win32 /m
    if ($LASTEXITCODE -ne 0) { throw "Native Injector (Win32) build failed." }

    & $msbuild "src\native\AppProxy.Hook\AppProxy.Hook.vcxproj" /p:Configuration=Release /p:Platform=x64 /m
    if ($LASTEXITCODE -ne 0) { throw "Native Hook (x64) build failed." }

    & $msbuild "src\native\AppProxy.Injector\AppProxy.Injector.vcxproj" /p:Configuration=Release /p:Platform=x64 /m
    if ($LASTEXITCODE -ne 0) { throw "Native Injector (x64) build failed." }
}
else {
    Write-Host "`n[1/6] Skipping native build (-SkipNative)." -ForegroundColor DarkGray
}

# 2. Run Automated Tests
if (-not $SkipTests) {
    Write-Host "`n[2/6] Running Automated Tests (Release)..." -ForegroundColor Yellow
    & dotnet test "tests\AppProxy.Tests\AppProxy.Tests.csproj" -c Release
    if ($LASTEXITCODE -ne 0) { throw "dotnet test failed." }
}
else {
    Write-Host "`n[2/6] Skipping tests (-SkipTests)." -ForegroundColor DarkGray
}

# 3. Publish Self-Contained Bridge & UI (win-x64)
Write-Host "`n[3/6] Publishing Self-Contained win-x64 Bridge & UI..." -ForegroundColor Yellow

$publishRoot = Join-Path $Root "artifacts\publish"
$bridgePubDir = Join-Path $publishRoot "bridge"
$uiPubDir = Join-Path $publishRoot "ui"
$stageParent = Join-Path $Root "artifacts\package"
$stageDir = Join-Path $stageParent "AppProxy"
$releaseDir = Join-Path $Root "artifacts\release"

foreach ($dir in @($bridgePubDir, $uiPubDir, $stageDir)) {
    if (Test-Path $dir) {
        Remove-Item $dir -Recurse -Force
    }
}
New-Item -ItemType Directory -Path $bridgePubDir, $uiPubDir, $stageDir, $releaseDir -Force | Out-Null

& dotnet publish "src\AppProxy.Bridge\AppProxy.Bridge.csproj" `
    -c Release `
    -r win-x64 `
    --self-contained true `
    -p:DebugType=None `
    -p:DebugSymbols=false `
    -p:AppProxyVersion=$AppVersion `
    -o $bridgePubDir
if ($LASTEXITCODE -ne 0) { throw "dotnet publish AppProxy.Bridge failed." }

& dotnet publish "src\AppProxy.UI\AppProxy.UI.csproj" `
    -c Release `
    -r win-x64 `
    --self-contained true `
    -p:DebugType=None `
    -p:DebugSymbols=false `
    -p:SkipCopyBridgeOnBuild=true `
    -p:AppProxyVersion=$AppVersion `
    -o $uiPubDir
if ($LASTEXITCODE -ne 0) { throw "dotnet publish AppProxy.UI failed." }

# 4. Assemble Clean Staging Folder (Shared .NET 8 Runtime + Native x86/x64)
Write-Host "`n[4/6] Assembling Clean Staging Directory..." -ForegroundColor Yellow

Copy-DirectoryMerged -SourceDir $bridgePubDir -DestDir $stageDir
Copy-DirectoryMerged -SourceDir $uiPubDir -DestDir $stageDir

$stageNativeDir = Join-Path $stageDir "native"
New-Item -ItemType Directory -Path $stageNativeDir -Force | Out-Null

$nativeBinaries = @(
    (Join-Path $Root "artifacts\bin\x64\Release\AppProxy.Hook.x64.dll"),
    (Join-Path $Root "artifacts\bin\x64\Release\AppProxy.Injector.x64.exe"),
    (Join-Path $Root "artifacts\bin\Win32\Release\AppProxy.Hook.x86.dll"),
    (Join-Path $Root "artifacts\bin\Win32\Release\AppProxy.Injector.x86.exe")
)

foreach ($bin in $nativeBinaries) {
    if (-not (Test-Path $bin)) {
        throw "Required native binary missing: $bin. Run without -SkipNative or build Win32+x64 Release first."
    }
    Copy-Item -Path $bin -Destination $stageNativeDir -Force
}

# Remove debug symbols and any unintended dev/runtime data files from package staging
Get-ChildItem -Path $stageDir -Recurse -Filter "*.pdb" -File | Remove-Item -Force
Get-ChildItem -Path $stageDir -Recurse -Filter "*.log" -File | Remove-Item -Force
foreach ($strayPath in @(
    (Join-Path $stageDir "config.json"),
    (Join-Path $stageDir "data"),
    (Join-Path $stageDir "profiles")
)) {
    if (Test-Path $strayPath) {
        Remove-Item -Path $strayPath -Recurse -Force
    }
}

$requiredStageFiles = @(
    "AppProxy.UI.exe",
    "AppProxy.UI.dll",
    "AppProxy.UI.deps.json",
    "AppProxy.UI.runtimeconfig.json",
    "AppProxy.Bridge.exe",
    "AppProxy.Bridge.dll",
    "AppProxy.Bridge.deps.json",
    "AppProxy.Bridge.runtimeconfig.json",
    "AppProxy.Core.dll",
    "coreclr.dll",
    "hostfxr.dll",
    "hostpolicy.dll",
    "native\AppProxy.Hook.x64.dll",
    "native\AppProxy.Injector.x64.exe",
    "native\AppProxy.Hook.x86.dll",
    "native\AppProxy.Injector.x86.exe"
)

foreach ($rel in $requiredStageFiles) {
    $full = Join-Path $stageDir $rel
    if (-not (Test-Path $full)) {
        throw "Staging verification failed; missing expected file: $full"
    }
}

# 5. Create Portable ZIP Archive
Write-Host "`n[5/6] Creating Portable ZIP Archive..." -ForegroundColor Yellow

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$zipName = "AppProxy-v$AppVersion-win-x64-portable.zip"
$zipPath = Join-Path $releaseDir $zipName
if (Test-Path $zipPath) {
    Remove-Item $zipPath -Force
}

[System.IO.Compression.ZipFile]::CreateFromDirectory(
    $stageDir,
    $zipPath,
    [System.IO.Compression.CompressionLevel]::Optimal,
    $true
)

Write-Host "Portable ZIP created: $zipPath" -ForegroundColor Green

# 6. Compile Inno Setup 7 Installer (.exe)
$setupName = "AppProxy-v$AppVersion-win-x64-setup.exe"
$setupPath = Join-Path $releaseDir $setupName
$builtSetup = $false

if (-not $PortableOnly) {
    Write-Host "`n[6/6] Building Inno Setup 7 Installer..." -ForegroundColor Yellow
    $resolvedIscc = Resolve-IsccPath -ExplicitPath $IsccPath
    $issPath = Join-Path $Root "installer\AppProxy.iss"

    if (-not $resolvedIscc) {
        Write-Warning "ISCC.exe (Inno Setup 7) not found. Portable ZIP succeeded, but installer .exe was skipped."
        Write-Host "To build the installer, install Inno Setup 7 via one of:" -ForegroundColor Cyan
        Write-Host "  winget install --id JRSoftware.InnoSetup.7 -e -s winget" -ForegroundColor White
        Write-Host "  scoop install inno-setup" -ForegroundColor White
        Write-Host "  or place portable Inno Setup 7 at: $(Join-Path $Root 'tools\InnoSetup7\ISCC.exe')" -ForegroundColor White
    }
    else {
        if (Test-Path $setupPath) {
            Remove-Item $setupPath -Force
        }
        Write-Host "Using ISCC (Inno Setup 7): $resolvedIscc"
        & $resolvedIscc "/DMyAppVersion=$AppVersion" "/DSourceDir=$stageDir" "/DOutputDir=$releaseDir" "$issPath"
        if ($LASTEXITCODE -ne 0) {
            throw "ISCC.exe installer build failed with exit code $LASTEXITCODE."
        }
        if (-not (Test-Path $setupPath)) {
            throw "Installer compilation completed cleanly, but output file was not found at $setupPath"
        }
        $builtSetup = $true
        Write-Host "Installer EXE created: $setupPath" -ForegroundColor Green
    }
}
else {
    Write-Host "`n[6/6] Skipping installer build (-PortableOnly)." -ForegroundColor DarkGray
}

# Compute SHA-256 checksums for produced artifacts
$releaseFiles = @($zipPath)
if ($builtSetup) {
    $releaseFiles += $setupPath
}

[string[]]$hashLines = @(foreach ($file in $releaseFiles) {
    $h = Get-FileHash -Path $file -Algorithm SHA256
    "$($h.Hash.ToLowerInvariant()) *$([System.IO.Path]::GetFileName($file))"
})
$sumsPath = Join-Path $releaseDir "SHA256SUMS.txt"
[System.IO.File]::WriteAllLines($sumsPath, $hashLines, [System.Text.UTF8Encoding]::new($false))

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " Packaging Summary" -ForegroundColor Cyan
Write-Host "  Staging Dir : $stageDir"
Write-Host "  Portable ZIP: $zipPath"
if ($builtSetup) {
    Write-Host "  Installer   : $setupPath"
}
else {
    Write-Host "  Installer   : SKIPPED (install Inno Setup 7 or run with -IsccPath)"
}
Write-Host "  SHA-256 Sums: $sumsPath"
Write-Host "========================================" -ForegroundColor Cyan

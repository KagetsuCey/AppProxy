@echo off
setlocal enabledelayedexpansion

set "ROOT=%~dp0.."
cd /d "%ROOT%"

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" (
    echo [ERROR] vswhere.exe not found. Please run this from a Developer Command Prompt for VS 2022.
    exit /b 1
)

for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.Component.MSBuild -find MSBuild\**\Bin\MSBuild.exe`) do (
    set "MSBUILD=%%i"
)

if "%MSBUILD%"=="" (
    echo [ERROR] MSBuild.exe not found in Visual Studio installation.
    exit /b 1
)

echo Using MSBuild: "%MSBUILD%"

echo.
echo [1/4] Building Native Hook & Injector (x86)...
"%MSBUILD%" src\native\AppProxy.Hook\AppProxy.Hook.vcxproj /p:Configuration=Release /p:Platform=Win32 /m || exit /b 1
"%MSBUILD%" src\native\AppProxy.Injector\AppProxy.Injector.vcxproj /p:Configuration=Release /p:Platform=Win32 /m || exit /b 1

echo.
echo [2/4] Building Native Hook & Injector (x64)...
"%MSBUILD%" src\native\AppProxy.Hook\AppProxy.Hook.vcxproj /p:Configuration=Release /p:Platform=x64 /m || exit /b 1
"%MSBUILD%" src\native\AppProxy.Injector\AppProxy.Injector.vcxproj /p:Configuration=Release /p:Platform=x64 /m || exit /b 1

echo.
echo [3/4] Restoring and Building C# WPF UI (.NET 8)...
dotnet build src\AppProxy.UI\AppProxy.UI.csproj -c Release || exit /b 1

echo.
echo [4/4] Running Automated Tests...
dotnet test tests\AppProxy.Tests\AppProxy.Tests.csproj -c Release || exit /b 1

echo.
echo Build & Test succeeded!
echo Output UI executable: src\AppProxy.UI\bin\Release\net8.0-windows\AppProxy.UI.exe
endlocal

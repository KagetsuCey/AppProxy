; Inno Setup 7 installer script for AppProxy (native 64-bit Setup engine)
; Default installation targets current user (%LocalAppData%\Programs\AppProxy) without UAC so app-relative "data\" stays writable.
; Users can customize the install folder or switch to all-users installation via the setup mode dialog.

#ifndef MyAppVersion
  #define MyAppVersion "1.0.0"
#endif

#ifndef SourceDir
  #define SourceDir "..\artifacts\package\AppProxy"
#endif

#ifndef OutputDir
  #define OutputDir "..\artifacts\release"
#endif

[Setup]
AppId={{B8F4C7A2-4C19-4E53-9B6D-2A8E7F103C41}
AppName=AppProxy
AppVersion={#MyAppVersion}
AppVerName=AppProxy {#MyAppVersion}
AppPublisher=AppProxy
VersionInfoVersion={#MyAppVersion}.0
VersionInfoProductName=AppProxy
VersionInfoProductVersion={#MyAppVersion}.0
VersionInfoDescription=AppProxy Windows Application Proxy Launcher
DefaultDirName={autopf}\AppProxy
DefaultGroupName=AppProxy
AllowNoIcons=yes
DisableProgramGroupPage=yes
DisableDirPage=no
DirExistsWarning=no
UsePreviousAppDir=yes
UsePreviousPrivileges=yes
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
SetupArchitecture=x64
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutputDir}
OutputBaseFilename=AppProxy-v{#MyAppVersion}-win-x64-setup
SetupIconFile=..\src\AppProxy.UI\Assets\AppProxy.ico
UninstallDisplayIcon={app}\AppProxy.UI.exe
UninstallDisplayName=AppProxy
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern dynamic windows11
ShowLanguageDialog=auto
CloseApplications=yes
CloseApplicationsFilter=*.exe,*.dll
RestartApplications=no
ChangesEnvironment=no

[Languages]
#if FileExists(AddBackslash(CompilerPath) + "Languages\ChineseSimplified.isl")
Name: "chinesesimplified"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"
#endif
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "{#SourceDir}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Dirs]
Name: "{app}\data"; Check: not IsAdminInstallMode
Name: "{app}\data\profiles"; Check: not IsAdminInstallMode
Name: "{app}\data\logs"; Check: not IsAdminInstallMode
Name: "{app}\data"; Permissions: users-modify; Check: IsAdminInstallMode
Name: "{app}\data\profiles"; Permissions: users-modify; Check: IsAdminInstallMode
Name: "{app}\data\logs"; Permissions: users-modify; Check: IsAdminInstallMode

[Icons]
Name: "{autoprograms}\AppProxy"; Filename: "{app}\AppProxy.UI.exe"
Name: "{autodesktop}\AppProxy"; Filename: "{app}\AppProxy.UI.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\AppProxy.UI.exe"; Description: "{cm:LaunchProgram,AppProxy}"; Flags: nowait postinstall skipifsilent

[Code]
function CmdLineParamExists(const Param: string): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do
  begin
    if CompareText(ParamStr(I), Param) = 0 then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: string;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    DataDir := ExpandConstant('{app}\data');
    if DirExists(DataDir) then
    begin
      if CmdLineParamExists('/PURGEDATA') or
         ((not UninstallSilent) and
          (MsgBox(
            'Do you also want to delete saved AppProxy user data (configuration, isolated browser profiles, and crash logs in "data")?' + #13#10 + #13#10 + DataDir,
            mbConfirmation,
            MB_YESNO or MB_DEFBUTTON2) = IDYES)) then
      begin
        DelTree(DataDir, True, True, True);
        RemoveDir(ExpandConstant('{app}'));
      end;
    end;
  end;
end;

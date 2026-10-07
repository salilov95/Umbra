; Inno Setup 6 script. Build it with build_installer.bat (it passes the version).
; Installs for the current user only: no administrator rights are needed.
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif

[Setup]
AppId={{8C1B6C0E-6C7B-4B67-9E6A-5D2F0C6E7A11}
AppName=Umbra
AppVersion={#AppVersion}
AppPublisher=Umbra
DefaultDirName={localappdata}\Programs\Umbra
DefaultGroupName=Umbra
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
OutputDir=..\dist
OutputBaseFilename=Umbra-Setup-{#AppVersion}
SetupIconFile=..\assets\icon.ico
UninstallDisplayIcon={app}\Umbra.exe
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
; An update is installed over a running copy: ask to close it first.
CloseApplications=yes
RestartApplications=no

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"

[Files]
Source: "..\dist\Umbra.exe"; DestDir: "{app}"; Flags: ignoreversion
; The Xray core, if build_exe.bat has put it into dist\core (works offline then).
Source: "..\dist\core\*"; DestDir: "{app}\core"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
Name: "{group}\Umbra"; Filename: "{app}\Umbra.exe"
Name: "{autodesktop}\Umbra"; Filename: "{app}\Umbra.exe"; Tasks: desktopicon

[Run]
Filename: "{app}\Umbra.exe"; Description: "{cm:LaunchProgram,Umbra}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Never leave the Windows proxy pointing at a program that is no longer there.
Filename: "{app}\Umbra.exe"; Parameters: "--restore-proxy"; Flags: runhidden; RunOnceId: "RestoreProxy"

[Registry]
; Remove our "start with Windows" entry on uninstall (the app creates it itself).
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: none; ValueName: "Umbra"; Flags: dontcreatekey uninsdeletevalue

#define MyAppName "eID Reader"
#define MyAppVersion "1.1.0"
#define MyAppPublisher "Sophia"
#define MyAppExeName "eid-reader.exe"

[Setup]
AppId={{A4D03DBC-E7F1-4F76-B527-C4B2B6F666A2}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
OutputDir=installer
OutputBaseFilename=eid-reader-setup
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "target\release\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion
Source: "C:\Windows\System32\beidpkcs11.dll"; DestDir: "{sys}"; Flags: ignoreversion onlyifdoesntexist uninsneveruninstall

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"

[Tasks]
Name: "startupicon"; Description: "Start eID Reader automatically when Windows starts"; GroupDescription: "Windows Startup"

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "eID Reader"; ValueData: """{app}\{#MyAppExeName}"" --address 127.0.0.1"; Flags: uninsdeletevalue; Tasks: startupicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Parameters: "--address 127.0.0.1"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent 
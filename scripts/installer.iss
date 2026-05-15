; ============================================================================
;  TIME Coin Wallet - Inno Setup Installer Script
;
;  Prerequisites:
;    1. Install Inno Setup 6 from https://jrsoftware.org/isdl.php
;    2. Build the wallet:  cargo build --release
;    3. Compile this script:
;       - Open in Inno Setup Compiler and press Ctrl+F9, or
;       - Command line: iscc.exe scripts\installer.iss
;
;  Output: installer\TIMECoinWallet-Setup-{version}.exe
; ============================================================================

#define MyAppName      "TIME Coin Wallet"
#define MyAppVersion   "0.6.7"
#define MyAppPublisher "TIME Coin Contributors"
#define MyAppURL       "https://time-coin.io"
#define MyAppExeName   "time-wallet.exe"

[Setup]
AppId={{B8A3F1D2-7E4C-4A9B-8D5F-1C6E2F3A4B5D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
OutputDir=..\installer
OutputBaseFilename=TIMECoinWallet-Setup-{#MyAppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
#ifexist "..\wallet-gui\assets\logo.ico"
SetupIconFile=..\wallet-gui\assets\logo.ico
#endif
UninstallDisplayIcon={app}\{#MyAppExeName}
WizardStyle=modern
DisableWelcomePage=no
LicenseFile=..\LICENSE

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Main executable
Source: "..\target\release\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

; Assets
Source: "..\wallet-gui\assets\*"; DestDir: "{app}\assets"; Flags: ignoreversion recursesubdirs createallsubdirs

; Documentation
Source: "..\README.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\LICENSE"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Start Menu
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\{cm:UninstallProgram,{#MyAppName}}"; Filename: "{uninstallexe}"

; Desktop (optional)
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; Offer to launch after install
Filename: "{app}\{#MyAppExeName}"; Description: "{cm:LaunchProgram,{#StringChange(MyAppName, '&', '&&')}}"; Flags: nowait postinstall skipifsilent

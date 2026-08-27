; Inno Setup script for PrivateFirewall — a signed, single-file Windows installer.
; This app controls the Windows firewall, so it installs machine-wide and
; ELEVATES (admin). Ships the engine exe, the PowerShell tooling, the dashboard,
; and the QuickOpen Root CA. Compiled and Authenticode-signed in CI.
;
; Expects packaging\staging\ to hold: PrivateFirewall.exe, *.ps1, Install.cmd,
; dashboard.html, README.md, FEATURES.md, LICENSE, quickopen-root.crt.

#define AppName "PrivateFirewall"
#define AppVersion "1.0.12"
#define AppPublisher "QuickOpen (quickopen.ai)"
#define AppURL "https://quickopen.ai/projects/private-firewall"

[Setup]
AppMutex=QuickOpen.PrivateFirewall
AppId={{C4E1F2A9-7B63-4D5E-9A1C-2F8B0D3E4A61}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
DefaultDirName={autopf}\PrivateFirewall
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\PrivateFirewall.exe
; unins000.exe ships UNSIGNED by default, and on a machine with Smart App
; Control or a WDAC policy enforcing, Windows refuses to load it: the Uninstall
; button in Settings fails with CodeIntegrity 3077/3033 and WinError 4551,
; leaving the app impossible to remove through the normal route.
;
; Inno writes that binary on the USER'S machine at install time from a template
; baked into the installer, so no later signing hop can reach it - COMPILE time
; is the only moment it can be signed, which is what SignedUninstaller=yes does.
; That needs a SignTool where ISCC runs, so the ISCC step moved onto the signing
; machine (2026-08-21). ISCC signs uninst.e32, then the setup exe.
;
; Guarded by #ifdef so this same .iss still compiles anywhere without the token
; (CI, a laptop) - just unsigned. publish/scripts/compile-windows-installer.sh
; passes /DSIGNED_UNINSTALLER and defines the "quickopen" SignTool.
#ifdef SIGNED_UNINSTALLER
SignTool=quickopen
SignedUninstaller=yes
#endif
OutputDir=dist
OutputBaseFilename=PrivateFirewall-Setup
SetupIconFile=..\private-firewall.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
WizardImageFile=branding\wizard-large.bmp
WizardSmallImageFile=branding\wizard-small.bmp
AppCopyright=Apache-2.0. 100%% AI-built, published on QuickOpen (quickopen.ai).
VersionInfoCompany=QuickOpen
VersionInfoProductName=PrivateFirewall
VersionInfoVersion=1.0.12.0
; Firewall control requires administrator rights.
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
WelcomeLabel2=PrivateFirewall is a 100%% AI-built, open-source control plane and intrusion-alert dashboard for the Windows firewall, published on QuickOpen (quickopen.ai).%n%nIt runs entirely on this PC and needs administrator rights to manage the firewall.
BeveledLabel=QuickOpen · quickopen.ai

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"
Name: "trustca"; Description: "Trust the QuickOpen Root CA (lets Windows verify QuickOpen signatures)"; GroupDescription: "Security:"; Flags: unchecked
Name: "bootlockdown"; Description: "Enforce default-deny-outbound at boot (persistent firewall lockdown). Advanced — you can undo this anytime from the app or Revert-PrivateFirewall.ps1."; GroupDescription: "Firewall:"; Flags: unchecked

[Files]
Source: "staging\PrivateFirewall.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "staging\dashboard.html"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "staging\*.ps1"; DestDir: "{app}"; Flags: ignoreversion
Source: "staging\Install.cmd"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "staging\quickopen-root.crt"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "staging\README.md"; DestDir: "{app}"; Flags: ignoreversion isreadme skipifsourcedoesntexist
Source: "staging\FEATURES.md"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "staging\LICENSE"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist

[Icons]
Name: "{group}\PrivateFirewall"; Filename: "{app}\PrivateFirewall.exe"; IconFilename: "{app}\PrivateFirewall.exe"
Name: "{group}\Uninstall PrivateFirewall"; Filename: "{uninstallexe}"
Name: "{autodesktop}\PrivateFirewall"; Filename: "{app}\PrivateFirewall.exe"; IconFilename: "{app}\PrivateFirewall.exe"; Tasks: desktopicon

[Run]
Filename: "certutil.exe"; Parameters: "-addstore Root ""{app}\quickopen-root.crt"""; Tasks: trustca; Flags: runhidden; StatusMsg: "Trusting the QuickOpen Root CA..."
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Install-PrivateFirewall.ps1"" -BootLockdown"; Tasks: bootlockdown; Flags: runhidden; StatusMsg: "Arming boot-time default-deny outbound..."
; shellexec is REQUIRED here, not cosmetic. PrivateFirewall.exe is built with
; --uac-admin (requireAdministrator in its manifest) because it drives the
; Windows firewall. Inno runs a `postinstall` entry as the ORIGINAL,
; non-elevated user, and CreateProcess refuses to start an elevation-requiring
; image from a non-elevated caller — that is exactly "CreateProcess failed;
; code 740. The requested operation requires elevation." ShellExecuteEx (what
; shellexec uses) reads the manifest and raises the UAC consent prompt instead,
; which is the same thing that happens when the user double-clicks the Start
; menu shortcut. Any future QuickOpen app built with --uac-admin needs this.
Filename: "{app}\PrivateFirewall.exe"; Description: "Launch PrivateFirewall now (Windows will ask for administrator rights)"; Flags: nowait postinstall skipifsilent shellexec

[UninstallRun]
; Tear down the firewall rules, scheduled tasks and boot lockdown this app added.
Filename: "powershell.exe"; Parameters: "-NoProfile -ExecutionPolicy Bypass -File ""{app}\Revert-PrivateFirewall.ps1"" -Revert -Uninstall"; Flags: runhidden skipifdoesntexist; RunOnceId: "PfwRevert"

[UninstallDelete]
Type: filesandordirs; Name: "{commonappdata}\PrivateFirewall"

[Code]
// On uninstall, offer to also remove the QuickOpen Root CA (opt-in; other
// QuickOpen apps may rely on it).

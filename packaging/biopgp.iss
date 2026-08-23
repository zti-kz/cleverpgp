#ifndef AppVersion
  #define AppVersion "0.6.0"
#endif
#ifndef AppSourceDirectory
  #error AppSourceDirectory must be defined by build_installer.ps1
#endif
#ifndef WinFspInstaller
  #error WinFspInstaller must be defined by build_installer.ps1
#endif
#ifndef WinSpdInstaller
  #error WinSpdInstaller must be defined by build_installer.ps1
#endif
#ifndef ReleaseDirectory
  #error ReleaseDirectory must be defined by build_installer.ps1
#endif
#ifndef ProjectDirectory
  #error ProjectDirectory must be defined by build_installer.ps1
#endif

#define AppName "Clever PGP"
#define AppExecutable "CleverPGP.exe"
#define AppPublisher "Almas Oskenbay"
#define AppCopyright "Almas Oskenbay, Institute of Intellectual Technologies"
#define AppId "{{9CA87C0D-5BA5-47E6-A52F-9935E8A51DFB}"

[Setup]
AppId={#AppId}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\Clever PGP
DefaultGroupName=Clever PGP
DisableProgramGroupPage=yes
UninstallDisplayIcon={app}\{#AppExecutable}
OutputDir={#ReleaseDirectory}
OutputBaseFilename=Clever-PGP-Setup-{#AppVersion}
SetupIconFile=..\assets\biopgp.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
WizardSizePercent=120
PrivilegesRequired=admin
SetupArchitecture=x64
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=force
RestartApplications=no
ChangesAssociations=yes
VersionInfoVersion={#AppVersion}.0
VersionInfoCompany={#AppPublisher}
VersionInfoProductName={#AppName}
VersionInfoDescription=Установщик Clever PGP
VersionInfoCopyright=Copyright (C) 2026 {#AppCopyright}

[Languages]
Name: "russian"; MessagesFile: "compiler:Languages\Russian.isl"

[Tasks]
Name: "desktopicon"; Description: "Создать ярлык на рабочем столе"; GroupDescription: "Дополнительные значки:"; Flags: unchecked

[Files]
Source: "{#AppSourceDirectory}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#ProjectDirectory}\LICENSE"; DestDir: "{app}"; DestName: "LICENSE.txt"; Flags: ignoreversion
Source: "{#ProjectDirectory}\THIRD_PARTY_NOTICES.md"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#ProjectDirectory}\LICENSE"; DestDir: "{app}\Source"; Flags: ignoreversion
Source: "{#ProjectDirectory}\THIRD_PARTY_NOTICES.md"; DestDir: "{app}\Source"; Flags: ignoreversion
Source: "{#ProjectDirectory}\README.md"; DestDir: "{app}\Source"; Flags: ignoreversion
Source: "{#ProjectDirectory}\pyproject.toml"; DestDir: "{app}\Source"; Flags: ignoreversion
Source: "{#ProjectDirectory}\.gitignore"; DestDir: "{app}\Source"; Flags: ignoreversion
Source: "{#ProjectDirectory}\*.ps1"; DestDir: "{app}\Source"; Flags: ignoreversion
Source: "{#ProjectDirectory}\*.cmd"; DestDir: "{app}\Source"; Flags: ignoreversion
Source: "{#ProjectDirectory}\src\*"; DestDir: "{app}\Source\src"; Excludes: "__pycache__\*,*.pyc"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#ProjectDirectory}\tests\*"; DestDir: "{app}\Source\tests"; Excludes: "__pycache__\*,*.pyc"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#ProjectDirectory}\docs\*"; DestDir: "{app}\Source\docs"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#ProjectDirectory}\scripts\*"; DestDir: "{app}\Source\scripts"; Excludes: "__pycache__\*,*.pyc"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#ProjectDirectory}\packaging\*"; DestDir: "{app}\Source\packaging"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#ProjectDirectory}\assets\*"; DestDir: "{app}\Source\assets"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#ProjectDirectory}\models\licenses\*"; DestDir: "{app}\Source\models\licenses"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#WinFspInstaller}"; DestDir: "{tmp}"; DestName: "winfsp-biopgp.msi"; Flags: ignoreversion deleteafterinstall
Source: "{#WinSpdInstaller}"; DestDir: "{tmp}"; DestName: "winspd-cleverpgp.msi"; Flags: ignoreversion deleteafterinstall

[InstallDelete]
Type: files; Name: "{app}\BioPGP.exe"
Type: files; Name: "{autoprograms}\BioPGP.lnk"
Type: files; Name: "{autodesktop}\BioPGP.lnk"

[Icons]
Name: "{autoprograms}\Clever PGP"; Filename: "{app}\{#AppExecutable}"; WorkingDir: "{app}"
Name: "{autodesktop}\Clever PGP"; Filename: "{app}\{#AppExecutable}"; WorkingDir: "{app}"; Tasks: desktopicon

[Registry]
Root: HKLM; Subkey: "Software\Classes\*\shell\BioPGP.Encrypt"; ValueType: none; Flags: deletekey
Root: HKLM; Subkey: "Software\Classes\BioPGP.EncryptedFile"; ValueType: none; Flags: deletekey
Root: HKLM; Subkey: "Software\Classes\BioPGP.ContainerFile"; ValueType: none; Flags: deletekey
Root: HKLM; Subkey: "Software\Classes\Drive\shell\CleverPGP.Unmount"; ValueType: none; Flags: deletekey
Root: HKLM; Subkey: "Software\Classes\.bpgp"; ValueType: none; Flags: deletekey
Root: HKLM; Subkey: "Software\Classes\.bpgv"; ValueType: none; Flags: deletekey
Root: HKLM; Subkey: "Software\Classes\*\shell\CleverPGP.Encrypt"; ValueType: string; ValueName: ""; ValueData: "Зашифровать с Clever PGP"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\*\shell\CleverPGP.Encrypt"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExecutable},0"
Root: HKLM; Subkey: "Software\Classes\*\shell\CleverPGP.Encrypt"; ValueType: string; ValueName: "MultiSelectModel"; ValueData: "Single"
Root: HKLM; Subkey: "Software\Classes\*\shell\CleverPGP.Encrypt\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#AppExecutable}"" --shell encrypt ""%1"""
Root: HKLM; Subkey: "Software\Classes\.cpgp"; ValueType: string; ValueName: ""; ValueData: "CleverPGP.EncryptedFile"; Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\Classes\.cpgp"; ValueType: string; ValueName: "Content Type"; ValueData: "application/x-clever-pgp"; Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\Classes\CleverPGP.EncryptedFile"; ValueType: string; ValueName: ""; ValueData: "Зашифрованный файл Clever PGP"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\CleverPGP.EncryptedFile\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\{#AppExecutable},0"
Root: HKLM; Subkey: "Software\Classes\CleverPGP.EncryptedFile\shell\open"; ValueType: string; ValueName: ""; ValueData: "Расшифровать с Clever PGP"
Root: HKLM; Subkey: "Software\Classes\CleverPGP.EncryptedFile\shell\open"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExecutable},0"
Root: HKLM; Subkey: "Software\Classes\CleverPGP.EncryptedFile\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#AppExecutable}"" --shell decrypt ""%1"""
Root: HKLM; Subkey: "Software\Classes\.cpgv"; ValueType: string; ValueName: ""; ValueData: "CleverPGP.ContainerFile"; Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\Classes\.cpgv"; ValueType: string; ValueName: "Content Type"; ValueData: "application/x-clever-pgp-container"; Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\Classes\CleverPGP.ContainerFile"; ValueType: string; ValueName: ""; ValueData: "Зашифрованный диск Clever PGP"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\CleverPGP.ContainerFile\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\{#AppExecutable},0"
Root: HKLM; Subkey: "Software\Classes\CleverPGP.ContainerFile\shell\open"; ValueType: string; ValueName: ""; ValueData: "Подключить зашифрованный диск"
Root: HKLM; Subkey: "Software\Classes\CleverPGP.ContainerFile\shell\open"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExecutable},0"
Root: HKLM; Subkey: "Software\Classes\CleverPGP.ContainerFile\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#AppExecutable}"" --container ""%1"""
Root: HKLM; Subkey: "Software\Classes\Drive\shell\CleverPGP.Menu"; ValueType: string; ValueName: "MUIVerb"; ValueData: "Clever PGP"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\Drive\shell\CleverPGP.Menu"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExecutable},0"
Root: HKLM; Subkey: "Software\Classes\Drive\shell\CleverPGP.Menu"; ValueType: string; ValueName: "AppliesTo"; ValueData: "System.Volume.FileSystem:=""FUSE"""
Root: HKLM; Subkey: "Software\Classes\Drive\shell\CleverPGP.Menu"; ValueType: string; ValueName: "SubCommands"; ValueData: ""
Root: HKLM; Subkey: "Software\Classes\Drive\shell\CleverPGP.Menu\shell\Open"; ValueType: string; ValueName: "MUIVerb"; ValueData: "Открыть зашифрованный диск"
Root: HKLM; Subkey: "Software\Classes\Drive\shell\CleverPGP.Menu\shell\Open"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExecutable},0"
Root: HKLM; Subkey: "Software\Classes\Drive\shell\CleverPGP.Menu\shell\Open\command"; ValueType: string; ValueName: ""; ValueData: """{sys}\explorer.exe"" ""%1"""
Root: HKLM; Subkey: "Software\Classes\Drive\shell\CleverPGP.Menu\shell\Info"; ValueType: string; ValueName: "MUIVerb"; ValueData: "Сведения о диске"
Root: HKLM; Subkey: "Software\Classes\Drive\shell\CleverPGP.Menu\shell\Info"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExecutable},0"
Root: HKLM; Subkey: "Software\Classes\Drive\shell\CleverPGP.Menu\shell\Info\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#AppExecutable}"" --disk-info ""%1"""
Root: HKLM; Subkey: "Software\Classes\Drive\shell\CleverPGP.Menu\shell\Unmount"; ValueType: string; ValueName: "MUIVerb"; ValueData: "Отключить зашифрованный диск"
Root: HKLM; Subkey: "Software\Classes\Drive\shell\CleverPGP.Menu\shell\Unmount"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExecutable},0"
Root: HKLM; Subkey: "Software\Classes\Drive\shell\CleverPGP.Menu\shell\Unmount"; ValueType: dword; ValueName: "CommandFlags"; ValueData: "$00000020"
Root: HKLM; Subkey: "Software\Classes\Drive\shell\CleverPGP.Menu\shell\Unmount\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#AppExecutable}"" --unmount ""%1"""

[Run]
Filename: "{sys}\msiexec.exe"; Parameters: "/i ""{tmp}\winfsp-biopgp.msi"" /passive /norestart"; StatusMsg: "Устанавливается компонент виртуального диска..."; Flags: waituntilterminated; Check: not IsWinFspInstalled
Filename: "{sys}\msiexec.exe"; Parameters: "/i ""{tmp}\winspd-cleverpgp.msi"" /passive /norestart"; StatusMsg: "Устанавливается компонент системного диска..."; Flags: waituntilterminated; Check: not IsWinSpdInstalled
Filename: "{app}\{#AppExecutable}"; Description: "Запустить Clever PGP"; Flags: nowait postinstall skipifsilent runasoriginaluser

[Code]
function IsWinFspInstalled: Boolean;
var
  InstallDirectory: String;
begin
  Result :=
    RegQueryStringValue(HKLM32, 'SOFTWARE\WinFsp', 'InstallDir', InstallDirectory) or
    RegQueryStringValue(HKLM64, 'SOFTWARE\WinFsp', 'InstallDir', InstallDirectory);
  if Result then
    Result := FileExists(AddBackslash(InstallDirectory) + 'bin\winfsp-x64.dll');
end;

function IsWinSpdInstalled: Boolean;
var
  InstallDirectory: String;
begin
  Result :=
    RegQueryStringValue(HKLM32, 'SOFTWARE\WinSpd', 'InstallDir', InstallDirectory) or
    RegQueryStringValue(HKLM64, 'SOFTWARE\WinSpd', 'InstallDir', InstallDirectory);
  if Result then
    Result := FileExists(AddBackslash(InstallDirectory) + 'sys\winspd-x64.dll');
end;

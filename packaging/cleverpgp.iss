#ifndef AppVersion
  #define AppVersion "0.13.8"
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
SetupIconFile=..\assets\cleverpgp.ico
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
Source: "{#WinFspInstaller}"; DestDir: "{tmp}"; DestName: "winfsp-cleverpgp.msi"; Flags: ignoreversion deleteafterinstall
Source: "{#WinSpdInstaller}"; DestDir: "{tmp}"; DestName: "winspd-cleverpgp.msi"; Flags: ignoreversion deleteafterinstall

[InstallDelete]
Type: files; Name: "{app}\BioPGP.exe"
Type: files; Name: "{autoprograms}\BioPGP.lnk"
Type: files; Name: "{autodesktop}\BioPGP.lnk"
Type: files; Name: "{autoprograms}\Clever PGP.lnk"
Type: filesandordirs; Name: "{app}\Source"

[Icons]
Name: "{group}\Clever PGP"; Filename: "{app}\{#AppExecutable}"; WorkingDir: "{app}"
Name: "{group}\Удалить Clever PGP"; Filename: "{app}\{#AppExecutable}"; Parameters: "--launch-uninstaller"; IconFilename: "{app}\{#AppExecutable}"; Comment: "Удалить Clever PGP с этого компьютера"
Name: "{autodesktop}\Clever PGP"; Filename: "{app}\{#AppExecutable}"; WorkingDir: "{app}"; Tasks: desktopicon

[Registry]
Root: HKLM; Subkey: "Software\Classes\*\shell\BioPGP.Encrypt"; ValueType: none; Flags: deletekey
Root: HKLM; Subkey: "Software\Classes\BioPGP.EncryptedFile"; ValueType: none; Flags: deletekey
Root: HKLM; Subkey: "Software\Classes\BioPGP.ContainerFile"; ValueType: none; Flags: deletekey
Root: HKLM; Subkey: "Software\Classes\Drive\shell\CleverPGP.Unmount"; ValueType: none; Flags: deletekey
Root: HKLM; Subkey: "Software\Classes\Drive\shell\CleverPGP.Menu"; ValueType: none; Flags: deletekey
Root: HKLM; Subkey: "Software\Classes\.bpgp"; ValueType: none; Flags: deletekey
Root: HKLM; Subkey: "Software\Classes\.bpgv"; ValueType: none; Flags: deletekey
Root: HKLM; Subkey: "Software\Classes\*\shell\CleverPGP.Encrypt"; ValueType: string; ValueName: ""; ValueData: "Зашифровать с Clever PGP"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\*\shell\CleverPGP.Encrypt"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExecutable},0"
Root: HKLM; Subkey: "Software\Classes\*\shell\CleverPGP.Encrypt"; ValueType: string; ValueName: "MultiSelectModel"; ValueData: "Single"
Root: HKLM; Subkey: "Software\Classes\*\shell\CleverPGP.Encrypt"; ValueType: string; ValueName: "AppliesTo"; ValueData: "NOT System.FileExtension:=.cpgp AND NOT System.FileExtension:=.cpgv AND NOT System.FileExtension:=.cpgk"
Root: HKLM; Subkey: "Software\Classes\*\shell\CleverPGP.Encrypt\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#AppExecutable}"" --encrypt-file ""%1"""
Root: HKLM; Subkey: "Software\Classes\.cpgp"; ValueType: string; ValueName: ""; ValueData: "CleverPGP.EncryptedFile"; Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\Classes\.cpgp"; ValueType: string; ValueName: "Content Type"; ValueData: "application/x-clever-pgp"; Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\Classes\CleverPGP.EncryptedFile"; ValueType: string; ValueName: ""; ValueData: "Зашифрованный файл Clever PGP"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\CleverPGP.EncryptedFile\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\{#AppExecutable},0"
Root: HKLM; Subkey: "Software\Classes\CleverPGP.EncryptedFile\shell\open"; ValueType: string; ValueName: ""; ValueData: "Расшифровать с Clever PGP"
Root: HKLM; Subkey: "Software\Classes\CleverPGP.EncryptedFile\shell\open"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExecutable},0"
Root: HKLM; Subkey: "Software\Classes\CleverPGP.EncryptedFile\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#AppExecutable}"" --decrypt-file ""%1"""
Root: HKLM; Subkey: "Software\Classes\.cpgk"; ValueType: string; ValueName: ""; ValueData: "CleverPGP.PublicKey"; Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\Classes\.cpgk"; ValueType: string; ValueName: "Content Type"; ValueData: "application/x-clever-pgp-public-key"; Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\Classes\CleverPGP.PublicKey"; ValueType: string; ValueName: ""; ValueData: "Открытый ключ Clever PGP"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\CleverPGP.PublicKey\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\{#AppExecutable},0"
Root: HKLM; Subkey: "Software\Classes\CleverPGP.PublicKey\shell\open"; ValueType: string; ValueName: ""; ValueData: "Импортировать открытый ключ"
Root: HKLM; Subkey: "Software\Classes\CleverPGP.PublicKey\shell\open"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExecutable},0"
Root: HKLM; Subkey: "Software\Classes\CleverPGP.PublicKey\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#AppExecutable}"" --import-key ""%1"""
Root: HKLM; Subkey: "Software\Classes\.cpgv"; ValueType: string; ValueName: ""; ValueData: "CleverPGP.ContainerFile"; Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\Classes\.cpgv"; ValueType: string; ValueName: "Content Type"; ValueData: "application/x-clever-pgp-container"; Flags: uninsdeletevalue
Root: HKLM; Subkey: "Software\Classes\CleverPGP.ContainerFile"; ValueType: string; ValueName: ""; ValueData: "Зашифрованный диск Clever PGP"; Flags: uninsdeletekey
Root: HKLM; Subkey: "Software\Classes\CleverPGP.ContainerFile\DefaultIcon"; ValueType: string; ValueName: ""; ValueData: "{app}\{#AppExecutable},0"
Root: HKLM; Subkey: "Software\Classes\CleverPGP.ContainerFile\shell\open"; ValueType: string; ValueName: ""; ValueData: "Подключить зашифрованный диск"
Root: HKLM; Subkey: "Software\Classes\CleverPGP.ContainerFile\shell\open"; ValueType: string; ValueName: "Icon"; ValueData: "{app}\{#AppExecutable},0"
Root: HKLM; Subkey: "Software\Classes\CleverPGP.ContainerFile\shell\open\command"; ValueType: string; ValueName: ""; ValueData: """{app}\{#AppExecutable}"" --container ""%1"""
[Run]
Filename: "{sys}\msiexec.exe"; Parameters: "/i ""{tmp}\winfsp-cleverpgp.msi"" /passive /norestart"; StatusMsg: "Устанавливается компонент виртуального диска..."; Flags: waituntilterminated; Check: not IsWinFspInstalled
Filename: "{sys}\msiexec.exe"; Parameters: "/i ""{tmp}\winspd-cleverpgp.msi"" /passive /norestart"; StatusMsg: "Устанавливается компонент виртуального диска..."; Flags: waituntilterminated; Check: not IsWinSpdInstalled
Filename: "{app}\{#AppExecutable}"; Parameters: "--set-language {code:SelectedAppLanguage}"; StatusMsg: "Сохраняется язык Clever PGP..."; Flags: runhidden waituntilterminated runasoriginaluser
Filename: "{app}\{#AppExecutable}"; Description: "Запустить Clever PGP"; Flags: nowait postinstall skipifsilent runasoriginaluser

[Code]
var
  RemoveLocalProfile: Boolean;
  AppLanguagePage: TInputOptionWizardPage;

procedure InitializeWizard;
begin
  AppLanguagePage := CreateInputOptionPage(
    wpSelectTasks,
    'Язык Clever PGP',
    'Выберите язык интерфейса программы',
    'Русский язык выбран по умолчанию. Язык можно изменить позже в настройках Clever PGP.',
    True,
    True
  );
  AppLanguagePage.Add('Русский');
  AppLanguagePage.Add('Қазақша');
  AppLanguagePage.Add('English');
  case GetPreviousData('AppLanguage', '') of
    'kk': AppLanguagePage.SelectedValueIndex := 1;
    'en': AppLanguagePage.SelectedValueIndex := 2;
  else
    AppLanguagePage.SelectedValueIndex := 0;
  end;
end;

function SelectedAppLanguage(Param: String): String;
begin
  case AppLanguagePage.SelectedValueIndex of
    1: Result := 'kk';
    2: Result := 'en';
  else
    Result := 'ru';
  end;
end;

procedure RegisterPreviousData(PreviousDataKey: Integer);
begin
  SetPreviousData(
    PreviousDataKey,
    'AppLanguage',
    SelectedAppLanguage('')
  );
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  UninstallKey: String;
  LauncherCommand: String;
begin
  if CurStep <> ssPostInstall then
    exit;
  UninstallKey := 'Software\Microsoft\Windows\CurrentVersion\Uninstall\' +
    '{9CA87C0D-5BA5-47E6-A52F-9935E8A51DFB}_is1';
  LauncherCommand := '"' + ExpandConstant('{app}\{#AppExecutable}') +
    '" --launch-uninstaller';
  RegWriteStringValue(HKLM64, UninstallKey, 'UninstallString', LauncherCommand);
end;

function ProfilePathForUninstall(Param: String): String;
begin
  Result := ExpandConstant('{param:PROFILEPATH|}');
  if Result = '' then
    Result := ExpandConstant('{localappdata}\CleverPGP');
end;

function InitializeUninstall(): Boolean;
var
  Choice: Integer;
  ShutdownResult: Integer;
  PurgeResult: Integer;
  ProfilePath: String;
begin
  if FileExists(ExpandConstant('{app}\{#AppExecutable}')) then
  begin
    if
      (not Exec(
        ExpandConstant('{app}\{#AppExecutable}'),
        '--shutdown-for-uninstall',
        ExpandConstant('{app}'),
        SW_HIDE,
        ewWaitUntilTerminated,
        ShutdownResult
      )) or
      (ShutdownResult <> 0)
    then
    begin
      MsgBox(
        'Не удалось завершить Clever PGP. ' +
        'Дождитесь окончания текущей операции и повторите удаление.',
        mbError,
        MB_OK
      );
      Result := False;
      exit;
    end;
  end;
  Choice := MsgBox(
    'Удалить локальный профиль Clever PGP?' + #13#10 + #13#10 +
    'Да — удалить профиль, настройки, биометрические данные и локальные ключи.' + #13#10 +
    'Нет — сохранить их для последующей переустановки.' + #13#10 +
    'Файлы .cpgp и диски .cpgv не удаляются.',
    mbConfirmation,
    MB_YESNOCANCEL
  );
  if Choice = IDCANCEL then
  begin
    Result := False;
    exit;
  end;
  RemoveLocalProfile := Choice = IDYES;
  if RemoveLocalProfile then
  begin
    ProfilePath := ProfilePathForUninstall('');
    if
      (not Exec(
        ExpandConstant('{app}\{#AppExecutable}'),
        '--purge-local-profile "' + ProfilePath + '"',
        ExpandConstant('{app}'),
        SW_HIDE,
        ewWaitUntilTerminated,
        PurgeResult
      )) or
      (PurgeResult <> 0) or
      DirExists(ProfilePath)
    then
    begin
      MsgBox(
        'Локальный профиль не удалось удалить. ' +
        'Удаление программы остановлено, чтобы вы могли повторить операцию.',
        mbError,
        MB_OK
      );
      Result := False;
      exit;
    end;
  end;
  Result := True;
end;

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

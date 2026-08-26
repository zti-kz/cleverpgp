$ErrorActionPreference = "Stop"
$ProjectDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$PythonWindowed = Join-Path $ProjectDirectory ".venv\Scripts\pythonw.exe"

if (-not (Test-Path -LiteralPath $PythonWindowed -PathType Leaf)) {
    throw "Не найден pythonw.exe проекта. Сначала выполните .\setup.ps1"
}

$ClassesRoot = "HKCU:\Software\Classes"
$EncryptVerb = Join-Path $ClassesRoot "*\shell\CleverPGP.Encrypt"
$DecryptVerb = Join-Path $ClassesRoot "*\shell\CleverPGP.Decrypt"
$SecureDeleteVerb = Join-Path $ClassesRoot "*\shell\CleverPGP.SecureDelete"
$EncryptedExtension = Join-Path $ClassesRoot ".cpgp"
$EncryptedType = Join-Path $ClassesRoot "CleverPGP.EncryptedFile"
$PublicKeyExtension = Join-Path $ClassesRoot ".cpgk"
$PublicKeyType = Join-Path $ClassesRoot "CleverPGP.PublicKey"
$PrivateKeyExtension = Join-Path $ClassesRoot ".cpgx"
$PrivateKeyType = Join-Path $ClassesRoot "CleverPGP.PrivateKey"
$ContainerExtension = Join-Path $ClassesRoot ".cpgv"
$ContainerType = Join-Path $ClassesRoot "CleverPGP.ContainerFile"
$LegacyUnmountVerb = Join-Path $ClassesRoot "Drive\shell\CleverPGP.Unmount"
$DriveMenu = Join-Path $ClassesRoot "Drive\shell\CleverPGP.Menu"

New-Item -Path $EncryptVerb -Force | Out-Null
Set-Item -Path $EncryptVerb -Value "Зашифровать с Clever PGP"
New-ItemProperty -Path $EncryptVerb -Name "Icon" -Value $PythonWindowed -PropertyType String -Force | Out-Null
New-ItemProperty -Path $EncryptVerb -Name "MultiSelectModel" -Value "Single" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $EncryptVerb -Name "AppliesTo" -Value 'NOT System.FileExtension:=".cpgp" AND NOT System.FileExtension:=".cpgv" AND NOT System.FileExtension:=".cpgk" AND NOT System.FileExtension:=".cpgx"' -PropertyType String -Force | Out-Null
$EncryptCommand = New-Item -Path (Join-Path $EncryptVerb "command") -Force
Set-Item -Path $EncryptCommand.PSPath -Value "`"$PythonWindowed`" -m cleverpgp --shell encrypt `"%1`""

New-Item -Path $DecryptVerb -Force | Out-Null
Set-Item -Path $DecryptVerb -Value "Расшифровать файл — Clever PGP"
New-ItemProperty -Path $DecryptVerb -Name "Icon" -Value $PythonWindowed -PropertyType String -Force | Out-Null
New-ItemProperty -Path $DecryptVerb -Name "MultiSelectModel" -Value "Single" -PropertyType String -Force | Out-Null
New-ItemProperty -Path $DecryptVerb -Name "AppliesTo" -Value 'System.FileExtension:=".cpgp"' -PropertyType String -Force | Out-Null
$DirectDecryptCommand = New-Item -Path (Join-Path $DecryptVerb "command") -Force
Set-Item -Path $DirectDecryptCommand.PSPath -Value "`"$PythonWindowed`" -m cleverpgp --shell decrypt `"%1`""

New-Item -Path $SecureDeleteVerb -Force | Out-Null
Set-Item -Path $SecureDeleteVerb -Value "Безвозвратно удалить файл — Clever PGP"
New-ItemProperty -Path $SecureDeleteVerb -Name "Icon" -Value $PythonWindowed -PropertyType String -Force | Out-Null
New-ItemProperty -Path $SecureDeleteVerb -Name "MultiSelectModel" -Value "Single" -PropertyType String -Force | Out-Null
$SecureDeleteCommand = New-Item -Path (Join-Path $SecureDeleteVerb "command") -Force
Set-Item -Path $SecureDeleteCommand.PSPath -Value "`"$PythonWindowed`" -m cleverpgp --secure-delete `"%1`""

New-Item -Path $EncryptedExtension -Force | Out-Null
Set-Item -Path $EncryptedExtension -Value "CleverPGP.EncryptedFile"
New-ItemProperty -Path $EncryptedExtension -Name "Content Type" -Value "application/x-clever-pgp" -PropertyType String -Force | Out-Null

New-Item -Path $EncryptedType -Force | Out-Null
Set-Item -Path $EncryptedType -Value "Зашифрованный файл Clever PGP"
$DefaultIcon = New-Item -Path (Join-Path $EncryptedType "DefaultIcon") -Force
Set-Item -Path $DefaultIcon.PSPath -Value $PythonWindowed
$OpenVerb = New-Item -Path (Join-Path $EncryptedType "shell\open") -Force
Set-Item -Path $OpenVerb.PSPath -Value "Расшифровать с Clever PGP"
New-ItemProperty -Path $OpenVerb.PSPath -Name "Icon" -Value $PythonWindowed -PropertyType String -Force | Out-Null
$DecryptCommand = New-Item -Path (Join-Path $OpenVerb.PSPath "command") -Force
Set-Item -Path $DecryptCommand.PSPath -Value "`"$PythonWindowed`" -m cleverpgp --shell decrypt `"%1`""

New-Item -Path $PublicKeyExtension -Force | Out-Null
Set-Item -Path $PublicKeyExtension -Value "CleverPGP.PublicKey"
New-ItemProperty -Path $PublicKeyExtension -Name "Content Type" -Value "application/x-clever-pgp-public-key" -PropertyType String -Force | Out-Null

New-Item -Path $PublicKeyType -Force | Out-Null
Set-Item -Path $PublicKeyType -Value "Открытый ключ Clever PGP"
$PublicKeyIcon = New-Item -Path (Join-Path $PublicKeyType "DefaultIcon") -Force
Set-Item -Path $PublicKeyIcon.PSPath -Value $PythonWindowed
$ImportVerb = New-Item -Path (Join-Path $PublicKeyType "shell\open") -Force
Set-Item -Path $ImportVerb.PSPath -Value "Импортировать открытый ключ"
New-ItemProperty -Path $ImportVerb.PSPath -Name "Icon" -Value $PythonWindowed -PropertyType String -Force | Out-Null
$ImportCommand = New-Item -Path (Join-Path $ImportVerb.PSPath "command") -Force
Set-Item -Path $ImportCommand.PSPath -Value "`"$PythonWindowed`" -m cleverpgp --import-key `"%1`""

New-Item -Path $PrivateKeyExtension -Force | Out-Null
Set-Item -Path $PrivateKeyExtension -Value "CleverPGP.PrivateKey"
New-ItemProperty -Path $PrivateKeyExtension -Name "Content Type" -Value "application/x-clever-pgp-private-key" -PropertyType String -Force | Out-Null
New-Item -Path $PrivateKeyType -Force | Out-Null
Set-Item -Path $PrivateKeyType -Value "Защищённый закрытый ключ Clever PGP"
$PrivateKeyIcon = New-Item -Path (Join-Path $PrivateKeyType "DefaultIcon") -Force
Set-Item -Path $PrivateKeyIcon.PSPath -Value $PythonWindowed
$PrivateImportVerb = New-Item -Path (Join-Path $PrivateKeyType "shell\open") -Force
Set-Item -Path $PrivateImportVerb.PSPath -Value "Импортировать закрытый ключ"
New-ItemProperty -Path $PrivateImportVerb.PSPath -Name "Icon" -Value $PythonWindowed -PropertyType String -Force | Out-Null
$PrivateImportCommand = New-Item -Path (Join-Path $PrivateImportVerb.PSPath "command") -Force
Set-Item -Path $PrivateImportCommand.PSPath -Value "`"$PythonWindowed`" -m cleverpgp --import-private-key `"%1`""

New-Item -Path $ContainerExtension -Force | Out-Null
Set-Item -Path $ContainerExtension -Value "CleverPGP.ContainerFile"
New-ItemProperty -Path $ContainerExtension -Name "Content Type" -Value "application/x-clever-pgp-container" -PropertyType String -Force | Out-Null

New-Item -Path $ContainerType -Force | Out-Null
Set-Item -Path $ContainerType -Value "Зашифрованный диск Clever PGP"
$ContainerIcon = New-Item -Path (Join-Path $ContainerType "DefaultIcon") -Force
Set-Item -Path $ContainerIcon.PSPath -Value $PythonWindowed
$MountVerb = New-Item -Path (Join-Path $ContainerType "shell\open") -Force
Set-Item -Path $MountVerb.PSPath -Value "Подключить зашифрованный диск"
New-ItemProperty -Path $MountVerb.PSPath -Name "Icon" -Value $PythonWindowed -PropertyType String -Force | Out-Null
$MountCommand = New-Item -Path (Join-Path $MountVerb.PSPath "command") -Force
Set-Item -Path $MountCommand.PSPath -Value "`"$PythonWindowed`" -m cleverpgp --container `"%1`""

foreach ($LegacyDriveVerb in @($LegacyUnmountVerb, $DriveMenu)) {
    if (Test-Path -LiteralPath $LegacyDriveVerb) {
        Remove-Item -LiteralPath $LegacyDriveVerb -Recurse -Force
    }
}

Add-Type -Namespace CleverPGP -Name ShellNotify -MemberDefinition @"
[System.Runtime.InteropServices.DllImport("shell32.dll")]
public static extern void SHChangeNotify(int eventId, uint flags, System.IntPtr item1, System.IntPtr item2);
"@
[CleverPGP.ShellNotify]::SHChangeNotify(0x08000000, 0, [IntPtr]::Zero, [IntPtr]::Zero)

Write-Host "Контекстное меню и ассоциации Clever PGP установлены для текущего пользователя."
Write-Host "В Windows 11 команда может находиться в разделе 'Показать дополнительные параметры'."

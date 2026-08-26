$ErrorActionPreference = "Stop"
$ClassesRoot = "HKCU:\Software\Classes"
$Targets = @(
    (Join-Path $ClassesRoot "*\shell\CleverPGP.Encrypt"),
    (Join-Path $ClassesRoot "*\shell\CleverPGP.Decrypt"),
    (Join-Path $ClassesRoot "*\shell\CleverPGP.SecureDelete"),
    (Join-Path $ClassesRoot ".cpgp"),
    (Join-Path $ClassesRoot "CleverPGP.EncryptedFile"),
    (Join-Path $ClassesRoot ".cpgk"),
    (Join-Path $ClassesRoot "CleverPGP.PublicKey"),
    (Join-Path $ClassesRoot ".cpgx"),
    (Join-Path $ClassesRoot "CleverPGP.PrivateKey"),
    (Join-Path $ClassesRoot ".cpgv"),
    (Join-Path $ClassesRoot "CleverPGP.ContainerFile"),
    (Join-Path $ClassesRoot "Drive\shell\CleverPGP.Unmount"),
    (Join-Path $ClassesRoot "Drive\shell\CleverPGP.Menu")
)

foreach ($Target in $Targets) {
    if (Test-Path -LiteralPath $Target) {
        Remove-Item -LiteralPath $Target -Recurse -Force
    }
}

Add-Type -Namespace CleverPGP -Name ShellNotify -MemberDefinition @"
[System.Runtime.InteropServices.DllImport("shell32.dll")]
public static extern void SHChangeNotify(int eventId, uint flags, System.IntPtr item1, System.IntPtr item2);
"@
[CleverPGP.ShellNotify]::SHChangeNotify(0x08000000, 0, [IntPtr]::Zero, [IntPtr]::Zero)

Write-Host "Контекстное меню и ассоциации .cpgp/.cpgk/.cpgx/.cpgv удалены для текущего пользователя."

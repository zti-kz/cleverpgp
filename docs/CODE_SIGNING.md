# Цифровая подпись Windows

Clever PGP проверяет каждый Portable Executable (PE) в собранном приложении.
Уже существующие доверенные подписи поставщиков сохраняются, а каждый неподписанный
EXE, DLL и нативный модуль подписывается до упаковки. Затем отдельно подписывается
готовый установщик. Подписи используют SHA-256 и доверенную метку времени RFC 3161.
Закрытый ключ или данные доступа к облачной службе не сохраняются в исходном коде,
настройках проекта или GitHub.

## Сертификат издателя

Для публичных Windows-выпусков нужен сертификат Public Trust, цепочка которого
заканчивается доверенным корневым центром Microsoft. Сборка поддерживает два
равноправных варианта: Microsoft Artifact Signing (прежнее название Trusted
Signing) и сертификат Code Signing от внешнего удостоверяющего центра.

Закреплённое имя издателя:

```text
Almas Oskenbay
```

Имя в сертификате должно совпадать с официальным латинским написанием в документе,
который проверил центр сертификации. `Institute of Intellectual Technologies`
остаётся в авторских сведениях программы, но не добавляется в субъект сертификата,
пока институт не подтверждён как отдельное юридическое лицо или зарегистрированное
наименование.

Самоподписанный сертификат нельзя применять к публичному установщику: Windows не
доверяет ему на компьютерах пользователей.

## Microsoft Artifact Signing

Служба не требует USB-токена: закрытый ключ остаётся в управляемой Microsoft
среде. До сборки необходимо создать в Azure учётную запись Artifact Signing,
пройти проверку личности или организации, создать профиль Public Trust и назначить
сборочной учётной записи роль `Artifact Signing Certificate Profile Signer`.

На 27 августа 2026 года Microsoft предоставляет Public Trust организациям только
из перечисленных в документации стран; Казахстан в этот список не входит. Для
каталога Azure также обязательна действующая подписка. Профиль Private Trust нельзя
использовать для публичного установщика Microsoft Store, поскольку его цепочка не
является общедоверенной на компьютерах пользователей. Если юридическое лицо и
платёжный профиль Azure находятся в Казахстане, следует использовать сертификат
внешнего удостоверяющего центра из Microsoft Trusted Root Program.

Официальные инструкции Microsoft:

- [настройка Artifact Signing](https://learn.microsoft.com/azure/artifact-signing/quickstart);
- [подключение SignTool](https://learn.microsoft.com/azure/artifact-signing/how-to-signing-integrations).

Клиентские средства устанавливаются официальным пакетом Microsoft:

```powershell
winget install -e --id Microsoft.Azure.ArtifactSigningClientTools
```

Создайте локальный `metadata.json`, который не добавляется в Git:

```json
{
  "Endpoint": "https://<region>.codesigning.azure.net/",
  "CodeSigningAccountName": "<account-name>",
  "CertificateProfileName": "<profile-name>"
}
```

После входа через Azure CLI или настройки служебной учётной записи задайте пути:

```powershell
$env:CLEVERPGP_ARTIFACT_SIGNING_DLIB = `
  "C:\Program Files (x86)\Microsoft\ArtifactSigningClientTools\bin\Azure.CodeSigning.Dlib.dll"
$env:CLEVERPGP_ARTIFACT_SIGNING_METADATA = "C:\Secure\cleverpgp-signing-metadata.json"
$env:CLEVERPGP_SIGN_EXPECTED_NAME = "Almas Oskenbay"
.\build_installer.ps1 -OutputDirectory "E:\Clever\_PGP"
```

Сборка проверяет, что endpoint использует домен `codesigning.azure.net`, а после
каждой операции проверяет доверие подписи, имя издателя и метку времени Microsoft.

## Параметры Microsoft Store

Для EXE-установщика Clever PGP в Partner Center указываются:

```text
Архитектура: x64
Параметры тихой установки: /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP-
Код успешной установки: 0
```

Флажок «установщик работает в тихом режиме без параметров» включать нельзя.
Каждая новая подписанная сборка получает новый номер версии и новый неизменяемый
HTTPS-адрес. После замены файла, параметров тихой установки или подписи необходимо
повторно запустить проверку пакета в Partner Center.

## Сертификат внешнего удостоверяющего центра

1. Для облачного варианта Certum установить SimplySign Desktop и активировать
   виртуальную карту. Для физического варианта установить программное обеспечение
   предоставленного токена.
2. Подключить SimplySign или токен и убедиться, что сертификат появился в личном
   хранилище сертификатов Windows текущего пользователя или компьютера.
3. Получить отпечаток сертификата без закрытого ключа:

```powershell
Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My |
    Where-Object { $_.EnhancedKeyUsageList.ObjectId.Value -contains "1.3.6.1.5.5.7.3.3" } |
    Select-Object Subject, Thumbprint, NotAfter, HasPrivateKey
```

PIN облачной карты или токена не записывается в переменные, файлы или историю
команд. Его следует вводить только в защищённом окне программного обеспечения
Certum при подписи.

## Подписанная сборка

Для сертификата из хранилища Windows достаточно указать отпечаток:

```powershell
$env:CLEVERPGP_SIGN_CERT_SHA1 = "40-ЗНАЧНЫЙ-ОТПЕЧАТОК-БЕЗ-ПРОБЕЛОВ"
.\build_installer.ps1 -OutputDirectory "E:\Clever\_PGP"
```

По умолчанию сборка находит 64-разрядный `signtool.exe` из Windows SDK и использует
официальный сервер метки времени Certum:

```text
http://time.certum.pl
```

Для сертификата другого центра эти значения можно переопределить:

```powershell
$env:CLEVERPGP_SIGNTOOL = "C:\Program Files (x86)\Windows Kits\10\bin\<версия>\x64\signtool.exe"
$env:CLEVERPGP_TIMESTAMP_URL = "АДРЕС_RFC3161_ОТ_ПОСТАВЩИКА"
```

До подписи сборка проверяет срок действия, наличие закрытого ключа, назначение
сертификата и точное имя издателя. После подписи она независимо проверяет цепочку
доверия Windows, издателя и наличие метки времени. При несовпадении выпуск
останавливается. Вместе с установщиком создаётся файл `.sha256`.

## Проверка готового выпуска

```powershell
Get-AuthenticodeSignature "E:\Clever\_PGP\Clever-PGP-Setup-0.13.1.exe" |
    Select-Object Status, StatusMessage, SignerCertificate, TimeStamperCertificate
```

Ожидаемый результат — состояние `Valid`, издатель `Almas Oskenbay` и заполненный
сертификат службы времени. Даже корректная новая подпись не гарантирует мгновенного
исчезновения предупреждений SmartScreen: репутация издателя формируется постепенно.

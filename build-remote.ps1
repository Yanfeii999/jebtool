param(
    [string]$GithubRawUrl = "",
    [switch]$UpdatePayloadOnly
)

$ErrorActionPreference = 'Stop'

$wsDir      = 'c:\Users\ADMIN\Documents\AD-Tool'
$ghDir      = Join-Path $wsDir 'github-release'
$relDir     = Join-Path $wsDir 'Jebtool-Release'
$ps1Path    = Join-Path $wsDir 'Jebtool.ps1'
$icoPath    = Join-Path $wsDir 'Jebtool.ico'
$tmplPath   = Join-Path $ghDir 'StubHost.tmpl.cs'
$cfgPath    = Join-Path $ghDir 'stub_strings.json'
$manifest   = Join-Path $ghDir 'jebtool.manifest'
$statePath  = Join-Path $ghDir 'build_secret.local.json'
$payloadOut = Join-Path $ghDir 'jebtool.bin'
$csc        = "$env:windir\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
$smaDll     = [System.Management.Automation.PowerShell].Assembly.Location

$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
function Get-RandBytes([int]$n) {
    $b = New-Object byte[] $n
    $rng.GetBytes($b)
    return ,$b
}
function Get-RandIdent([string]$prefix = '_0x') {
    $b = Get-RandBytes 4
    return $prefix + ([BitConverter]::ToString($b).Replace('-', '').ToLowerInvariant())
}

function Strip-PsComments([string]$path) {
    $tokens = $null; $errs = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errs)
    if ($errs.Count -gt 0) { throw "Jebtool.ps1 has $($errs.Count) parse errors!" }
    $raw = [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8)
    $cts = $tokens | Where-Object { $_.Kind -eq [System.Management.Automation.Language.TokenKind]::Comment } | Sort-Object { $_.Extent.StartOffset } -Descending
    $sb = New-Object System.Text.StringBuilder($raw)
    foreach ($ct in $cts) {
        $s = $ct.Extent.StartOffset; $l = $ct.Extent.EndOffset - $s
        if ($s -ge 0 -and ($s + $l) -le $sb.Length) { [void]$sb.Remove($s, $l) }
    }
    $stripped = $sb.ToString()
    $sErrs = $null
    [void][System.Management.Automation.Language.Parser]::ParseInput($stripped, [ref]$null, [ref]$sErrs)
    if ($sErrs.Count -gt 0) { return $raw }
    return $stripped
}

function Encrypt-RemotePayload([string]$scriptText, [byte[]]$masterRaw, [byte[]]$ilHash, [string]$outFile) {
    $plain = [System.Text.Encoding]::UTF8.GetBytes($scriptText)
    $msGz = New-Object System.IO.MemoryStream
    $gz = New-Object System.IO.Compression.GZipStream($msGz, [System.IO.Compression.CompressionMode]::Compress)
    $gz.Write($plain, 0, $plain.Length); $gz.Close()
    $comp = $msGz.ToArray(); $msGz.Dispose()

    $sha = [System.Security.Cryptography.SHA256]::Create()
    $eIn = New-Object byte[] (32 + $ilHash.Length + 2)
    [Buffer]::BlockCopy($masterRaw, 0, $eIn, 0, 32)
    [Buffer]::BlockCopy($ilHash, 0, $eIn, 32, $ilHash.Length)
    $eIn[32 + $ilHash.Length] = 0x45; $eIn[32 + $ilHash.Length + 1] = 0x33
    $ek = $sha.ComputeHash($eIn)

    $mIn = New-Object byte[] (32 + $ilHash.Length + 2)
    [Buffer]::BlockCopy($masterRaw, 0, $mIn, 0, 32)
    [Buffer]::BlockCopy($ilHash, 0, $mIn, 32, $ilHash.Length)
    $mIn[32 + $ilHash.Length] = 0x4D; $mIn[32 + $ilHash.Length + 1] = 0x33
    $mk = $sha.ComputeHash($mIn)
    $sha.Dispose()

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.KeySize = 256; $aes.Mode = 'CBC'; $aes.Padding = 'PKCS7'; $aes.Key = $ek; $aes.GenerateIV()
    $iv = $aes.IV
    $msEnc = New-Object System.IO.MemoryStream
    $cs = New-Object System.Security.Cryptography.CryptoStream($msEnc, $aes.CreateEncryptor(), [System.Security.Cryptography.CryptoStreamMode]::Write)
    $cs.Write($comp, 0, $comp.Length); $cs.FlushFinalBlock()
    $cipher = $msEnc.ToArray()
    $cs.Dispose(); $msEnc.Dispose(); $aes.Dispose()

    $macIn = New-Object byte[] (16 + $cipher.Length)
    [Buffer]::BlockCopy($iv, 0, $macIn, 0, 16)
    [Buffer]::BlockCopy($cipher, 0, $macIn, 16, $cipher.Length)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256(, $mk)
    $mac = $hmac.ComputeHash($macIn)
    $hmac.Dispose()

    $raw = New-Object byte[] (48 + $cipher.Length)
    [Buffer]::BlockCopy($iv, 0, $raw, 0, 16)
    [Buffer]::BlockCopy($mac, 0, $raw, 16, 32)
    [Buffer]::BlockCopy($cipher, 0, $raw, 48, $cipher.Length)

    # Apply outer transport XOR mask so GitHub file looks like pure opaque binary
    for ($i = 0; $i -lt $raw.Length; $i++) {
        $raw[$i] = [byte]($raw[$i] -bxor (($i * 37 + 0xA3) -band 0xFF))
    }
    [System.IO.File]::WriteAllBytes($outFile, $raw)
    Write-Host "[OK] Encrypted remote payload: $outFile ($($raw.Length) bytes)"
}

# Mode 1: Update jebtool.bin only (keeps existing Jebtool.exe working with zero rebuild!)
if ($UpdatePayloadOnly) {
    if (-not (Test-Path -LiteralPath $statePath)) {
        throw "Chưa có file $statePath. Hãy chạy build đầy đủ với -GithubRawUrl trước!"
    }
    $st = Get-Content -Raw $statePath | ConvertFrom-Json
    $masterRaw = [Convert]::FromBase64String($st.MasterB64)
    $ilHash    = [Convert]::FromBase64String($st.IlHashB64)
    $stripped  = Strip-PsComments $ps1Path
    Encrypt-RemotePayload $stripped $masterRaw $ilHash $payloadOut
    Write-Host "Xong! Chỉ cần upload lại file github-release\jebtool.bin lên GitHub Raw URL: $($st.GithubRawUrl)"
    exit 0
}

if ([string]::IsNullOrWhiteSpace($GithubRawUrl)) {
    $GithubRawUrl = "https://raw.githubusercontent.com/YOUR_USERNAME/YOUR_REPO/main/jebtool.bin"
    Write-Host "[LƯU Ý] Chưa truyền -GithubRawUrl, đang build mẫu với URL: $GithubRawUrl"
}

Write-Host "=== [1/3] Generating thin obfuscated Jebtool.exe stub (ZERO source code inside) ==="
$cfg = [System.IO.File]::ReadAllText($cfgPath, [System.Text.Encoding]::UTF8) | ConvertFrom-Json

$nsName   = Get-RandIdent '_0x'
$clsName  = Get-RandIdent '_0x'
$mDecStr  = Get-RandIdent '_0x'
$mAntiDbg = Get-RandIdent '_0x'
$mIlHash  = Get-RandIdent '_0x'
$mDerive  = Get-RandIdent '_0x'
$mFetch   = Get-RandIdent '_0x'
$mDecrypt = Get-RandIdent '_0x'

$masterRaw = Get-RandBytes 32
$mask1 = (Get-RandBytes 1)[0] -bor 0x11
$mask2 = (Get-RandBytes 1)[0] -bor 0x22
$p1Arr = (0..15 | ForEach-Object { "0x{0:X2}" -f ($masterRaw[$_] -bxor $mask1) }) -join ','
$p2Arr = (0..15 | ForEach-Object { "0x{0:X2}" -f ($masterRaw[16 + $_] -bxor $mask2) }) -join ','

function Make-EncStr([string]$s) {
    $utf8 = [System.Text.Encoding]::UTF8.GetBytes($s)
    $k = (Get-RandBytes 1)[0] -bor 0x05
    $enc = for ($i = 0; $i -lt $utf8.Length; $i++) {
        "0x{0:X2}" -f ($utf8[$i] -bxor $k -bxor (($i * 29 + 11) -band 0xFF))
    }
    return "$mDecStr(new byte[]{$($enc -join ',')}, 0x$('{0:X2}' -f $k))"
}

$blockedExprs = ($cfg.blocked | ForEach-Object { Make-EncStr ([string]$_) }) -join ",`r`n                "
$csCode = [System.IO.File]::ReadAllText($tmplPath, [System.Text.Encoding]::UTF8)
$reps = @{
    '__NS__'       = $nsName
    '__CLS__'      = $clsName
    '__DEC__'      = $mDecStr
    '__ADBG__'     = $mAntiDbg
    '__ILH__'      = $mIlHash
    '__DRV__'      = $mDerive
    '__FETCH__'    = $mFetch
    '__DECRYPT__'  = $mDecrypt
    '__P1__'       = $p1Arr
    '__P2__'       = $p2Arr
    '__M1__'       = ('0x{0:X2}' -f $mask1)
    '__M2__'       = ('0x{0:X2}' -f $mask2)
    '__BLOCKED__'  = $blockedExprs
    '__S_RAWURL__' = (Make-EncStr $GithubRawUrl)
}
foreach ($prop in $cfg.strings.PSObject.Properties) {
    $reps[$prop.Name] = (Make-EncStr ([string]$prop.Value))
}
foreach ($k in $reps.Keys) { $csCode = $csCode.Replace($k, $reps[$k]) }

$csOutPath = Join-Path $ghDir 'StubHost.generated.cs'
[System.IO.File]::WriteAllText($csOutPath, $csCode, (New-Object System.Text.UTF8Encoding($true)))

$exeOut = Join-Path $wsDir 'Jebtool.exe'
& $csc /nologo /target:winexe /optimize+ /debug- /platform:anycpu `
    "/out:$exeOut" `
    "/win32icon:$icoPath" `
    "/win32manifest:$manifest" `
    "/reference:$smaDll" `
    '/reference:System.Windows.Forms.dll' `
    '/reference:System.Drawing.dll' `
    $csOutPath
if ($LASTEXITCODE -ne 0) { throw "Failed to compile thin Jebtool.exe stub!" }
Remove-Item -LiteralPath $csOutPath -Force -ErrorAction SilentlyContinue
Write-Host "[OK] Compiled thin Jebtool.exe stub: $((Get-Item $exeOut).Length) bytes"

Write-Host "=== [2/3] Extracting exact IL SHA-256 hash from thin Jebtool.exe ==="
foreach ($dep in @('System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089', 'System.Windows.Forms, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089', 'System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a')) {
    try { [void][System.Reflection.Assembly]::ReflectionOnlyLoad($dep) } catch { }
}
try { [void][System.Reflection.Assembly]::ReflectionOnlyLoadFrom($smaDll) } catch { }
$asmBytes = [System.IO.File]::ReadAllBytes($exeOut)
$roAsm = [System.Reflection.Assembly]::ReflectionOnlyLoad($asmBytes)
$roType = $roAsm.GetType("$nsName.$clsName")
$ms = $roType.GetMethods([System.Reflection.BindingFlags]'Static,Public,NonPublic,DeclaredOnly') | Sort-Object MetadataToken
$accMs = New-Object System.IO.MemoryStream
foreach ($mInfo in $ms) {
    $mb = $mInfo.GetMethodBody()
    if ($null -ne $mb) {
        $ilb = $mb.GetILAsByteArray()
        if ($null -ne $ilb -and $ilb.Length -gt 0) { $accMs.Write($ilb, 0, $ilb.Length) }
    }
}
$shaTmp = [System.Security.Cryptography.SHA256]::Create()
$ilHash = $shaTmp.ComputeHash($accMs.ToArray())
$shaTmp.Dispose(); $accMs.Dispose()
Write-Host "[OK] IL SHA-256: $([BitConverter]::ToString($ilHash).Replace('-',''))"

Write-Host "=== [3/3] Encrypting Jebtool.ps1 -> github-release\jebtool.bin (upload this to GitHub!) ==="
$stripped = Strip-PsComments $ps1Path
Encrypt-RemotePayload $stripped $masterRaw $ilHash $payloadOut

# Update Jebtool-Release\Jebtool.exe
if (Test-Path -LiteralPath $relDir) {
    Copy-Item -LiteralPath $exeOut -Destination (Join-Path $relDir 'Jebtool.exe') -Force
    Unblock-File -LiteralPath (Join-Path $relDir 'Jebtool.exe') -ErrorAction SilentlyContinue
}

# Save local admin build state (NEVER upload build_secret.local.json to GitHub!)
@{
    GithubRawUrl = $GithubRawUrl
    MasterB64    = [Convert]::ToBase64String($masterRaw)
    IlHashB64    = [Convert]::ToBase64String($ilHash)
    Ns           = $nsName
    Cls          = $clsName
    Decrypt      = $mDecrypt
    StrippedLen  = $stripped.Length
} | ConvertTo-Json | Set-Content -Path $statePath -Encoding UTF8
Write-Host "DONE! Upload ONLY 'github-release\jebtool.bin' to your GitHub repo."

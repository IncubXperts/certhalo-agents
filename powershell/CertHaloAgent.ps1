<#
.SYNOPSIS
  CertHalo agent (Windows PowerShell 5.1 or PowerShell 7, no modules needed).

.DESCRIPTION
  Reads the TLS certificate each internal host presents and reports it to CertHalo, which grades it
  and alerts on it. Only certificates are ever sent, never keys. Report format: ../spec/report.schema.json.
  The chain reported is the one .NET builds for the server's certificate (it may include certificates
  from this machine's store); CertHalo judges trust itself.

.EXAMPLE
  $env:CERTHALO_API_KEY = "chk_..."   # an Agent key from CertHalo's Developers page
  .\CertHaloAgent.ps1 -Targets .\targets.txt

.EXAMPLE
  .\CertHaloAgent.ps1 -Targets .\targets.txt -DryRun
#>
[CmdletBinding()]
param(
  [string]$Targets = $(if ($env:CERTHALO_TARGETS) { $env:CERTHALO_TARGETS } else { "targets.txt" }),
  [string]$Url = $(if ($env:CERTHALO_URL) { $env:CERTHALO_URL } else { "https://certhalo.com" }),
  [string]$Name = $(if ($env:CERTHALO_AGENT_NAME) { $env:CERTHALO_AGENT_NAME } else { $env:COMPUTERNAME }),
  [ValidateRange(300, 604800)][int]$Interval = $(if ($env:CERTHALO_INTERVAL) { [int]$env:CERTHALO_INTERVAL } else { 21600 }),
  [int]$TimeoutSeconds = 10,
  [switch]$Loop,
  [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$Version = "1.0.0"
$MaxPerReport = 100   # CertHalo's limit per report
if (-not $Name) { $Name = [System.Net.Dns]::GetHostName() }
if ($Name.Length -gt 60) { $Name = $Name.Substring(0, 60) }
if (-not $env:CERTHALO_API_KEY -and -not $DryRun) {
  Write-Error "Set CERTHALO_API_KEY to an Agent key from CertHalo's Developers page."
  exit 1
}

# Captures the chain during the TLS handshake. Compiled C#, not a script block: .NET may run the
# certificate callback on another thread, where a PowerShell script block can deadlock.
if (-not ("CertHaloCapture" -as [type])) {
  Add-Type -TypeDefinition @"
using System.Collections.Generic;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
public static class CertHaloCapture {
  public static List<byte[]> Chain = new List<byte[]>();
  public static bool Accept(object sender, X509Certificate cert, X509Chain chain, SslPolicyErrors errors) {
    var found = new List<byte[]>();
    if (chain != null) foreach (var el in chain.ChainElements) found.Add(el.Certificate.RawData);
    if (found.Count == 0 && cert != null) found.Add(cert.GetRawCertData());
    Chain = found;
    return true; // CertHalo judges the chain, so untrusted ones must still be reported
  }
}
"@
}

function ConvertTo-Target([string]$Line) {
  $s = ($Line -replace '^(https|tls)://', '').Split('/')[0]
  if ($s -match '^\[(.+)\](?::(\d+))?$') { return @{ host = $Matches[1]; port = $(if ($Matches[2]) { [int]$Matches[2] } else { 443 }) } }
  $ip = $null
  if ([System.Net.IPAddress]::TryParse($s, [ref]$ip) -and $ip.AddressFamily -eq 'InterNetworkV6') { return @{ host = $s; port = 443 } }
  $parts = $s.Split(':')
  $port = if ($parts.Count -gt 1) { [int]$parts[1] } else { 443 }
  if ($port -lt 1 -or $port -gt 65535) { throw "bad port in '$s'" }
  return @{ host = $parts[0]; port = $port }
}

function Read-Targets([string]$Path) {
  $list = @()
  $n = 0
  foreach ($raw in Get-Content -LiteralPath $Path) {
    $n++
    $line = ($raw -split '#', 2)[0].Trim()
    if (-not $line) { continue }
    try { $list += ConvertTo-Target $line } catch { throw "$Path line ${n}: $_" }
  }
  if ($list.Count -eq 0) { throw "$Path lists no hosts" }
  return $list
}

function ConvertTo-Pem([byte[]]$Der) {
  $b64 = [Convert]::ToBase64String($Der)
  $lines = for ($i = 0; $i -lt $b64.Length; $i += 64) { $b64.Substring($i, [Math]::Min(64, $b64.Length - $i)) }
  return "-----BEGIN CERTIFICATE-----`n" + ($lines -join "`n") + "`n-----END CERTIFICATE-----`n"
}

function Get-ErrorCode($Err) {
  $e = $Err
  while ($e.InnerException) { $e = $e.InnerException }
  if ($e -is [System.Net.Sockets.SocketException]) {
    switch ($e.SocketErrorCode) {
      'ConnectionRefused' { return 'refused' }
      'TimedOut' { return 'timeout' }
      'HostNotFound' { return 'dns' }
      'NoData' { return 'dns' }
      'TryAgain' { return 'dns' }
      'ConnectionReset' { return 'reset' }
    }
  }
  if ($e -is [System.TimeoutException]) { return 'timeout' }
  if ($e -is [System.Security.Authentication.AuthenticationException] -or $e -is [System.IO.IOException]) { return 'not_tls' }
  return 'other'
}

# The chain a host presents, or why we couldn't get it. Verification is off on purpose:
# CertHalo judges the chain, so expired or untrusted certificates must still be reported.
function Get-Observation($Target) {
  $o = [ordered]@{ host = $Target.host; port = $Target.port; observedAt = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") }
  [CertHaloCapture]::Chain = New-Object 'System.Collections.Generic.List[byte[]]'
  $tcp = New-Object System.Net.Sockets.TcpClient
  try {
    $connect = $tcp.ConnectAsync($Target.host, $Target.port)
    if (-not $connect.Wait($TimeoutSeconds * 1000)) { throw [System.TimeoutException]::new("no response within $TimeoutSeconds seconds") }
    $stream = $tcp.GetStream()
    $stream.ReadTimeout = $TimeoutSeconds * 1000
    $callback = [System.Net.Security.RemoteCertificateValidationCallback] [CertHaloCapture]::Accept
    $ssl = New-Object System.Net.Security.SslStream($stream, $false, $callback)
    $ip = $null
    $sni = if ([System.Net.IPAddress]::TryParse($Target.host, [ref]$ip)) { "" } else { $Target.host }
    $ssl.AuthenticateAsClient($sni)
    $o.chain = @([CertHaloCapture]::Chain | ForEach-Object { ConvertTo-Pem $_ })
    $protocol = switch ("$($ssl.SslProtocol)") { 'Tls13' { 'TLSv1.3' } 'Tls12' { 'TLSv1.2' } 'Tls11' { 'TLSv1.1' } 'Tls' { 'TLSv1' } default { $null } }
    $cipher = $null
    if ($ssl.PSObject.Properties['NegotiatedCipherSuite']) { $cipher = "$($ssl.NegotiatedCipherSuite)" }
    $o.tls = [ordered]@{ protocol = $protocol; cipher = $cipher }
    $ssl.Dispose()
  } catch {
    $inner = $_.Exception
    while ($inner.InnerException) { $inner = $inner.InnerException }
    $msg = "$($inner.Message)"
    if ($msg.Length -gt 200) { $msg = $msg.Substring(0, 200) }
    $o.error = [ordered]@{ code = (Get-ErrorCode $_.Exception); message = $msg }
  } finally {
    $tcp.Dispose()
  }
  return $o
}

function Send-Report([string]$Body) {
  $headers = @{ Authorization = "Bearer $env:CERTHALO_API_KEY"; "User-Agent" = "certhalo-agent-powershell/$Version" }
  $uri = $Url.TrimEnd('/') + "/api/v1/reports"
  $out = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType "application/json" -Body ([System.Text.Encoding]::UTF8.GetBytes($Body)) -TimeoutSec 60
  Write-Host "certhalo-agent: reported $($out.accepted + $out.rejected) hosts ($($out.accepted) accepted, $($out.rejected) rejected)"
  foreach ($r in $out.results) { if ($r.outcome -ne 'accepted') { Write-Warning "$($r.host):$($r.port) rejected: $($r.error)" } }
}

function Invoke-Once {
  [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
  $observations = @(Read-Targets $Targets | ForEach-Object { Get-Observation $_ })
  $status = 0
  for ($i = 0; $i -lt $observations.Count; $i += $MaxPerReport) {
    $batch = $observations[$i..([Math]::Min($i + $MaxPerReport, $observations.Count) - 1)]
    $report = [ordered]@{ agent = [ordered]@{ name = $Name; version = $Version; intervalSeconds = $Interval }; observations = @($batch) }
    $body = $report | ConvertTo-Json -Depth 6
    # Never send key material, whatever went wrong upstream (CertHalo refuses it too).
    if ($body -match 'PRIVATE KEY') { throw "refusing to send a report containing a private key" }
    # Straight to stdout: anything written to the pipeline here would become Invoke-Once's return value.
    if ($DryRun) { [Console]::Out.WriteLine($body); continue }
    try { Send-Report $body } catch { Write-Warning "certhalo-agent: $_"; $status = 2 }
  }
  return $status
}

do {
  try { $code = Invoke-Once } catch { Write-Warning "certhalo-agent: $_"; $code = 1 }
  if (-not $Loop) { exit $code }
  Start-Sleep -Seconds $Interval
} while ($true)

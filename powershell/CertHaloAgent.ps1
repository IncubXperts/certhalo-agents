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
$Version = "1.1.0"
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
// The server answered, but won't switch to TLS (or isn't the server the protocol expects).
public class CertHaloNoTls : System.Exception {
  public CertHaloNoTls(string message) : base(message) {}
}
"@
}

# Schemes a target can start with: the protocol to speak, and its usual port.
$Schemes = @{ https = @('', 443); tls = @('', 443); smtp = @('smtp', 25); postgres = @('postgres', 5432); postgresql = @('postgres', 5432); mysql = @('mysql', 3306); ldap = @('ldap', 389) }
# Ports where STARTTLS is the norm, used when a target has no scheme.
$StartTlsPorts = @{ 25 = 'smtp'; 587 = 'smtp'; 389 = 'ldap'; 3306 = 'mysql'; 5432 = 'postgres' }

# "host", "host:port" or "[ipv6]:port", optionally with a scheme: smtp://, postgres://, mysql:// or
# ldap:// for STARTTLS, https:// or tls:// for TLS from the first byte. Without a scheme, ports 25,
# 587, 389, 3306 and 5432 use STARTTLS. proto is '' for TLS from the first byte.
function ConvertTo-Target([string]$Line) {
  $s = $Line
  $proto = ''
  $defaultPort = 443
  $explicit = $false
  if ($s -match '^([A-Za-z][A-Za-z0-9+.-]*)://') {
    $scheme = $Matches[1].ToLowerInvariant()
    if (-not $Schemes.ContainsKey($scheme)) { throw "unknown scheme `"$($Matches[1])`" (use https, smtp, postgres, mysql or ldap)" }
    $proto, $defaultPort = $Schemes[$scheme]
    $explicit = $true
    $s = $s.Substring($Matches[0].Length)
  }
  $s = $s.Split('/')[0]
  if ($s -match '^\[(.+)\](?::(\d+))?$') {
    $h = $Matches[1]; $port = $(if ($Matches[2]) { [int]$Matches[2] } else { $defaultPort })
  } else {
    $ip = $null
    if ([System.Net.IPAddress]::TryParse($s, [ref]$ip) -and $ip.AddressFamily -eq 'InterNetworkV6') { $h = $s; $port = $defaultPort }
    else {
      $parts = $s.Split(':')
      $h = $parts[0]
      $port = if ($parts.Count -gt 1) { [int]$parts[1] } else { $defaultPort }
    }
  }
  if ($port -lt 1 -or $port -gt 65535) { throw "bad port in '$s'" }
  if (-not $explicit) { $proto = $(if ($StartTlsPorts.ContainsKey($port)) { $StartTlsPorts[$port] } else { '' }) }
  return @{ host = $h; port = $port; proto = $proto }
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
  if ($e -is [CertHaloNoTls]) { return 'not_tls' }
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

# ── STARTTLS: ask a server that starts in plain text to switch to TLS. Only the messages each
# protocol needs before the handshake: no login, no data. Reads never go past what each step needs.

function Read-Exact($Stream, [int]$Count) {
  $buf = New-Object byte[] $Count
  $read = 0
  while ($read -lt $Count) {
    $n = $Stream.Read($buf, $read, $Count - $read)
    if ($n -le 0) { throw [System.Net.Sockets.SocketException]::new(10054) } # closed: reported as reset
    $read += $n
  }
  return , $buf
}

function Read-Line($Stream) {
  $bytes = New-Object System.Collections.Generic.List[byte]
  while ($true) {
    $b = (Read-Exact $Stream 1)[0]
    if ($b -eq 10) { break }
    $bytes.Add($b)
    if ($bytes.Count -gt 4096) { throw [CertHaloNoTls]::new("the server sent more than expected") }
  }
  return [System.Text.Encoding]::ASCII.GetString($bytes.ToArray()).TrimEnd("`r")
}

function Write-Bytes($Stream, [byte[]]$Bytes) { $Stream.Write($Bytes, 0, $Bytes.Length); $Stream.Flush() }

function Read-SmtpReply($Stream) {
  $lines = @()
  for ($i = 0; $i -lt 100; $i++) {
    $line = Read-Line $Stream
    if ($line -notmatch '^\d{3}') { throw [CertHaloNoTls]::new("not an SMTP server") }
    $lines += $(if ($line.Length -gt 4) { $line.Substring(4).Trim() } else { '' }) # after "250-" or "250 "
    if ($line.Length -eq 3 -or $line[3] -ne '-') { return @{ code = [int]$line.Substring(0, 3); lines = $lines } }
  }
  throw [CertHaloNoTls]::new("the SMTP reply is too long")
}

function Invoke-SmtpStartTls($Stream) {
  $r = Read-SmtpReply $Stream
  if ($r.code -ne 220) { throw [CertHaloNoTls]::new("the SMTP server didn't greet ($($r.code))") }
  Write-Bytes $Stream ([System.Text.Encoding]::ASCII.GetBytes("EHLO certhalo-agent`r`n"))
  $r = Read-SmtpReply $Stream
  if ($r.code -ne 250) { throw [CertHaloNoTls]::new("the SMTP server refused EHLO ($($r.code))") }
  if (-not ($r.lines | Where-Object { $_ -match '^STARTTLS(\s|$)' })) { throw [CertHaloNoTls]::new("the SMTP server doesn't offer STARTTLS") }
  Write-Bytes $Stream ([System.Text.Encoding]::ASCII.GetBytes("STARTTLS`r`n"))
  $r = Read-SmtpReply $Stream
  if ($r.code -ne 220) { throw [CertHaloNoTls]::new("the SMTP server refused STARTTLS ($($r.code))") }
}

function Invoke-PostgresStartTls($Stream) {
  # SSLRequest: length 8, then the code 80877103. The server answers one byte: S (yes) or N (no).
  Write-Bytes $Stream ([byte[]](0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f))
  $answer = [char](Read-Exact $Stream 1)[0]
  if ($answer -ceq 'N') { throw [CertHaloNoTls]::new("the PostgreSQL server doesn't have TLS turned on") }
  if ($answer -cne 'S') { throw [CertHaloNoTls]::new("not a PostgreSQL server") }
}

function Invoke-MySqlStartTls($Stream) {
  $head = Read-Exact $Stream 4
  $n = $head[0] + ($head[1] -shl 8) + ($head[2] -shl 16)
  if ($n -gt 65536) { throw [CertHaloNoTls]::new("not a MySQL server") }
  $p = Read-Exact $Stream $n
  if ($p[0] -eq 0xff) { throw [CertHaloNoTls]::new("the MySQL server refused the connection: " + [System.Text.Encoding]::UTF8.GetString($p, 3, $p.Length - 3).TrimStart('#')) }
  # Initial handshake (protocol 10): version string, thread id, 8 bytes of salt, a filler byte, then capabilities.
  $end = [Array]::IndexOf($p, [byte]0)
  if ($p[0] -ne 10 -or $end -lt 0 -or $p.Length -lt $end + 16) { throw [CertHaloNoTls]::new("not a MySQL server") }
  if (([BitConverter]::ToUInt16($p, $end + 14) -band 0x0800) -eq 0) { throw [CertHaloNoTls]::new("the MySQL server doesn't have TLS turned on") }
  # SSLRequest: CLIENT_SSL | PROTOCOL_41 | SECURE_CONNECTION, max packet size, utf8mb4, 23 zero bytes. Sequence number 1.
  $req = New-Object byte[] 36
  $req[0] = 32; $req[3] = 1
  [BitConverter]::GetBytes([uint32](0x0800 -bor 0x0200 -bor 0x8000)).CopyTo($req, 4)
  [BitConverter]::GetBytes([uint32](1 -shl 24)).CopyTo($req, 8)
  $req[12] = 45
  Write-Bytes $Stream $req
}

# The first BER element in a byte array from $At: tag, start and length of its contents.
function Get-BerElement([byte[]]$B, [int]$At) {
  if ($B.Length -lt $At + 2) { throw [CertHaloNoTls]::new("not an LDAP server") }
  $n = [int]$B[$At + 1]; $start = $At + 2
  if ($n -band 0x80) {
    $size = $n -band 0x7f
    if ($size -eq 0 -or $size -gt 3 -or $B.Length -lt $start + $size) { throw [CertHaloNoTls]::new("not an LDAP server") }
    $n = 0
    for ($i = 0; $i -lt $size; $i++) { $n = ($n -shl 8) + $B[$start + $i] }
    $start += $size
  }
  if ($B.Length -lt $start + $n) { throw [CertHaloNoTls]::new("not an LDAP server") }
  return @{ tag = $B[$At]; start = $start; length = $n }
}

function Invoke-LdapStartTls($Stream) {
  # The StartTLS extended request (RFC 4511), message ID 1.
  Write-Bytes $Stream ([byte[]](0x30, 0x1d, 0x02, 0x01, 0x01, 0x77, 0x18, 0x80, 0x16) + [System.Text.Encoding]::ASCII.GetBytes("1.3.6.1.4.1.1466.20037"))
  $head = Read-Exact $Stream 2
  $n = [int]$head[1]
  if ($n -band 0x80) {
    $size = $n -band 0x7f
    if ($size -eq 0 -or $size -gt 3) { throw [CertHaloNoTls]::new("not an LDAP server") }
    $n = 0
    foreach ($x in (Read-Exact $Stream $size)) { $n = ($n -shl 8) + $x }
  }
  if ($head[0] -ne 0x30 -or $n -gt 65536) { throw [CertHaloNoTls]::new("not an LDAP server") }
  $msg = Read-Exact $Stream $n
  # LDAPMessage: messageID, then the ExtendedResponse [APPLICATION 24], which starts with resultCode.
  $id = Get-BerElement $msg 0
  $op = Get-BerElement $msg ($id.start + $id.length)
  if ($op.tag -ne 0x78) { throw [CertHaloNoTls]::new("not an LDAP server") }
  $code = Get-BerElement $msg $op.start
  if ($code.tag -ne 0x0a -or $code.length -ne 1) { throw [CertHaloNoTls]::new("not an LDAP server") }
  $result = $msg[$code.start]
  if ($result -ne 0) { throw [CertHaloNoTls]::new("the LDAP server refused StartTLS (result $result)") }
}

function Invoke-StartTls($Stream, [string]$Proto) {
  switch ($Proto) {
    'smtp' { Invoke-SmtpStartTls $Stream }
    'postgres' { Invoke-PostgresStartTls $Stream }
    'mysql' { Invoke-MySqlStartTls $Stream }
    'ldap' { Invoke-LdapStartTls $Stream }
  }
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
    $stream.WriteTimeout = $TimeoutSeconds * 1000
    if ($Target.proto) { Invoke-StartTls $stream $Target.proto }
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
    # Collected, and written to the pipeline after the run: written here, it would become
    # Invoke-Once's return value instead of output (and `| Out-File` would get nothing).
    if ($DryRun) { $script:DryRunOutput.Add($body); continue }
    try { Send-Report $body } catch { Write-Warning "certhalo-agent: $_"; $status = 2 }
  }
  return $status
}

$script:DryRunOutput = New-Object 'System.Collections.Generic.List[string]'
do {
  try { $code = Invoke-Once } catch { Write-Warning "certhalo-agent: $_"; $code = 1 }
  foreach ($report in $script:DryRunOutput) { Write-Output $report }
  $script:DryRunOutput.Clear()
  if (-not $Loop) { exit $code }
  Start-Sleep -Seconds $Interval
} while ($true)

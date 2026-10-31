#!/usr/bin/env python3
"""CertHalo agent (Python 3.8+, standard library only).

Reads the TLS certificate each internal host presents and reports it to CertHalo, which grades it
and alerts on it. Only certificates are ever sent, never keys. Report format: ../spec/report.schema.json.

On Python 3.13+ the whole chain the server sends is reported; on older versions only the server's
own certificate (CertHalo then trusts it if it's signed directly by one of your uploaded CAs).
"""
import argparse
import datetime
import ipaddress
import json
import os
import socket
import ssl
import struct
import sys
import time
import urllib.error
import urllib.request

VERSION = "1.1.0"
DEFAULT_URL = "https://certhalo.com"
DEFAULT_INTERVAL = 21600  # 6 hours
MAX_PER_REPORT = 100  # CertHalo's limit per report


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# Schemes a target can start with: the protocol to speak, and its usual port.
SCHEMES = {"https": ("", 443), "tls": ("", 443), "smtp": ("smtp", 25), "postgres": ("postgres", 5432), "postgresql": ("postgres", 5432), "mysql": ("mysql", 3306), "ldap": ("ldap", 389)}
# Ports where STARTTLS is the norm, used when a target has no scheme.
STARTTLS_PORTS = {25: "smtp", 587: "smtp", 389: "ldap", 3306: "mysql", 5432: "postgres"}


def parse_target(line):
    """'host', 'host:port' or '[ipv6]:port', optionally with a scheme: 'smtp://', 'postgres://',
    'mysql://' or 'ldap://' for STARTTLS, 'https://' or 'tls://' for TLS from the first byte.
    Without a scheme, ports 25, 587, 389, 3306 and 5432 use STARTTLS. Returns (host, port, proto),
    proto "" meaning TLS from the first byte."""
    s, proto, default_port, explicit = line, "", 443, False
    if "://" in s:
        scheme, s = s.split("://", 1)
        if scheme.lower() not in SCHEMES:
            raise ValueError(f'unknown scheme "{scheme}" (use https, smtp, postgres, mysql or ldap)')
        (proto, default_port), explicit = SCHEMES[scheme.lower()], True
    s = s.split("/", 1)[0]
    if s.startswith("["):
        host, _, rest = s[1:].partition("]")
        port = rest.lstrip(":") or str(default_port)
    elif is_ip(s):
        host, port = s, str(default_port)
    else:
        host, _, port = s.partition(":")
        port = port or str(default_port)
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError(f'bad port in "{s}"')
    return host, int(port), proto if explicit else STARTTLS_PORTS.get(int(port), "")


def read_targets(path):
    targets = []
    with open(path, encoding="utf-8") as f:
        for i, raw in enumerate(f, 1):
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            try:
                targets.append(parse_target(line))
            except ValueError as e:
                raise ValueError(f"{path} line {i}: {e}") from None
    if not targets:
        raise ValueError(f"{path} lists no hosts")
    return targets


class NoTLS(Exception):
    """The server answered, but won't switch to TLS (or isn't the server the protocol expects)."""


def classify(err):
    message = str(err)[:200] or err.__class__.__name__
    if isinstance(err, NoTLS):
        return {"code": "not_tls", "message": message}
    if isinstance(err, socket.gaierror):
        return {"code": "dns", "message": message}
    if isinstance(err, (socket.timeout, TimeoutError)):
        return {"code": "timeout", "message": message}
    if isinstance(err, ConnectionRefusedError):
        return {"code": "refused", "message": message}
    if isinstance(err, (ConnectionResetError, BrokenPipeError)):
        return {"code": "reset", "message": message}
    if isinstance(err, ssl.SSLError):
        return {"code": "not_tls", "message": message}
    return {"code": "other", "message": message}


def recv_exact(sock, n):
    """Exactly n bytes. Never more: the TLS handshake starts right after."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionResetError("the server closed the connection")
        data += chunk
    return data


def recv_line(sock):
    line = b""
    while not line.endswith(b"\n"):
        if len(line) > 4096:
            raise NoTLS("the server sent more than expected")
        line += recv_exact(sock, 1)
    return line.decode("latin-1").rstrip("\r\n")


def smtp_reply(sock):
    lines = []
    for _ in range(100):
        line = recv_line(sock)
        if not line[:3].isdigit():
            raise NoTLS("not an SMTP server")
        lines.append(line[4:].strip())  # after "250-" or "250 "
        if len(line) == 3 or line[3] != "-":
            return int(line[:3]), lines
    raise NoTLS("the SMTP reply is too long")


def smtp_starttls(sock):
    code, _ = smtp_reply(sock)
    if code != 220:
        raise NoTLS(f"the SMTP server didn't greet ({code})")
    sock.sendall(b"EHLO certhalo-agent\r\n")
    code, lines = smtp_reply(sock)
    if code != 250:
        raise NoTLS(f"the SMTP server refused EHLO ({code})")
    if not any(l.upper() == "STARTTLS" or l.upper().startswith("STARTTLS ") for l in lines):
        raise NoTLS("the SMTP server doesn't offer STARTTLS")
    sock.sendall(b"STARTTLS\r\n")
    code, _ = smtp_reply(sock)
    if code != 220:
        raise NoTLS(f"the SMTP server refused STARTTLS ({code})")


def postgres_starttls(sock):
    # SSLRequest: length 8, then the code 80877103. The server answers one byte: S (yes) or N (no).
    sock.sendall(struct.pack(">II", 8, 80877103))
    answer = recv_exact(sock, 1)
    if answer == b"N":
        raise NoTLS("the PostgreSQL server doesn't have TLS turned on")
    if answer != b"S":
        raise NoTLS("not a PostgreSQL server")


MYSQL_CLIENT_PROTOCOL_41, MYSQL_CLIENT_SSL, MYSQL_CLIENT_SECURE_CONNECTION = 0x0200, 0x0800, 0x8000


def mysql_starttls(sock):
    head = recv_exact(sock, 4)
    n = int.from_bytes(head[:3], "little")
    if n > 65536:
        raise NoTLS("not a MySQL server")
    p = recv_exact(sock, n)
    if p[:1] == b"\xff":
        raise NoTLS("the MySQL server refused the connection: " + p[3:].decode("utf-8", "replace").lstrip("#"))
    # Initial handshake (protocol 10): version string, thread id, 8 bytes of salt, a filler byte, then capabilities.
    end = p.find(b"\x00")
    if p[:1] != b"\x0a" or end < 0 or len(p) < end + 16:
        raise NoTLS("not a MySQL server")
    if not int.from_bytes(p[end + 14 : end + 16], "little") & MYSQL_CLIENT_SSL:
        raise NoTLS("the MySQL server doesn't have TLS turned on")
    # SSLRequest: our capabilities, max packet size, character set (utf8mb4), 23 zero bytes. Sequence number 1.
    payload = struct.pack("<IIB23x", MYSQL_CLIENT_SSL | MYSQL_CLIENT_PROTOCOL_41 | MYSQL_CLIENT_SECURE_CONNECTION, 1 << 24, 45)
    sock.sendall(struct.pack("<I", len(payload))[:3] + b"\x01" + payload)


# The StartTLS extended request (RFC 4511), message ID 1.
LDAP_STARTTLS_REQUEST = bytes([0x30, 0x1D, 0x02, 0x01, 0x01, 0x77, 0x18, 0x80, 0x16]) + b"1.3.6.1.4.1.1466.20037"


def ber_next(b):
    """The first BER element in b: (tag, contents, what follows)."""
    if len(b) < 2:
        raise NoTLS("not an LDAP server")
    n, at = b[1], 2
    if n & 0x80:
        size = n & 0x7F
        if size == 0 or size > 3 or len(b) < 2 + size:
            raise NoTLS("not an LDAP server")
        n, at = int.from_bytes(b[2 : 2 + size], "big"), 2 + size
    if len(b) < at + n:
        raise NoTLS("not an LDAP server")
    return b[0], b[at : at + n], b[at + n :]


def ldap_starttls(sock):
    sock.sendall(LDAP_STARTTLS_REQUEST)
    tag, n = recv_exact(sock, 2)
    if n & 0x80:
        size = n & 0x7F
        if size == 0 or size > 3:
            raise NoTLS("not an LDAP server")
        n = int.from_bytes(recv_exact(sock, size), "big")
    if tag != 0x30 or n > 65536:
        raise NoTLS("not an LDAP server")
    # LDAPMessage: messageID, then the ExtendedResponse [APPLICATION 24], which starts with resultCode.
    _, _, rest = ber_next(recv_exact(sock, n))
    op, response, _ = ber_next(rest)
    if op != 0x78:
        raise NoTLS("not an LDAP server")
    code, value, _ = ber_next(response)
    if code != 0x0A or len(value) != 1:
        raise NoTLS("not an LDAP server")
    if value[0] != 0:
        raise NoTLS(f"the LDAP server refused StartTLS (result {value[0]})")


# Protocols that start in plain text and switch to TLS on request: only the messages each needs, no login, no data.
STARTTLS = {"smtp": smtp_starttls, "postgres": postgres_starttls, "mysql": mysql_starttls, "ldap": ldap_starttls}


def observe(host, port, timeout=10, proto=""):
    """The chain a host presents, or why we couldn't get it. Verification is off on purpose:
    CertHalo judges the chain, so expired or untrusted certificates must still be reported."""
    observed_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    o = {"host": host, "port": port, "observedAt": observed_at}
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            if proto:
                STARTTLS[proto](sock)
            with ctx.wrap_socket(sock, server_hostname=None if is_ip(host) else host) as tls:
                if hasattr(tls, "get_unverified_chain"):  # Python 3.13+: DER bytes, as the server sent them
                    ders = list(tls.get_unverified_chain())
                else:
                    ders = [tls.getpeercert(binary_form=True)]
                chain = [ssl.DER_cert_to_PEM_cert(d) for d in ders if d]
                if not chain:
                    o["error"] = {"code": "not_tls", "message": "the server sent no certificate"}
                    return o
                cipher = tls.cipher()
                o["chain"] = chain
                o["tls"] = {"protocol": tls.version(), "cipher": cipher[0] if cipher else None}
    except Exception as e:  # noqa: BLE001 - every failure is reported as an observation
        o["error"] = classify(e)
    return o


def send(cfg, body):
    req = urllib.request.Request(
        cfg.url.rstrip("/") + "/api/v1/reports",
        data=body.encode(),
        method="POST",
        headers={"Authorization": f"Bearer {cfg.key}", "Content-Type": "application/json", "User-Agent": f"certhalo-agent-python/{VERSION}"},
    )
    try:  # urllib honours HTTPS_PROXY
        with urllib.request.urlopen(req, timeout=60) as res:
            out = json.loads(res.read())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"CertHalo answered {e.code}: {e.read().decode(errors='replace').strip()}") from None
    print(f"certhalo-agent: reported {out['accepted'] + out['rejected']} hosts ({out['accepted']} accepted, {out['rejected']} rejected)")
    for r in out.get("results", []):
        if r.get("outcome") != "accepted":
            print(f"  {r['host']}:{r['port']} rejected: {r.get('error')}", file=sys.stderr)


def run_once(cfg):
    observations = [observe(h, p, cfg.timeout, proto) for h, p, proto in read_targets(cfg.targets)]
    status = 0
    for i in range(0, len(observations), MAX_PER_REPORT):
        report = {"agent": {"name": cfg.name, "version": VERSION, "intervalSeconds": cfg.interval}, "observations": observations[i : i + MAX_PER_REPORT]}
        body = json.dumps(report, indent=2)
        # Never send key material, whatever went wrong upstream (CertHalo refuses it too).
        if "PRIVATE KEY" in body:
            raise RuntimeError("refusing to send a report containing a private key")
        if cfg.dry_run:
            print(body)
            continue
        try:
            send(cfg, body)
        except Exception as e:  # noqa: BLE001
            print(f"certhalo-agent: {e}", file=sys.stderr)
            status = 2
    return status


def parse_args(argv, env=os.environ):
    p = argparse.ArgumentParser(prog="certhalo-agent", description="Report internal TLS certificates to CertHalo.")
    p.add_argument("--targets", default=env.get("CERTHALO_TARGETS", "targets.txt"), help="file with one host or host:port per line")
    p.add_argument("--url", default=env.get("CERTHALO_URL", DEFAULT_URL))
    p.add_argument("--name", default=env.get("CERTHALO_AGENT_NAME") or socket.gethostname() or "certhalo-agent")
    p.add_argument("--interval", type=int, default=int(env.get("CERTHALO_INTERVAL", DEFAULT_INTERVAL)), help="seconds between reports (300 to 604800)")
    p.add_argument("--timeout", type=int, default=10, help="seconds to wait for each host")
    p.add_argument("--loop", action="store_true", help="keep running, reporting every interval")
    p.add_argument("--dry-run", action="store_true", help="print the report instead of sending it")
    p.add_argument("--version", action="version", version=f"certhalo-agent {VERSION}")
    cfg = p.parse_args(argv)
    cfg.name = cfg.name[:60]
    cfg.key = env.get("CERTHALO_API_KEY", "")
    if not cfg.key and not cfg.dry_run:
        p.error("set CERTHALO_API_KEY to an Agent key from CertHalo's Developers page")
    if not 300 <= cfg.interval <= 604800:
        p.error("interval must be between 300 and 604800 seconds")
    return cfg


def main():
    cfg = parse_args(sys.argv[1:])
    while True:
        try:
            status = run_once(cfg)
        except Exception as e:  # noqa: BLE001
            print(f"certhalo-agent: {e}", file=sys.stderr)
            status = 1
        if not cfg.loop:
            sys.exit(status)
        time.sleep(cfg.interval)


if __name__ == "__main__":
    main()

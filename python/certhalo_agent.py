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
import sys
import time
import urllib.error
import urllib.request

VERSION = "1.0.0"
DEFAULT_URL = "https://certhalo.com"
DEFAULT_INTERVAL = 21600  # 6 hours
MAX_PER_REPORT = 100  # CertHalo's limit per report


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def parse_target(line):
    """'host', 'host:port' or '[ipv6]:port'; a scheme or path is ignored."""
    s = line.split("://", 1)[-1].split("/", 1)[0]
    if s.startswith("["):
        host, _, rest = s[1:].partition("]")
        port = rest.lstrip(":") or "443"
    elif is_ip(s):
        host, port = s, "443"
    else:
        host, _, port = s.partition(":")
        port = port or "443"
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError(f'bad port in "{s}"')
    return host, int(port)


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


def classify(err):
    message = str(err)[:200] or err.__class__.__name__
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


def observe(host, port, timeout=10):
    """The chain a host presents, or why we couldn't get it. Verification is off on purpose:
    CertHalo judges the chain, so expired or untrusted certificates must still be reported."""
    observed_at = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    o = {"host": host, "port": port, "observedAt": observed_at}
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
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
    observations = [observe(h, p, cfg.timeout) for h, p in read_targets(cfg.targets)]
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

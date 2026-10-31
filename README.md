# CertHalo agents

Monitor the TLS certificates **inside your network**: intranet sites, internal APIs, databases, load balancers and appliances that [CertHalo](https://certhalo.com) can't reach from the internet.

An agent runs inside your network, connects to each host on your list, reads the certificate chain it presents and reports it to CertHalo. CertHalo grades each certificate and alerts you before it expires or when something changes, exactly as for your public domains: by email, Slack, Microsoft Teams or webhooks.

Internal certificates are on CertHalo's **Business** plan. Built and maintained by [IncubXperts](https://incubxperts.com).

| Agent | Runs on | Needs |
| --- | --- | --- |
| [Go](go/) (recommended) | Linux, Windows, macOS; one file, nothing to install | nothing |
| [Docker image](Dockerfile) | Docker, Kubernetes | `ghcr.io/incubxperts/certhalo-agent` |
| [PowerShell](powershell/) | Windows | Windows PowerShell 5.1 or PowerShell 7 |
| [Node.js](node/) | anywhere with Node | Node.js 18+ |
| [Python](python/) | anywhere with Python | Python 3.8+ (3.13+ reports the full chain) |

All of them behave the same way, take the same settings and send the same [report format](spec/report.schema.json). CI checks every agent's real output against that format.

## Quick start

1. In CertHalo, open **Developers** and create a key with the access **Agent (sends reports only)**. If your servers use your own certificate authority, upload its root certificate there too.
2. List your hosts in `targets.txt`, one per line (`host`, `host:port` or `[ipv6]:port`; see [the example](examples/targets.txt) and [what can be monitored](#what-can-be-monitored)).
3. See what would be sent, without sending anything:

   ```bash
   ./certhalo-agent-linux-amd64 --targets targets.txt --dry-run
   ```

4. Send it:

   ```bash
   export CERTHALO_API_KEY=chk_...   # the Agent key
   ./certhalo-agent-linux-amd64 --targets targets.txt
   ```

   Your hosts appear on the CertHalo dashboard with an **Internal** badge.

5. Run it on a schedule: every 6 hours by default ([systemd](examples/systemd/), [Kubernetes](examples/kubernetes-cronjob.yaml), [Windows Task Scheduler](examples/windows-task-scheduler.md)), or keep it running with `--loop`.

Downloads for every platform, with SHA-256 checksums, are on the [releases page](https://github.com/IncubXperts/certhalo-agents/releases).

### Downloading the binaries

Check a download against the checksums file first:

```bash
shasum -a 256 -c SHA256SUMS --ignore-missing   # Linux: sha256sum -c SHA256SUMS --ignore-missing
```

The binaries aren't code-signed yet, so the first run may be blocked:

- **macOS**: a file downloaded in a browser is quarantined by Gatekeeper ("cannot be opened because the developer cannot be verified"). Remove the quarantine flag, then run it:

  ```bash
  chmod +x certhalo-agent-darwin-arm64
  xattr -d com.apple.quarantine certhalo-agent-darwin-arm64
  ```

  Or right-click the file in Finder, choose **Open**, then **Open** again. Use `-darwin-amd64` on Intel Macs.

- **Windows**: SmartScreen may show "Windows protected your PC" for the `.exe`. Choose **More info**, then **Run anyway**. Downloads that reach a server without a browser (for example with `Invoke-WebRequest`) aren't affected. For the PowerShell agent, a downloaded script may need `Unblock-File .\CertHaloAgent.ps1`, or `-ExecutionPolicy Bypass` as in the [Task Scheduler example](examples/windows-task-scheduler.md).

- **Linux**: `chmod +x certhalo-agent-linux-amd64` (or `-arm64`) is all it needs.

### Docker

```bash
docker run --rm -e CERTHALO_API_KEY=chk_... \
  -v "$PWD/targets.txt:/config/targets.txt:ro" \
  ghcr.io/incubxperts/certhalo-agent:1
```

The image runs with `--loop` by default; pass other flags to override it (for example, `--interval 21600` alone reports once and exits, for cron jobs).

### Other agents

```bash
node node/certhalo-agent.mjs --targets targets.txt
python3 python/certhalo_agent.py --targets targets.txt
```

```powershell
.\powershell\CertHaloAgent.ps1 -Targets .\targets.txt
```

## What can be monitored

Anything that serves a TLS certificate, written in `targets.txt` as `host`, `host:port` or `[ipv6]:port` (port 443 when there isn't one):

- **TLS from the first byte**: HTTPS on any port, LDAPS (636), Redis, Kafka and RabbitMQ with TLS, appliance and admin pages.
- **STARTTLS**, services that start in plain text and switch to TLS on request. The agent sends only the few messages each protocol needs to switch, then reads the certificate: it never logs in or reads data.

  | Service | Write it as | Or just the port |
  | --- | --- | --- |
  | PostgreSQL | `postgres://db.corp:5432` | `db.corp:5432` |
  | MySQL, MariaDB | `mysql://db.corp:3306` | `db.corp:3306` |
  | SMTP (mail servers) | `smtp://mail.corp:587` | `mail.corp:25`, `mail.corp:587` |
  | LDAP | `ldap://dc1.corp:389` | `dc1.corp:389` |

  Use the scheme for a service on another port (`smtp://mail.corp:2525`), and `https://` to force TLS from the first byte on one of those ports. A server that doesn't have TLS turned on is reported as `not_tls`, with the reason.

## Settings

| Flag (Go, Node, Python) | PowerShell | Environment variable | Default |
| --- | --- | --- | --- |
| | | `CERTHALO_API_KEY` | (required, except with `--dry-run`) |
| `--targets FILE` | `-Targets` | `CERTHALO_TARGETS` | `targets.txt` |
| `--name NAME` | `-Name` | `CERTHALO_AGENT_NAME` | this machine's name |
| `--interval SECONDS` | `-Interval` | `CERTHALO_INTERVAL` | `21600` (6 hours) |
| `--timeout SECONDS` | `-TimeoutSeconds` | | `10` |
| `--loop` | `-Loop` | | report once and exit |
| `--dry-run` | `-DryRun` | | send |
| `--url URL` | `-Url` | `CERTHALO_URL` | `https://certhalo.com` |

`--interval` tells CertHalo how often to expect a report. If none arrives for twice that long, CertHalo sends a **no report** alert, so a stopped agent never looks like "all fine". Keep it the same as your schedule.

Proxies: the agents use the standard `HTTPS_PROXY` setting (PowerShell uses the system proxy) for their one outbound connection, to CertHalo.

Exit codes: `0` sent (individual hosts may still have been rejected; they're listed on stderr), `1` a setting or the targets file is wrong, `2` the report couldn't be sent.

## What's sent, and what isn't

- **Sent**: for each host, its name and port, when it was checked, the certificates it presented (public information that any client sees) and the TLS version and cipher, or why the agent couldn't connect.
- **Never sent**: private keys, passwords, page content or anything else from your servers. The agents refuse to send a report containing a private key, and CertHalo refuses to accept one.
- **One outbound connection**: to `certhalo.com` over HTTPS. Nothing else leaves your network, and CertHalo never connects to your internal hosts.
- **Least privilege**: an Agent key can only send reports for its own workspace. It can't read your results or change anything, so a compromised machine running an agent can't do more than that.
- The agents connect to your hosts without verifying their certificates, on purpose: CertHalo judges each chain, so expired, self-signed or otherwise broken certificates must be reported too.

Run any agent with `--dry-run` to see exactly what it would send. See [SECURITY.md](SECURITY.md) to report a vulnerability.

## Report format

Agents `POST` a JSON report to `https://certhalo.com/api/v1/reports` with `Authorization: Bearer <Agent key>`, at most 100 hosts per report. The format is [spec/report.schema.json](spec/report.schema.json), also served at [certhalo.com/api/v1/schemas/report.json](https://certhalo.com/api/v1/schemas/report.json), and documented in the [CertHalo API docs](https://certhalo.com/docs/api#internal). Writing an agent in another language? Make its `--dry-run` output pass `python .github/check-report.py spec/report.schema.json report.json` and send a pull request.

## License

[MIT](LICENSE). © IncubXperts.

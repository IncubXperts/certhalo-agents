#!/usr/bin/env node
// CertHalo agent (Node.js 18+, no dependencies): reads the TLS certificate each internal host
// presents and reports it to CertHalo, which grades it and alerts on it. Only certificates are
// ever sent, never keys. Report format: ../spec/report.schema.json.
import { readFileSync } from "node:fs";
import { hostname } from "node:os";
import net, { isIP } from "node:net";
import tls from "node:tls";

export const VERSION = "1.1.0";
const DEFAULT_URL = "https://certhalo.com";
const DEFAULT_INTERVAL = 21600; // 6 hours
const MAX_PER_REPORT = 100; // CertHalo's limit per report

export function parseArgs(argv, env = process.env) {
  const flag = (name) => argv.includes(`--${name}`);
  const value = (name, fallback) => {
    const i = argv.indexOf(`--${name}`);
    return i >= 0 && argv[i + 1] ? argv[i + 1] : fallback;
  };
  const cfg = {
    targetsFile: value("targets", env.CERTHALO_TARGETS || "targets.txt"),
    url: value("url", env.CERTHALO_URL || DEFAULT_URL).replace(/\/+$/, ""),
    name: value("name", env.CERTHALO_AGENT_NAME || hostname() || "certhalo-agent").slice(0, 60),
    interval: Number(value("interval", env.CERTHALO_INTERVAL || DEFAULT_INTERVAL)),
    timeout: Number(value("timeout", 10)),
    loop: flag("loop"),
    dryRun: flag("dry-run"),
    key: env.CERTHALO_API_KEY || "",
  };
  if (!cfg.key && !cfg.dryRun) throw new Error("set CERTHALO_API_KEY to an Agent key from CertHalo's Developers page");
  if (!Number.isInteger(cfg.interval) || cfg.interval < 300 || cfg.interval > 604800) throw new Error("interval must be between 300 and 604800 seconds");
  return cfg;
}

/** Schemes a target can start with: the protocol to speak, and its usual port. */
const SCHEMES = { https: ["", 443], tls: ["", 443], smtp: ["smtp", 25], postgres: ["postgres", 5432], postgresql: ["postgres", 5432], mysql: ["mysql", 3306], ldap: ["ldap", 389] };
/** Ports where STARTTLS is the norm, used when a target has no scheme. */
const STARTTLS_PORTS = { 25: "smtp", 587: "smtp", 389: "ldap", 3306: "mysql", 5432: "postgres" };

/**
 * "host", "host:port" or "[ipv6]:port", optionally with a scheme: "smtp://", "postgres://", "mysql://"
 * or "ldap://" for STARTTLS, "https://" or "tls://" for TLS from the first byte. Without a scheme,
 * ports 25, 587, 389, 3306 and 5432 use STARTTLS. `proto` is "" for TLS from the first byte.
 */
export function parseTarget(line) {
  let s = line;
  let proto = "";
  let defaultPort = 443;
  let explicit = false;
  const scheme = s.match(/^([A-Za-z][A-Za-z0-9+.-]*):\/\//);
  if (scheme) {
    const known = SCHEMES[scheme[1].toLowerCase()];
    if (!known) throw new Error(`unknown scheme "${scheme[1]}" (use https, smtp, postgres, mysql or ldap)`);
    [proto, defaultPort] = known;
    explicit = true;
    s = s.slice(scheme[0].length);
  }
  s = s.split("/")[0];
  let host;
  let p = defaultPort;
  const v6 = s.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (v6) [host, p] = [v6[1], v6[2] ? Number(v6[2]) : defaultPort];
  else if (isIP(s) === 6) host = s;
  else {
    const [h, port] = s.split(":");
    [host, p] = [h, port === undefined ? defaultPort : Number(port)];
  }
  if (!Number.isInteger(p) || p < 1 || p > 65535) throw new Error(`bad port in "${s}"`);
  return { host, port: p, proto: explicit ? proto : (STARTTLS_PORTS[p] ?? "") };
}

export function readTargets(path) {
  const lines = readFileSync(path, "utf8").split("\n");
  const targets = [];
  lines.forEach((raw, i) => {
    const line = raw.split("#")[0].trim();
    if (!line) return;
    try {
      targets.push(parseTarget(line));
    } catch (err) {
      throw new Error(`${path} line ${i + 1}: ${err.message}`);
    }
  });
  if (!targets.length) throw new Error(`${path} lists no hosts`);
  return targets;
}

const toPem = (der) => `-----BEGIN CERTIFICATE-----\n${der.toString("base64").match(/.{1,64}/g).join("\n")}\n-----END CERTIFICATE-----\n`;

/** The server answered, but won't switch to TLS (or isn't the server the protocol expects). */
const noTLS = (message) => Object.assign(new Error(message), { code: "NO_TLS" });

function classify(err) {
  const message = String(err.message || err).slice(0, 200);
  if (err.code === "NO_TLS") return { code: "not_tls", message };
  const code = { ETIMEDOUT: "timeout", ECONNREFUSED: "refused", ECONNRESET: "reset", EPIPE: "reset", ENOTFOUND: "dns", EAI_AGAIN: "dns" }[err.code];
  if (code) return { code, message };
  if (err.code?.startsWith?.("ERR_SSL") || /wrong version number|packet length/i.test(message)) return { code: "not_tls", message };
  return { code: "other", message };
}

/**
 * Connects to one host and returns the chain it presents, or why it couldn't. Verification is off
 * on purpose: CertHalo judges the chain, so expired or untrusted certificates must still be reported.
 */
export async function observe({ host, port, proto = "" }, timeoutSeconds = 10) {
  const observedAt = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  const socket = new net.Socket();
  // One deadline for everything: connecting, STARTTLS and the handshake.
  const timer = setTimeout(() => socket.destroy(Object.assign(new Error(`no response within ${timeoutSeconds} seconds`), { code: "ETIMEDOUT" })), timeoutSeconds * 1000);
  try {
    await new Promise((resolve, reject) => {
      socket.once("connect", resolve).once("error", reject);
      socket.connect(port, host);
    });
    if (proto) await startTLS(socket, proto);
    return { host, port, observedAt, ...(await handshake(socket, host)) };
  } catch (err) {
    return { host, port, observedAt, error: classify(err) };
  } finally {
    clearTimeout(timer);
    socket.destroy();
  }
}

function handshake(socket, host) {
  return new Promise((resolve, reject) => {
    const secure = tls.connect({ socket, servername: isIP(host) ? undefined : host, rejectUnauthorized: false });
    socket.once("close", () => reject(Object.assign(new Error("the connection closed during the TLS handshake"), { code: socket.errored?.code ?? "ECONNRESET" })));
    secure.once("error", reject);
    secure.once("secureConnect", () => {
      const chain = [];
      const seen = new Set();
      // Node links the certificates the server sent, leaf first.
      for (let c = secure.getPeerCertificate(true); c?.raw && !seen.has(c.fingerprint256); c = c.issuerCertificate) {
        seen.add(c.fingerprint256);
        chain.push(toPem(c.raw));
      }
      const cipher = secure.getCipher();
      const protocol = secure.getProtocol() ?? undefined;
      secure.destroy();
      if (!chain.length) return resolve({ error: { code: "not_tls", message: "the server sent no certificate" } });
      resolve({ chain, tls: { protocol, cipher: cipher?.standardName ?? cipher?.name } });
    });
  });
}

/**
 * Reads from a plain socket until TLS takes over. Nothing is read past what each step needs: the
 * server sends nothing more until the TLS handshake starts.
 */
function reader(socket) {
  let buf = Buffer.alloc(0);
  let failed = null;
  let wake = () => {};
  const onData = (d) => ((buf = Buffer.concat([buf, d])), wake());
  const onEnd = () => ((failed = Object.assign(new Error("the server closed the connection"), { code: "ECONNRESET" })), wake());
  const onError = (err) => ((failed = err), wake());
  socket.on("data", onData).on("end", onEnd).on("error", onError);
  const take = async (size) => {
    for (;;) {
      const n = size(buf);
      if (n >= 0) {
        const out = buf.subarray(0, n);
        buf = buf.subarray(n);
        return out;
      }
      if (failed) throw failed;
      if (buf.length > 65536) throw noTLS("the server sent more than expected");
      await new Promise((r) => (wake = r));
    }
  };
  return {
    bytes: (n) => take((b) => (b.length >= n ? n : -1)),
    line: async () => (await take((b) => (b.indexOf(10) >= 0 ? b.indexOf(10) + 1 : -1))).toString("latin1").replace(/\r?\n$/, ""),
    done() {
      socket.off("data", onData).off("end", onEnd).off("error", onError);
      socket.pause();
    },
  };
}

/** Asks a server that starts in plain text to switch to TLS: only the messages each protocol needs, no login, no data. */
async function startTLS(socket, proto) {
  const r = reader(socket);
  try {
    await { smtp: smtpStartTLS, postgres: postgresStartTLS, mysql: mysqlStartTLS, ldap: ldapStartTLS }[proto](socket, r);
  } finally {
    r.done();
  }
}

async function smtpReply(r) {
  const lines = [];
  for (let i = 0; i < 100; i++) {
    const line = await r.line();
    if (!/^\d{3}/.test(line)) throw noTLS("not an SMTP server");
    lines.push(line.slice(4).trim()); // after "250-" or "250 "
    if (line.length === 3 || line[3] !== "-") return { code: Number(line.slice(0, 3)), lines };
  }
  throw noTLS("the SMTP reply is too long");
}

async function smtpStartTLS(socket, r) {
  let reply = await smtpReply(r);
  if (reply.code !== 220) throw noTLS(`the SMTP server didn't greet (${reply.code})`);
  socket.write("EHLO certhalo-agent\r\n");
  reply = await smtpReply(r);
  if (reply.code !== 250) throw noTLS(`the SMTP server refused EHLO (${reply.code})`);
  if (!reply.lines.some((l) => /^STARTTLS(\s|$)/i.test(l))) throw noTLS("the SMTP server doesn't offer STARTTLS");
  socket.write("STARTTLS\r\n");
  reply = await smtpReply(r);
  if (reply.code !== 220) throw noTLS(`the SMTP server refused STARTTLS (${reply.code})`);
}

async function postgresStartTLS(socket, r) {
  // SSLRequest: length 8, then the code 80877103. The server answers one byte: S (yes) or N (no).
  socket.write(Buffer.from([0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f]));
  const answer = String.fromCharCode((await r.bytes(1))[0]);
  if (answer === "N") throw noTLS("the PostgreSQL server doesn't have TLS turned on");
  if (answer !== "S") throw noTLS("not a PostgreSQL server");
}

const MYSQL_CLIENT_PROTOCOL_41 = 0x0200;
const MYSQL_CLIENT_SSL = 0x0800;
const MYSQL_CLIENT_SECURE_CONNECTION = 0x8000;

async function mysqlStartTLS(socket, r) {
  const head = await r.bytes(4);
  const n = head.readUIntLE(0, 3);
  if (n > 65536) throw noTLS("not a MySQL server");
  const p = await r.bytes(n);
  if (p[0] === 0xff) throw noTLS(`the MySQL server refused the connection: ${p.subarray(3).toString("utf8").replace(/^#/, "")}`);
  // Initial handshake (protocol 10): version string, thread id, 8 bytes of salt, a filler byte, then capabilities.
  const end = p.indexOf(0);
  if (p[0] !== 10 || end < 0 || p.length < end + 16) throw noTLS("not a MySQL server");
  if (!(p.readUInt16LE(end + 14) & MYSQL_CLIENT_SSL)) throw noTLS("the MySQL server doesn't have TLS turned on");
  // SSLRequest: our capabilities, max packet size, character set, 23 zero bytes. Sequence number 1.
  const req = Buffer.alloc(4 + 32);
  req[0] = 32;
  req[3] = 1;
  req.writeUInt32LE(MYSQL_CLIENT_SSL | MYSQL_CLIENT_PROTOCOL_41 | MYSQL_CLIENT_SECURE_CONNECTION, 4);
  req.writeUInt32LE(1 << 24, 8);
  req[12] = 45; // utf8mb4
  socket.write(req);
}

/** The StartTLS extended request (RFC 4511), message ID 1. */
export const LDAP_STARTTLS_REQUEST = Buffer.concat([Buffer.from([0x30, 0x1d, 0x02, 0x01, 0x01, 0x77, 0x18, 0x80, 0x16]), Buffer.from("1.3.6.1.4.1.1466.20037")]);

async function ldapStartTLS(socket, r) {
  socket.write(LDAP_STARTTLS_REQUEST);
  const [tag, n0] = await r.bytes(2);
  let n = n0;
  if (n & 0x80) {
    const size = n & 0x7f;
    if (size === 0 || size > 3) throw noTLS("not an LDAP server");
    n = (await r.bytes(size)).readUIntBE(0, size);
  }
  if (tag !== 0x30 || n > 65536) throw noTLS("not an LDAP server");
  // LDAPMessage: messageID, then the ExtendedResponse [APPLICATION 24], which starts with resultCode.
  const [, , rest] = berNext(await r.bytes(n));
  const [op, response] = berNext(rest);
  if (op !== 0x78) throw noTLS("not an LDAP server");
  const [code, value] = berNext(response);
  if (code !== 0x0a || value.length !== 1) throw noTLS("not an LDAP server");
  if (value[0] !== 0) throw noTLS(`the LDAP server refused StartTLS (result ${value[0]})`);
}

/** The first BER element in a buffer: [tag, contents, what follows]. */
function berNext(b) {
  if (!b || b.length < 2) throw noTLS("not an LDAP server");
  let n = b[1];
  let at = 2;
  if (n & 0x80) {
    const size = n & 0x7f;
    if (size === 0 || size > 3 || b.length < 2 + size) throw noTLS("not an LDAP server");
    n = b.readUIntBE(2, size);
    at += size;
  }
  if (b.length < at + n) throw noTLS("not an LDAP server");
  return [b[0], b.subarray(at, at + n), b.subarray(at + n)];
}

async function send(cfg, body) {
  const res = await fetch(`${cfg.url}/api/v1/reports`, {
    method: "POST",
    headers: { Authorization: `Bearer ${cfg.key}`, "Content-Type": "application/json", "User-Agent": `certhalo-agent-node/${VERSION}` },
    body,
    signal: AbortSignal.timeout(60_000),
  });
  const text = await res.text();
  if (res.status !== 200) throw new Error(`CertHalo answered ${res.status}: ${text.trim()}`);
  const out = JSON.parse(text);
  console.log(`certhalo-agent: reported ${out.accepted + out.rejected} hosts (${out.accepted} accepted, ${out.rejected} rejected)`);
  for (const r of out.results ?? []) if (r.outcome !== "accepted") console.error(`  ${r.host}:${r.port} rejected: ${r.error}`);
}

export async function runOnce(cfg) {
  const targets = readTargets(cfg.targetsFile);
  const observations = [];
  for (const t of targets) observations.push(await observe(t, cfg.timeout));
  let status = 0;
  for (let i = 0; i < observations.length; i += MAX_PER_REPORT) {
    const body = JSON.stringify({ agent: { name: cfg.name, version: VERSION, intervalSeconds: cfg.interval }, observations: observations.slice(i, i + MAX_PER_REPORT) }, null, 2);
    // Never send key material, whatever went wrong upstream (CertHalo refuses it too).
    if (body.includes("PRIVATE KEY")) throw new Error("refusing to send a report containing a private key");
    if (cfg.dryRun) {
      console.log(body);
      continue;
    }
    try {
      await send(cfg, body);
    } catch (err) {
      console.error(`certhalo-agent: ${err.message}`);
      status = 2;
    }
  }
  return status;
}

async function main() {
  if (process.argv.includes("--version")) return console.log(`certhalo-agent ${VERSION}`);
  let cfg;
  try {
    cfg = parseArgs(process.argv.slice(2));
  } catch (err) {
    console.error(`certhalo-agent: ${err.message}`);
    process.exit(1);
  }
  for (;;) {
    let status;
    try {
      status = await runOnce(cfg);
    } catch (err) {
      console.error(`certhalo-agent: ${err.message}`);
      status = 1;
    }
    if (!cfg.loop) process.exit(status);
    await new Promise((r) => setTimeout(r, cfg.interval * 1000));
  }
}

if (import.meta.url === `file://${process.argv[1]}`) await main();

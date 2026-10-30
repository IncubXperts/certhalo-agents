#!/usr/bin/env node
// CertHalo agent (Node.js 18+, no dependencies): reads the TLS certificate each internal host
// presents and reports it to CertHalo, which grades it and alerts on it. Only certificates are
// ever sent, never keys. Report format: ../spec/report.schema.json.
import { readFileSync } from "node:fs";
import { hostname } from "node:os";
import { isIP } from "node:net";
import tls from "node:tls";

export const VERSION = "1.0.0";
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

/** "host", "host:port" or "[ipv6]:port"; a scheme or path is ignored. */
export function parseTarget(line) {
  const s = line.replace(/^(https|tls):\/\//, "").split("/")[0];
  const v6 = s.match(/^\[([^\]]+)\](?::(\d+))?$/);
  if (v6) return { host: v6[1], port: v6[2] ? Number(v6[2]) : 443 };
  if (isIP(s) === 6) return { host: s, port: 443 };
  const [host, port] = s.split(":");
  const p = port === undefined ? 443 : Number(port);
  if (!Number.isInteger(p) || p < 1 || p > 65535) throw new Error(`bad port in "${s}"`);
  return { host, port: p };
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

function classify(err) {
  const message = String(err.message || err).slice(0, 200);
  const code = { ETIMEDOUT: "timeout", ECONNREFUSED: "refused", ECONNRESET: "reset", EPIPE: "reset", ENOTFOUND: "dns", EAI_AGAIN: "dns" }[err.code];
  if (code) return { code, message };
  if (err.code?.startsWith?.("ERR_SSL") || /wrong version number|packet length/i.test(message)) return { code: "not_tls", message };
  return { code: "other", message };
}

/**
 * Connects to one host and returns the chain it presents, or why it couldn't. Verification is off
 * on purpose: CertHalo judges the chain, so expired or untrusted certificates must still be reported.
 */
export function observe({ host, port }, timeoutSeconds = 10) {
  const observedAt = new Date().toISOString().replace(/\.\d{3}Z$/, "Z");
  return new Promise((resolve) => {
    const socket = tls.connect({ host, port, servername: isIP(host) ? undefined : host, rejectUnauthorized: false, timeout: timeoutSeconds * 1000 });
    const done = (o) => {
      socket.destroy();
      resolve({ host, port, observedAt, ...o });
    };
    socket.once("secureConnect", () => {
      const chain = [];
      const seen = new Set();
      // Node links the certificates the server sent, leaf first.
      for (let c = socket.getPeerCertificate(true); c?.raw && !seen.has(c.fingerprint256); c = c.issuerCertificate) {
        seen.add(c.fingerprint256);
        chain.push(toPem(c.raw));
      }
      if (!chain.length) return done({ error: { code: "not_tls", message: "the server sent no certificate" } });
      const cipher = socket.getCipher();
      done({ chain, tls: { protocol: socket.getProtocol() ?? undefined, cipher: cipher?.standardName ?? cipher?.name } });
    });
    socket.once("timeout", () => done({ error: { code: "timeout", message: `no response within ${timeoutSeconds} seconds` } }));
    socket.once("error", (err) => done({ error: classify(err) }));
  });
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

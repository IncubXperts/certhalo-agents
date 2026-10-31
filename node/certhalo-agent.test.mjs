import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createServer } from "node:net";
import tls from "node:tls";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { LDAP_STARTTLS_REQUEST, observe, parseArgs, parseTarget, readTargets } from "./certhalo-agent.mjs";

test("parses hosts, ports and IPv6", () => {
  assert.deepEqual(parseTarget("intranet"), { host: "intranet", port: 443, proto: "" });
  assert.deepEqual(parseTarget("https://wiki.corp/x"), { host: "wiki.corp", port: 443, proto: "" });
  assert.deepEqual(parseTarget("[fd00::1]:8443"), { host: "fd00::1", port: 8443, proto: "" });
  assert.deepEqual(parseTarget("fd00::1"), { host: "fd00::1", port: 443, proto: "" });
  assert.deepEqual(parseTarget("dc1.corp:636"), { host: "dc1.corp", port: 636, proto: "" });
  assert.throws(() => parseTarget("host:99999"));
});

test("uses STARTTLS by scheme, or by the usual port", () => {
  assert.deepEqual(parseTarget("db.corp.local:5432"), { host: "db.corp.local", port: 5432, proto: "postgres" });
  assert.deepEqual(parseTarget("postgresql://db2.corp"), { host: "db2.corp", port: 5432, proto: "postgres" });
  assert.deepEqual(parseTarget("mysql://[fd00::2]"), { host: "fd00::2", port: 3306, proto: "mysql" });
  assert.deepEqual(parseTarget("smtp://mail.corp"), { host: "mail.corp", port: 25, proto: "smtp" });
  assert.deepEqual(parseTarget("mail.corp:587"), { host: "mail.corp", port: 587, proto: "smtp" });
  assert.deepEqual(parseTarget("SMTP://mail.corp:2525"), { host: "mail.corp", port: 2525, proto: "smtp" });
  assert.deepEqual(parseTarget("ldap://dc1.corp"), { host: "dc1.corp", port: 389, proto: "ldap" });
  // An explicit https:// means TLS from the first byte, whatever the port.
  assert.deepEqual(parseTarget("https://odd.corp:5432"), { host: "odd.corp", port: 5432, proto: "" });
  assert.throws(() => parseTarget("ftp://files.corp"), /unknown scheme/);
});

test("reads a targets file, skipping comments", () => {
  const path = join(mkdtempSync(join(tmpdir(), "agent-")), "targets.txt");
  writeFileSync(path, "# internal\nintranet\n\n10.0.4.12:8443 # lb\n");
  assert.deepEqual(readTargets(path), [
    { host: "intranet", port: 443, proto: "" },
    { host: "10.0.4.12", port: 8443, proto: "" },
  ]);
});

test("needs a key unless it's a dry run", () => {
  assert.throws(() => parseArgs([], {}), /CERTHALO_API_KEY/);
  assert.equal(parseArgs(["--dry-run"], {}).dryRun, true);
  assert.throws(() => parseArgs(["--interval", "10"], { CERTHALO_API_KEY: "k" }), /interval/);
});

test("reports a refused connection as refused", async () => {
  const server = createServer();
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const { port } = server.address();
  server.close();
  const o = await observe({ host: "127.0.0.1", port }, 2);
  assert.equal(o.error.code, "refused");
});

// A self-signed certificate for the fake servers below.
const dir = mkdtempSync(join(tmpdir(), "agent-tls-"));
execFileSync("openssl", ["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem")], { stdio: "ignore" });
const credentials = { key: readFileSync(join(dir, "key.pem")), cert: readFileSync(join(dir, "cert.pem")) };

/**
 * A server that speaks a protocol's plain-text opening, then TLS. `opening` gets each chunk the client
 * sends (the client waits for an answer at every step) and returns "tls" once TLS should start.
 */
async function starttlsServer(greeting, opening) {
  const server = createServer((socket) => {
    if (greeting) socket.write(greeting);
    const onData = (chunk) => {
      if (opening(socket, chunk) !== "tls") return;
      socket.off("data", onData);
      new tls.TLSSocket(socket, { isServer: true, ...credentials }).on("error", () => {});
    };
    socket.on("data", onData).on("error", () => {});
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  return { server, port: server.address().port };
}

const observeVia = async (proto, greeting, opening) => {
  const { server, port } = await starttlsServer(greeting, opening);
  try {
    return await observe({ host: "127.0.0.1", port, proto }, 5);
  } finally {
    server.close();
  }
};

test("SMTP: EHLO, STARTTLS, then the certificate", async () => {
  const o = await observeVia("smtp", "220 mail.corp ESMTP\r\n", (socket, chunk) => {
    const line = chunk.toString();
    if (line.startsWith("EHLO ")) socket.write("250-mail.corp\r\n250-SIZE 10240000\r\n250-STARTTLS\r\n250 8BITMIME\r\n");
    if (line === "STARTTLS\r\n") return socket.write("220 Ready to start TLS\r\n") && "tls";
  });
  assert.ok(o.chain?.[0]?.startsWith("-----BEGIN CERTIFICATE-----"), JSON.stringify(o));
});

test("SMTP without STARTTLS is not_tls, with the reason", async () => {
  const o = await observeVia("smtp", "220 mail.corp ESMTP\r\n", (socket) => socket.write("250-mail.corp\r\n250 8BITMIME\r\n"));
  assert.deepEqual(o.error, { code: "not_tls", message: "the SMTP server doesn't offer STARTTLS" });
});

test("PostgreSQL: SSLRequest answered S or N", async () => {
  const isSslRequest = (chunk) => chunk.length === 8 && chunk.readUInt32BE(4) === 80877103;
  const yes = await observeVia("postgres", null, (socket, chunk) => isSslRequest(chunk) && socket.write("S") && "tls");
  assert.ok(yes.chain?.length, JSON.stringify(yes));
  const no = await observeVia("postgres", null, (socket, chunk) => void (isSslRequest(chunk) && socket.write("N")));
  assert.deepEqual(no.error, { code: "not_tls", message: "the PostgreSQL server doesn't have TLS turned on" });
});

test("LDAP: StartTLS extended operation", async () => {
  const response = (result) => Buffer.from([0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, result, 0x04, 0x00, 0x04, 0x00]);
  const yes = await observeVia("ldap", null, (socket, chunk) => chunk.equals(LDAP_STARTTLS_REQUEST) && socket.write(response(0)) && "tls");
  assert.ok(yes.chain?.length, JSON.stringify(yes));
  const no = await observeVia("ldap", null, (socket, chunk) => void (chunk.equals(LDAP_STARTTLS_REQUEST) && socket.write(response(2))));
  assert.deepEqual(no.error, { code: "not_tls", message: "the LDAP server refused StartTLS (result 2)" });
});


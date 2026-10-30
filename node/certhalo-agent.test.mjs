import assert from "node:assert/strict";
import { createServer } from "node:net";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { observe, parseArgs, parseTarget, readTargets } from "./certhalo-agent.mjs";

test("parses hosts, ports and IPv6", () => {
  assert.deepEqual(parseTarget("intranet"), { host: "intranet", port: 443 });
  assert.deepEqual(parseTarget("db.corp.local:5432"), { host: "db.corp.local", port: 5432 });
  assert.deepEqual(parseTarget("https://wiki.corp/x"), { host: "wiki.corp", port: 443 });
  assert.deepEqual(parseTarget("[fd00::1]:8443"), { host: "fd00::1", port: 8443 });
  assert.deepEqual(parseTarget("fd00::1"), { host: "fd00::1", port: 443 });
  assert.throws(() => parseTarget("host:99999"));
});

test("reads a targets file, skipping comments", () => {
  const path = join(mkdtempSync(join(tmpdir(), "agent-")), "targets.txt");
  writeFileSync(path, "# internal\nintranet\n\n10.0.4.12:8443 # lb\n");
  assert.deepEqual(readTargets(path), [{ host: "intranet", port: 443 }, { host: "10.0.4.12", port: 8443 }]);
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

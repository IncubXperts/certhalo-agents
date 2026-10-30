"""Checks an agent's dry-run report against the published schema, and that it reads chains and errors."""
import json
import sys

import jsonschema

schema_path, report_path = sys.argv[1], sys.argv[2]
schema = json.load(open(schema_path, encoding="utf-8"))
report = json.load(open(report_path, encoding="utf-8-sig"))
jsonschema.validate(report, schema)

obs = {o["host"]: o for o in report["observations"]}
assert obs["example.com"]["chain"][0].startswith("-----BEGIN CERTIFICATE-----"), "no chain for example.com"
assert obs["certhalo.com"]["tls"]["protocol"].startswith("TLSv1"), "no TLS details"
assert obs["does-not-exist.invalid"]["error"]["code"] in ("dns", "other"), "no error for an unknown host"
assert "PRIVATE KEY" not in json.dumps(report)
print(f"OK: {len(report['observations'])} observations from {report['agent']['name']} {report['agent']['version']}")

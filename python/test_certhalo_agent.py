import os
import socket
import tempfile
import unittest

import certhalo_agent as agent


class AgentTest(unittest.TestCase):
    def test_parse_target(self):
        self.assertEqual(agent.parse_target("intranet"), ("intranet", 443))
        self.assertEqual(agent.parse_target("db.corp.local:5432"), ("db.corp.local", 5432))
        self.assertEqual(agent.parse_target("https://wiki.corp/x"), ("wiki.corp", 443))
        self.assertEqual(agent.parse_target("[fd00::1]:8443"), ("fd00::1", 8443))
        self.assertEqual(agent.parse_target("fd00::1"), ("fd00::1", 443))
        with self.assertRaises(ValueError):
            agent.parse_target("host:99999")

    def test_read_targets_skips_comments(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("# internal\nintranet\n\n10.0.4.12:8443 # lb\n")
        try:
            self.assertEqual(agent.read_targets(f.name), [("intranet", 443), ("10.0.4.12", 8443)])
        finally:
            os.unlink(f.name)

    def test_refused_connection(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        self.assertEqual(agent.observe("127.0.0.1", port, 2)["error"]["code"], "refused")

    def test_needs_a_key_unless_dry_run(self):
        with self.assertRaises(SystemExit):
            agent.parse_args([], env={})
        self.assertTrue(agent.parse_args(["--dry-run"], env={}).dry_run)


if __name__ == "__main__":
    unittest.main()

import os
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import unittest

import certhalo_agent as agent


class AgentTest(unittest.TestCase):
    def test_parse_target(self):
        self.assertEqual(agent.parse_target("intranet"), ("intranet", 443, ""))
        self.assertEqual(agent.parse_target("https://wiki.corp/x"), ("wiki.corp", 443, ""))
        self.assertEqual(agent.parse_target("[fd00::1]:8443"), ("fd00::1", 8443, ""))
        self.assertEqual(agent.parse_target("fd00::1"), ("fd00::1", 443, ""))
        self.assertEqual(agent.parse_target("dc1.corp:636"), ("dc1.corp", 636, ""))
        with self.assertRaises(ValueError):
            agent.parse_target("host:99999")

    def test_starttls_by_scheme_or_usual_port(self):
        self.assertEqual(agent.parse_target("db.corp.local:5432"), ("db.corp.local", 5432, "postgres"))
        self.assertEqual(agent.parse_target("postgresql://db2.corp"), ("db2.corp", 5432, "postgres"))
        self.assertEqual(agent.parse_target("mysql://[fd00::2]"), ("fd00::2", 3306, "mysql"))
        self.assertEqual(agent.parse_target("smtp://mail.corp"), ("mail.corp", 25, "smtp"))
        self.assertEqual(agent.parse_target("mail.corp:587"), ("mail.corp", 587, "smtp"))
        self.assertEqual(agent.parse_target("SMTP://mail.corp:2525"), ("mail.corp", 2525, "smtp"))
        self.assertEqual(agent.parse_target("ldap://dc1.corp"), ("dc1.corp", 389, "ldap"))
        # An explicit https:// means TLS from the first byte, whatever the port.
        self.assertEqual(agent.parse_target("https://odd.corp:5432"), ("odd.corp", 5432, ""))
        with self.assertRaisesRegex(ValueError, "unknown scheme"):
            agent.parse_target("ftp://files.corp")

    def test_read_targets_skips_comments(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write("# internal\nintranet\n\n10.0.4.12:8443 # lb\n")
        try:
            self.assertEqual(agent.read_targets(f.name), [("intranet", 443, ""), ("10.0.4.12", 8443, "")])
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



class StartTLSTest(unittest.TestCase):
    """Fake servers: a protocol's plain-text opening, then TLS with a self-signed certificate."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        key, cert = os.path.join(cls.dir, "key.pem"), os.path.join(cls.dir, "cert.pem")
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-keyout", key, "-out", cert],
            check=True,
            capture_output=True,
        )
        cls.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        cls.ctx.load_cert_chain(cert, key)

    def observe_via(self, proto, opening):
        """opening(conn) speaks the plain-text part and returns True when TLS should start."""
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)

        def serve():
            conn, _ = server.accept()
            with conn:
                try:
                    if opening(conn):
                        with self.ctx.wrap_socket(conn, server_side=True):
                            pass
                except (OSError, ssl.SSLError):
                    pass

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        try:
            return agent.observe("127.0.0.1", server.getsockname()[1], 5, proto)
        finally:
            t.join(5)
            server.close()

    def test_smtp(self):
        def opening(conn):
            conn.sendall(b"220 mail.corp ESMTP\r\n")
            if not agent.recv_line(conn).startswith("EHLO "):
                return False
            conn.sendall(b"250-mail.corp\r\n250-SIZE 10240000\r\n250-STARTTLS\r\n250 8BITMIME\r\n")
            if agent.recv_line(conn) != "STARTTLS":
                return False
            conn.sendall(b"220 Ready to start TLS\r\n")
            return True

        o = self.observe_via("smtp", opening)
        self.assertTrue(o.get("chain"), o)

    def test_smtp_without_starttls(self):
        def opening(conn):
            conn.sendall(b"220 mail.corp ESMTP\r\n")
            agent.recv_line(conn)
            conn.sendall(b"250-mail.corp\r\n250 8BITMIME\r\n")
            return False

        self.assertEqual(self.observe_via("smtp", opening)["error"], {"code": "not_tls", "message": "the SMTP server doesn't offer STARTTLS"})

    def test_postgres(self):
        for answer in (b"S", b"N"):

            def opening(conn, answer=answer):
                if agent.recv_exact(conn, 8) != struct.pack(">II", 8, 80877103):
                    return False
                conn.sendall(answer)
                return answer == b"S"

            o = self.observe_via("postgres", opening)
            if answer == b"S":
                self.assertTrue(o.get("chain"), o)
            else:
                self.assertEqual(o["error"], {"code": "not_tls", "message": "the PostgreSQL server doesn't have TLS turned on"})

    def test_ldap(self):
        for result in (0, 2):

            def opening(conn, result=result):
                if agent.recv_exact(conn, len(agent.LDAP_STARTTLS_REQUEST)) != agent.LDAP_STARTTLS_REQUEST:
                    return False
                conn.sendall(bytes([0x30, 0x0C, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0A, 0x01, result, 0x04, 0x00, 0x04, 0x00]))
                return result == 0

            o = self.observe_via("ldap", opening)
            if result == 0:
                self.assertTrue(o.get("chain"), o)
            else:
                self.assertEqual(o["error"], {"code": "not_tls", "message": "the LDAP server refused StartTLS (result 2)"})


if __name__ == "__main__":
    unittest.main()

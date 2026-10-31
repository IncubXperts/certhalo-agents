package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseTarget(t *testing.T) {
	cases := map[string]target{
		"intranet":            {"intranet", 443, ""},
		"https://wiki.corp/x": {"wiki.corp", 443, ""},
		"10.0.4.12:8443":      {"10.0.4.12", 8443, ""},
		"[fd00::1]:443":       {"fd00::1", 443, ""},
		"fd00::1":             {"fd00::1", 443, ""},
		"dc1.corp:636":        {"dc1.corp", 636, ""},
		// STARTTLS: by scheme, or by the usual port when there's no scheme.
		"db.corp.local:5432":    {"db.corp.local", 5432, "postgres"},
		"postgresql://db2.corp": {"db2.corp", 5432, "postgres"},
		"mysql://[fd00::2]":     {"fd00::2", 3306, "mysql"},
		"smtp://mail.corp":      {"mail.corp", 25, "smtp"},
		"mail.corp:587":         {"mail.corp", 587, "smtp"},
		"ldap://dc1.corp":       {"dc1.corp", 389, "ldap"},
		"SMTP://mail.corp:2525": {"mail.corp", 2525, "smtp"},
		// An explicit https:// means TLS from the first byte, whatever the port.
		"https://odd.corp:5432": {"odd.corp", 5432, ""},
	}
	for in, want := range cases {
		got, err := parseTarget(in)
		if err != nil || got != want {
			t.Errorf("parseTarget(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"host:99999", "ftp://files.corp"} {
		if _, err := parseTarget(bad); err == nil {
			t.Errorf("parseTarget(%q): expected an error", bad)
		}
	}
}

func TestReadTargetsSkipsCommentsAndBlankLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	os.WriteFile(path, []byte("# internal hosts\nintranet\n\n10.0.4.12:8443  # load balancer\n"), 0o600)
	got, err := readTargets(path)
	if err != nil || len(got) != 2 || got[1] != (target{"10.0.4.12", 8443, ""}) {
		t.Fatalf("readTargets = %v, %v", got, err)
	}
}

// A local TLS server: the agent must report its chain even though it's self-signed (untrusted).
func TestObserveReportsAnUntrustedChain(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	p, _ := strconv.Atoi(port)
	o := observe(target{host, p, ""}, 5*time.Second)
	if o.Error != nil || len(o.Chain) == 0 || !strings.HasPrefix(o.Chain[0], "-----BEGIN CERTIFICATE-----") {
		t.Fatalf("observe = %+v", o)
	}
	if o.TLS == nil || !strings.HasPrefix(o.TLS.Protocol, "TLSv1") {
		t.Fatalf("missing TLS details: %+v", o.TLS)
	}
}

func TestObserveClassifiesRefusedConnections(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close() // nothing listens now
	o := observe(target{"127.0.0.1", port, ""}, 2*time.Second)
	if o.Error == nil || o.Error.Code != "refused" {
		t.Fatalf("observe = %+v", o.Error)
	}
}

func TestSendPostsTheReportWithTheKey(t *testing.T) {
	var gotAuth string
	var got report
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		json.NewDecoder(r.Body).Decode(&got)
		w.Write([]byte(`{"accepted":1,"rejected":0,"results":[{"host":"intranet","port":443,"outcome":"accepted"}]}`))
	}))
	defer srv.Close()
	body, _ := json.Marshal(report{Agent: agentInfo{Name: "dc1", Version: version, IntervalSeconds: 3600}, Observations: []observation{{Host: "intranet", Port: 443}}})
	if err := send(config{url: srv.URL, key: "chk_test"}, body); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer chk_test" || got.Agent.Name != "dc1" || len(got.Observations) != 1 {
		t.Fatalf("server got %q %+v", gotAuth, got)
	}
}

// A server that speaks a protocol's plain-text opening, then TLS with a self-signed certificate.
func starttlsServer(t *testing.T, opening func(c net.Conn, r *bufio.Reader) bool) target {
	t.Helper()
	tlsSrv := httptest.NewUnstartedServer(nil)
	tlsSrv.StartTLS() // only for its certificate
	t.Cleanup(tlsSrv.Close)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		if opening(c, bufio.NewReader(c)) {
			tls.Server(c, tlsSrv.TLS).Handshake()
		}
	}()
	addr := ln.Addr().(*net.TCPAddr)
	return target{Host: "127.0.0.1", Port: addr.Port}
}

func expectChain(t *testing.T, o observation) {
	t.Helper()
	if o.Error != nil || len(o.Chain) == 0 || o.TLS == nil {
		t.Fatalf("observe = %+v (error %+v)", o, o.Error)
	}
}

func expectNoTLS(t *testing.T, o observation, want string) {
	t.Helper()
	if o.Error == nil || o.Error.Code != "not_tls" || !strings.Contains(o.Error.Message, want) {
		t.Fatalf("want not_tls %q, got %+v", want, o.Error)
	}
}

func TestSMTPStartTLS(t *testing.T) {
	srv := starttlsServer(t, func(c net.Conn, r *bufio.Reader) bool {
		fmt.Fprint(c, "220 mail.corp ESMTP\r\n")
		if l, _ := r.ReadString('\n'); !strings.HasPrefix(l, "EHLO ") {
			return false
		}
		fmt.Fprint(c, "250-mail.corp\r\n250-SIZE 10240000\r\n250-STARTTLS\r\n250 8BITMIME\r\n")
		if l, _ := r.ReadString('\n'); l != "STARTTLS\r\n" {
			return false
		}
		fmt.Fprint(c, "220 Ready to start TLS\r\n")
		return true
	})
	srv.Proto = "smtp"
	expectChain(t, observe(srv, 5*time.Second))
}

func TestSMTPWithoutStartTLS(t *testing.T) {
	srv := starttlsServer(t, func(c net.Conn, r *bufio.Reader) bool {
		fmt.Fprint(c, "220 mail.corp ESMTP\r\n")
		r.ReadString('\n')
		fmt.Fprint(c, "250-mail.corp\r\n250 8BITMIME\r\n")
		return false
	})
	srv.Proto = "smtp"
	expectNoTLS(t, observe(srv, 5*time.Second), "doesn't offer STARTTLS")
}

func TestPostgresStartTLS(t *testing.T) {
	for _, answer := range []byte{'S', 'N'} {
		srv := starttlsServer(t, func(c net.Conn, r *bufio.Reader) bool {
			req := make([]byte, 8)
			if _, err := io.ReadFull(r, req); err != nil || binary.BigEndian.Uint32(req[4:]) != 80877103 {
				return false
			}
			c.Write([]byte{answer})
			return answer == 'S'
		})
		srv.Proto = "postgres"
		o := observe(srv, 5*time.Second)
		if answer == 'S' {
			expectChain(t, o)
		} else {
			expectNoTLS(t, o, "doesn't have TLS turned on")
		}
	}
}

func TestMySQLStartTLS(t *testing.T) {
	srv := starttlsServer(t, func(c net.Conn, r *bufio.Reader) bool {
		// Protocol 10, version, thread id, 8 bytes of salt, filler, capabilities with CLIENT_SSL.
		p := append([]byte{10}, "8.0.40\x00"...)
		p = append(p, 1, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 0)
		p = binary.LittleEndian.AppendUint16(p, 0xffff)
		p = append(p, make([]byte, 20)...)
		c.Write(append([]byte{byte(len(p)), 0, 0, 0}, p...))
		// Straight from the connection: the client's TLS hello follows at once, and a buffered reader would swallow it.
		req := make([]byte, 36)
		if _, err := io.ReadFull(c, req); err != nil || req[0] != 32 || req[3] != 1 || binary.LittleEndian.Uint32(req[4:])&0x0800 == 0 {
			return false
		}
		return true
	})
	srv.Proto = "mysql"
	expectChain(t, observe(srv, 5*time.Second))
}

func TestLDAPStartTLS(t *testing.T) {
	for _, result := range []byte{0, 2} {
		srv := starttlsServer(t, func(c net.Conn, r *bufio.Reader) bool {
			req := make([]byte, len(ldapStartTLSRequest))
			if _, err := io.ReadFull(r, req); err != nil || !bytes.Equal(req, ldapStartTLSRequest) {
				return false
			}
			// ExtendedResponse: resultCode, matchedDN "", diagnosticMessage "".
			c.Write([]byte{0x30, 0x0c, 0x02, 0x01, 0x01, 0x78, 0x07, 0x0a, 0x01, result, 0x04, 0x00, 0x04, 0x00})
			return result == 0
		})
		srv.Proto = "ldap"
		o := observe(srv, 5*time.Second)
		if result == 0 {
			expectChain(t, o)
		} else {
			expectNoTLS(t, o, "refused StartTLS (result 2)")
		}
	}
}

package main

import (
	"encoding/json"
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
		"intranet":            {"intranet", 443},
		"db.corp.local:5432":  {"db.corp.local", 5432},
		"https://wiki.corp/x": {"wiki.corp", 443},
		"10.0.4.12:8443":      {"10.0.4.12", 8443},
		"[fd00::1]:443":       {"fd00::1", 443},
		"fd00::1":             {"fd00::1", 443},
	}
	for in, want := range cases {
		got, err := parseTarget(in)
		if err != nil || got != want {
			t.Errorf("parseTarget(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	if _, err := parseTarget("host:99999"); err == nil {
		t.Error("expected an error for a bad port")
	}
}

func TestReadTargetsSkipsCommentsAndBlankLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "targets.txt")
	os.WriteFile(path, []byte("# internal hosts\nintranet\n\n10.0.4.12:8443  # load balancer\n"), 0o600)
	got, err := readTargets(path)
	if err != nil || len(got) != 2 || got[1] != (target{"10.0.4.12", 8443}) {
		t.Fatalf("readTargets = %v, %v", got, err)
	}
}

// A local TLS server: the agent must report its chain even though it's self-signed (untrusted).
func TestObserveReportsAnUntrustedChain(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(srv.URL, "https://"))
	p, _ := strconv.Atoi(port)
	o := observe(target{host, p}, 5*time.Second)
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
	o := observe(target{"127.0.0.1", port}, 2*time.Second)
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

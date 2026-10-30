// CertHalo agent (Go): reads the TLS certificate each internal host presents and reports it to
// CertHalo, which grades it and alerts on it. Only certificates are ever sent, never keys.
// Report format: ../spec/report.schema.json. Docs: https://certhalo.com/docs/api#internal
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

const (
	version         = "1.0.0"
	defaultURL      = "https://certhalo.com"
	defaultInterval = 21600 // 6 hours
	maxPerReport    = 100   // CertHalo's limit per report
)

type target struct {
	Host string
	Port int
}

type tlsInfo struct {
	Protocol string `json:"protocol,omitempty"`
	Cipher   string `json:"cipher,omitempty"`
}

type obsError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type observation struct {
	Host       string    `json:"host"`
	Port       int       `json:"port"`
	ObservedAt string    `json:"observedAt"`
	Chain      []string  `json:"chain,omitempty"`
	TLS        *tlsInfo  `json:"tls,omitempty"`
	Error      *obsError `json:"error,omitempty"`
}

type agentInfo struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	IntervalSeconds int    `json:"intervalSeconds"`
}

type report struct {
	Agent        agentInfo     `json:"agent"`
	Observations []observation `json:"observations"`
}

type config struct {
	url, key, name, targetsFile string
	interval, timeout           int
	loop, dryRun                bool
}

func main() {
	cfg, err := parseConfig(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "certhalo-agent:", err)
		os.Exit(1)
	}
	for {
		code := runOnce(cfg)
		if !cfg.loop {
			os.Exit(code)
		}
		time.Sleep(time.Duration(cfg.interval) * time.Second)
	}
}

func env(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}

func parseConfig(args []string) (config, error) {
	host, _ := os.Hostname()
	fs := flag.NewFlagSet("certhalo-agent", flag.ContinueOnError)
	var c config
	fs.StringVar(&c.targetsFile, "targets", env("CERTHALO_TARGETS", "targets.txt"), "file with one host or host:port per line")
	fs.StringVar(&c.url, "url", env("CERTHALO_URL", defaultURL), "CertHalo address")
	fs.StringVar(&c.name, "name", env("CERTHALO_AGENT_NAME", host), "agent name shown on the dashboard")
	interval, _ := strconv.Atoi(env("CERTHALO_INTERVAL", strconv.Itoa(defaultInterval)))
	fs.IntVar(&c.interval, "interval", interval, "seconds between reports (300 to 604800)")
	fs.IntVar(&c.timeout, "timeout", 10, "seconds to wait for each host")
	fs.BoolVar(&c.loop, "loop", false, "keep running, reporting every interval (default: report once and exit)")
	fs.BoolVar(&c.dryRun, "dry-run", false, "print the report instead of sending it")
	showVersion := fs.Bool("version", false, "print the version")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if *showVersion {
		fmt.Println("certhalo-agent", version)
		os.Exit(0)
	}
	c.key = os.Getenv("CERTHALO_API_KEY")
	if c.key == "" && !c.dryRun {
		return c, errors.New("set CERTHALO_API_KEY to an Agent key from CertHalo's Developers page")
	}
	if c.interval < 300 || c.interval > 604800 {
		return c, errors.New("interval must be between 300 and 604800 seconds")
	}
	if c.name == "" {
		c.name = "certhalo-agent"
	}
	if len(c.name) > 60 {
		c.name = c.name[:60]
	}
	return c, nil
}

// readTargets reads "host", "host:port" or "[ipv6]:port" lines; # starts a comment.
func readTargets(path string) ([]target, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading targets: %w", err)
	}
	var out []target
	for i, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		t, err := parseTarget(line)
		if err != nil {
			return nil, fmt.Errorf("%s line %d: %w", path, i+1, err)
		}
		out = append(out, t)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s lists no hosts", path)
	}
	return out, nil
}

func parseTarget(s string) (target, error) {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "https://"), "tls://")
	s = strings.SplitN(s, "/", 2)[0]
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		// No port given (or a bare IPv6 address).
		return target{Host: strings.Trim(s, "[]"), Port: 443}, nil
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return target{}, fmt.Errorf("bad port in %q", s)
	}
	return target{Host: host, Port: port}, nil
}

// observe connects to one host and returns the chain it presents, or why it couldn't.
// Verification is off on purpose: CertHalo judges the chain, so an expired or untrusted
// certificate must still be reported.
func observe(t target, timeout time.Duration) observation {
	o := observation{Host: t.Host, Port: t.Port, ObservedAt: time.Now().UTC().Format(time.RFC3339)}
	conf := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10}
	if net.ParseIP(t.Host) == nil {
		conf.ServerName = t.Host
	}
	dialer := &net.Dialer{Timeout: timeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(t.Host, strconv.Itoa(t.Port)), conf)
	if err != nil {
		o.Error = classify(err)
		return o
	}
	defer conn.Close()
	state := conn.ConnectionState()
	for _, c := range state.PeerCertificates { // as the server sent them, leaf first
		o.Chain = append(o.Chain, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})))
	}
	if len(o.Chain) == 0 {
		o.Error = &obsError{Code: "not_tls", Message: "the server sent no certificate"}
		return o
	}
	o.TLS = &tlsInfo{Protocol: tlsVersion(state.Version), Cipher: tls.CipherSuiteName(state.CipherSuite)}
	return o
}

func classify(err error) *obsError {
	msg := err.Error()
	if len(msg) > 200 {
		msg = msg[:200]
	}
	var dnsErr *net.DNSError
	var netErr net.Error
	switch {
	case errors.As(err, &dnsErr):
		return &obsError{Code: "dns", Message: msg}
	case errors.Is(err, syscall.ECONNREFUSED):
		return &obsError{Code: "refused", Message: msg}
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, io.EOF):
		return &obsError{Code: "reset", Message: msg}
	case errors.As(err, &netErr) && netErr.Timeout():
		return &obsError{Code: "timeout", Message: msg}
	case strings.Contains(msg, "tls:") || strings.Contains(msg, "first record does not look like a TLS handshake"):
		return &obsError{Code: "not_tls", Message: msg}
	}
	return &obsError{Code: "other", Message: msg}
}

func tlsVersion(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLSv1.3"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS10:
		return "TLSv1"
	}
	return ""
}

func runOnce(cfg config) int {
	targets, err := readTargets(cfg.targetsFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "certhalo-agent:", err)
		return 1
	}
	var all []observation
	for _, t := range targets {
		all = append(all, observe(t, time.Duration(cfg.timeout)*time.Second))
	}
	status := 0
	for start := 0; start < len(all); start += maxPerReport {
		end := min(start+maxPerReport, len(all))
		r := report{Agent: agentInfo{Name: cfg.name, Version: version, IntervalSeconds: cfg.interval}, Observations: all[start:end]}
		body, _ := json.MarshalIndent(r, "", "  ")
		// Never send key material, whatever went wrong upstream (CertHalo refuses it too).
		if bytes.Contains(body, []byte("PRIVATE KEY")) {
			fmt.Fprintln(os.Stderr, "certhalo-agent: refusing to send a report containing a private key")
			return 2
		}
		if cfg.dryRun {
			fmt.Println(string(body))
			continue
		}
		if err := send(cfg, body); err != nil {
			fmt.Fprintln(os.Stderr, "certhalo-agent:", err)
			status = 2
		}
	}
	return status
}

func send(cfg config, body []byte) error {
	req, _ := http.NewRequest(http.MethodPost, strings.TrimRight(cfg.url, "/")+"/api/v1/reports", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+cfg.key)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "certhalo-agent-go/"+version)
	client := &http.Client{Timeout: 60 * time.Second} // honours HTTPS_PROXY
	res, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sending the report: %w", err)
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("CertHalo answered %d: %s", res.StatusCode, strings.TrimSpace(string(raw)))
	}
	var out struct {
		Accepted int `json:"accepted"`
		Rejected int `json:"rejected"`
		Results  []struct {
			Host    string `json:"host"`
			Port    int    `json:"port"`
			Outcome string `json:"outcome"`
			Error   string `json:"error"`
		} `json:"results"`
	}
	_ = json.Unmarshal(raw, &out)
	fmt.Printf("certhalo-agent: reported %d hosts (%d accepted, %d rejected)\n", out.Accepted+out.Rejected, out.Accepted, out.Rejected)
	for _, r := range out.Results {
		if r.Outcome != "accepted" {
			fmt.Fprintf(os.Stderr, "  %s:%d rejected: %s\n", r.Host, r.Port, r.Error)
		}
	}
	return nil
}

// CertHalo agent (Go): reads the TLS certificate each internal host presents and reports it to
// CertHalo, which grades it and alerts on it. Only certificates are ever sent, never keys.
// Report format: ../spec/report.schema.json. Docs: https://certhalo.com/docs/api#internal
package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/binary"
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
	version         = "1.1.0"
	defaultURL      = "https://certhalo.com"
	defaultInterval = 21600 // 6 hours
	maxPerReport    = 100   // CertHalo's limit per report
)

type target struct {
	Host string
	Port int
	// Proto: "" for TLS from the first byte, or a protocol that switches to TLS on request
	// (STARTTLS): "smtp", "postgres", "mysql" or "ldap".
	Proto string
}

// Schemes a target can start with: the protocol to speak, and its usual port.
var schemes = map[string]struct {
	proto string
	port  int
}{
	"https": {"", 443}, "tls": {"", 443},
	"smtp": {"smtp", 25}, "postgres": {"postgres", 5432}, "postgresql": {"postgres", 5432}, "mysql": {"mysql", 3306}, "ldap": {"ldap", 389},
}

// Ports where STARTTLS is the norm, used when a target has no scheme.
var starttlsPorts = map[int]string{25: "smtp", 587: "smtp", 389: "ldap", 3306: "mysql", 5432: "postgres"}

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

// parseTarget reads "host", "host:port", "[ipv6]:port", optionally with a scheme: "smtp://",
// "postgres://", "mysql://" or "ldap://" for STARTTLS, "https://" or "tls://" for TLS from the
// first byte. Without a scheme, ports 25, 587, 389, 3306 and 5432 use STARTTLS.
func parseTarget(s string) (target, error) {
	proto, defaultPort, explicit := "", 443, false
	if scheme, rest, ok := strings.Cut(s, "://"); ok {
		known, found := schemes[strings.ToLower(scheme)]
		if !found {
			return target{}, fmt.Errorf("unknown scheme %q (use https, smtp, postgres, mysql or ldap)", scheme)
		}
		proto, defaultPort, explicit, s = known.proto, known.port, true, rest
	}
	s = strings.SplitN(s, "/", 2)[0]
	host, portStr, err := net.SplitHostPort(s)
	port := defaultPort
	if err != nil {
		// No port given (or a bare IPv6 address).
		host = strings.Trim(s, "[]")
	} else if port, err = strconv.Atoi(portStr); err != nil || port < 1 || port > 65535 {
		return target{}, fmt.Errorf("bad port in %q", s)
	}
	if !explicit {
		proto = starttlsPorts[port]
	}
	return target{Host: host, Port: port, Proto: proto}, nil
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
	raw, err := net.DialTimeout("tcp", net.JoinHostPort(t.Host, strconv.Itoa(t.Port)), timeout)
	if err != nil {
		o.Error = classify(err)
		return o
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(timeout)) // the whole exchange, STARTTLS and handshake included
	if err := startTLS(raw, t.Proto); err != nil {
		o.Error = classify(err)
		return o
	}
	conn := tls.Client(raw, conf)
	if err := conn.Handshake(); err != nil {
		o.Error = classify(err)
		return o
	}
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

// noTLS: the server answered, but won't switch to TLS (or isn't the server the protocol expects).
type noTLS string

func (e noTLS) Error() string { return string(e) }

// startTLS asks a server that starts in plain text to switch to TLS. Only the few messages each
// protocol needs before its TLS handshake: no login, no data.
func startTLS(c net.Conn, proto string) error {
	switch proto {
	case "smtp":
		return smtpStartTLS(c)
	case "postgres":
		return postgresStartTLS(c)
	case "mysql":
		return mysqlStartTLS(c)
	case "ldap":
		return ldapStartTLS(c)
	}
	return nil
}

func smtpStartTLS(c net.Conn) error {
	r := bufio.NewReader(c)
	if code, _, err := smtpReply(r); err != nil || code != 220 {
		return orNoTLS(err, "the SMTP server didn't greet (%d)", code)
	}
	fmt.Fprint(c, "EHLO certhalo-agent\r\n")
	code, lines, err := smtpReply(r)
	if err != nil || code != 250 {
		return orNoTLS(err, "the SMTP server refused EHLO (%d)", code)
	}
	offered := false
	for _, l := range lines {
		offered = offered || strings.EqualFold(l, "STARTTLS") || strings.HasPrefix(strings.ToUpper(l), "STARTTLS ")
	}
	if !offered {
		return noTLS("the SMTP server doesn't offer STARTTLS")
	}
	fmt.Fprint(c, "STARTTLS\r\n")
	if code, _, err := smtpReply(r); err != nil || code != 220 {
		return orNoTLS(err, "the SMTP server refused STARTTLS (%d)", code)
	}
	return nil
}

// smtpReply reads one reply, which may span several "250-..." lines.
func smtpReply(r *bufio.Reader) (int, []string, error) {
	var lines []string
	for range 100 {
		line, err := r.ReadString('\n')
		if err != nil {
			return 0, nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		code, convErr := strconv.Atoi(line[:min(3, len(line))])
		if len(line) < 3 || convErr != nil {
			return 0, nil, noTLS("not an SMTP server")
		}
		text := ""
		if len(line) > 4 {
			text = line[4:] // after "250-" or "250 "
		}
		lines = append(lines, strings.TrimSpace(text))
		if len(line) == 3 || line[3] != '-' {
			return code, lines, nil
		}
	}
	return 0, nil, noTLS("the SMTP reply is too long")
}

func postgresStartTLS(c net.Conn) error {
	// SSLRequest: length 8, then the code 80877103. The server answers one byte: S (yes) or N (no).
	if _, err := c.Write([]byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}); err != nil {
		return err
	}
	b := make([]byte, 1)
	if _, err := io.ReadFull(c, b); err != nil {
		return err
	}
	switch b[0] {
	case 'S':
		return nil
	case 'N':
		return noTLS("the PostgreSQL server doesn't have TLS turned on")
	}
	return noTLS("not a PostgreSQL server")
}

const (
	mysqlClientProtocol41       = 0x0200
	mysqlClientSSL              = 0x0800
	mysqlClientSecureConnection = 0x8000
)

func mysqlStartTLS(c net.Conn) error {
	payload, err := mysqlPacket(c)
	if err != nil {
		return err
	}
	if len(payload) > 0 && payload[0] == 0xff {
		msg := ""
		if len(payload) > 3 {
			msg = strings.TrimPrefix(string(payload[3:]), "#")
		}
		return noTLS("the MySQL server refused the connection: " + msg)
	}
	// Initial handshake (protocol 10): version string, thread id, 8 bytes of salt, a filler byte, then capabilities.
	end := bytes.IndexByte(payload, 0)
	if len(payload) == 0 || payload[0] != 10 || end < 0 || len(payload) < end+16 {
		return noTLS("not a MySQL server")
	}
	caps := binary.LittleEndian.Uint16(payload[end+14:])
	if caps&mysqlClientSSL == 0 {
		return noTLS("the MySQL server doesn't have TLS turned on")
	}
	// SSLRequest: our capabilities, max packet size, character set, 23 zero bytes. Sequence number 1.
	req := make([]byte, 4+32)
	req[0], req[3] = 32, 1
	binary.LittleEndian.PutUint32(req[4:], mysqlClientSSL|mysqlClientProtocol41|mysqlClientSecureConnection)
	binary.LittleEndian.PutUint32(req[8:], 1<<24)
	req[12] = 45 // utf8mb4
	_, err = c.Write(req)
	return err
}

func mysqlPacket(c net.Conn) ([]byte, error) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(c, hdr); err != nil {
		return nil, err
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if n > 1<<16 {
		return nil, noTLS("not a MySQL server")
	}
	payload := make([]byte, n)
	_, err := io.ReadFull(c, payload)
	return payload, err
}

// The StartTLS extended request (RFC 4511), message ID 1.
var ldapStartTLSRequest = append([]byte{0x30, 0x1d, 0x02, 0x01, 0x01, 0x77, 0x18, 0x80, 0x16}, "1.3.6.1.4.1.1466.20037"...)

func ldapStartTLS(c net.Conn) error {
	if _, err := c.Write(ldapStartTLSRequest); err != nil {
		return err
	}
	tag, msg, err := berRead(c)
	if err != nil {
		return err
	}
	if tag != 0x30 {
		return noTLS("not an LDAP server")
	}
	// LDAPMessage: messageID, then the ExtendedResponse [APPLICATION 24], which starts with resultCode.
	_, _, rest, ok := berNext(msg)
	if !ok {
		return noTLS("not an LDAP server")
	}
	op, resp, _, ok := berNext(rest)
	if !ok || op != 0x78 {
		return noTLS("not an LDAP server")
	}
	code, value, _, ok := berNext(resp)
	if !ok || code != 0x0a || len(value) != 1 {
		return noTLS("not an LDAP server")
	}
	if value[0] != 0 {
		return noTLS(fmt.Sprintf("the LDAP server refused StartTLS (result %d)", value[0]))
	}
	return nil
}

// berRead reads one BER element from the connection: its tag and contents (64 KB at most).
func berRead(c net.Conn) (byte, []byte, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(c, head); err != nil {
		return 0, nil, err
	}
	n := int(head[1])
	if n&0x80 != 0 {
		size := n & 0x7f
		if size == 0 || size > 3 {
			return 0, nil, noTLS("not an LDAP server")
		}
		b := make([]byte, size)
		if _, err := io.ReadFull(c, b); err != nil {
			return 0, nil, err
		}
		n = 0
		for _, x := range b {
			n = n<<8 | int(x)
		}
	}
	if n > 1<<16 {
		return 0, nil, noTLS("not an LDAP server")
	}
	body := make([]byte, n)
	_, err := io.ReadFull(c, body)
	return head[0], body, err
}

// berNext splits the first BER element off a buffer: its tag, its contents and what follows.
func berNext(b []byte) (tag byte, value, rest []byte, ok bool) {
	if len(b) < 2 {
		return 0, nil, nil, false
	}
	n, at := int(b[1]), 2
	if n&0x80 != 0 {
		size := n & 0x7f
		if size == 0 || size > 3 || len(b) < 2+size {
			return 0, nil, nil, false
		}
		n = 0
		for _, x := range b[2 : 2+size] {
			n = n<<8 | int(x)
		}
		at += size
	}
	if len(b) < at+n {
		return 0, nil, nil, false
	}
	return b[0], b[at : at+n], b[at+n:], true
}

func orNoTLS(err error, format string, code int) error {
	if err != nil {
		return err
	}
	return noTLS(fmt.Sprintf(format, code))
}

func classify(err error) *obsError {
	msg := err.Error()
	if len(msg) > 200 {
		msg = msg[:200]
	}
	var dnsErr *net.DNSError
	var netErr net.Error
	var refusedTLS noTLS
	switch {
	case errors.As(err, &refusedTLS):
		return &obsError{Code: "not_tls", Message: msg}
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

// SPDX-FileCopyrightText: 2026 Daniel Eder
//
// SPDX-License-Identifier: CC0-1.0

package proxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daniel-eder/coolify-mail-proxy/internal/config"
	"github.com/daniel-eder/coolify-mail-proxy/internal/guard"
)

const (
	goodUser = "u@a.com"
	goodPass = "s3cret pw"
)

func testCert(t *testing.T, names ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IsCA:        true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// fake is a minimal implicit-TLS mail server that accepts goodUser/goodPass.
// After login, every line is echoed back as "ECHO <line>".
type fake struct {
	proto  string
	conns  atomic.Int32 // connections
	logins atomic.Int32 // login attempts
}

func startFake(t *testing.T, proto string) (*fake, int, *x509.CertPool) {
	t.Helper()
	cert, pool := testCert(t, "upstream.test")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	f := &fake{proto: proto}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			f.conns.Add(1)
			go f.serve(c)
		}
	}()
	return f, ln.Addr().(*net.TCPAddr).Port, pool
}

func checkPlain(b64 string) bool {
	d, err := base64.StdEncoding.DecodeString(b64)
	p := strings.Split(string(d), "\x00")
	return err == nil && len(p) == 3 && p[1] == goodUser && p[2] == goodPass
}

func (f *fake) serve(c net.Conn) {
	defer c.Close()
	w := func(s string) { io.WriteString(c, s) }
	r := bufio.NewReader(c)
	read := func() string { l, _ := r.ReadString('\n'); return strings.TrimRight(l, "\r\n") }
	authed := false
	switch f.proto {
	case config.ProtoIMAP:
		w("* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] ready\r\n")
	case config.ProtoPOP3:
		w("+OK <123@upstream> ready\r\n")
	case config.ProtoSMTP:
		w("220-upstream.test ESMTP\r\n220 hello\r\n")
	}
	user := ""
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if authed {
			w("ECHO " + line + "\r\n")
			continue
		}
		fl := strings.Fields(line)
		up := func(i int) string {
			if i < len(fl) {
				return strings.ToUpper(fl[i])
			}
			return ""
		}
		switch f.proto {
		case config.ProtoIMAP:
			tag := fl[0]
			switch up(1) {
			case "CAPABILITY":
				w("* CAPABILITY IMAP4rev1 IDLE LITERAL+ AUTH=PLAIN AUTH=CRAM-MD5\r\n" + tag + " OK done\r\n")
			case "LOGOUT":
				w("* BYE\r\n" + tag + " OK\r\n")
			case "LOGIN":
				f.logins.Add(1)
				var args []string
				if m := imapLiteral.FindStringSubmatch(line); m != nil {
					// LOGIN {n} / user {m} / pass
					n, _ := strconv.Atoi(m[1])
					w("+ go\r\n")
					buf := make([]byte, n)
					io.ReadFull(r, buf)
					rest := read()
					m2 := imapLiteral.FindStringSubmatch(rest)
					n2, _ := strconv.Atoi(m2[1])
					w("+ go\r\n")
					buf2 := make([]byte, n2)
					io.ReadFull(r, buf2)
					read()
					args = []string{string(buf), string(buf2)}
				} else {
					args = imapTokens(line)[2:]
				}
				if len(args) == 2 && args[0] == goodUser && args[1] == goodPass {
					authed = true
					w(tag + " OK [CAPABILITY IMAP4rev1 IDLE] Logged in\r\n")
				} else {
					w(tag + " NO [AUTHENTICATIONFAILED] Invalid credentials\r\n")
				}
			case "AUTHENTICATE":
				f.logins.Add(1)
				w("+ \r\n")
				if checkPlain(read()) {
					authed = true
					w(tag + " OK Logged in\r\n")
				} else {
					w(tag + " NO [AUTHENTICATIONFAILED] Invalid credentials\r\n")
				}
			default:
				w(tag + " BAD unexpected\r\n")
			}
		case config.ProtoPOP3:
			switch up(0) {
			case "CAPA":
				w("+OK caps\r\nUSER\r\nSASL PLAIN CRAM-MD5\r\nTOP\r\n.\r\n")
			case "QUIT":
				w("+OK bye\r\n")
				return
			case "USER":
				user = strings.TrimPrefix(line, "USER ")
				w("+OK\r\n")
			case "PASS":
				f.logins.Add(1)
				if user == goodUser && strings.TrimPrefix(line, "PASS ") == goodPass {
					authed = true
					w("+OK logged in\r\n")
				} else {
					w("-ERR [AUTH] Invalid\r\n")
				}
			case "AUTH":
				f.logins.Add(1)
				if checkPlain(fl[2]) {
					authed = true
					w("+OK logged in\r\n")
				} else {
					w("-ERR [AUTH] Invalid\r\n")
				}
			default:
				w("-ERR unexpected\r\n")
			}
		case config.ProtoSMTP:
			switch up(0) {
			case "EHLO":
				w("250-upstream.test\r\n250-AUTH PLAIN LOGIN CRAM-MD5\r\n250-SIZE 1000\r\n250 8BITMIME\r\n")
			case "QUIT":
				w("221 bye\r\n")
				return
			case "AUTH":
				f.logins.Add(1)
				ok := false
				if up(1) == "PLAIN" {
					ok = checkPlain(fl[2])
				} else {
					w("334 VXNlcm5hbWU6\r\n")
					u, _ := base64.StdEncoding.DecodeString(read())
					w("334 UGFzc3dvcmQ6\r\n")
					p, _ := base64.StdEncoding.DecodeString(read())
					ok = string(u) == goodUser && string(p) == goodPass
				}
				if ok {
					authed = true
					w("235 2.7.0 Authentication successful\r\n")
				} else {
					w("535 5.7.8 Authentication failed\r\n")
				}
			default:
				w("500 unexpected\r\n")
			}
		}
	}
}

type harness struct {
	t     *testing.T
	addr  string
	front *x509.CertPool
	up    *fake
	srv   *Server
}

func newHarness(t *testing.T, kind string, mods ...func(*Server)) *harness {
	t.Helper()
	k := config.Kinds[kind]
	f, upPort, upPool := startFake(t, k.Protocol)
	frontCert, frontPool := testCert(t, "mail.a.com")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	gcfg := guard.DefaultConfig()
	gcfg.Domains = []string{"a.com"}
	gcfg.ConnRateLimit = 0
	up := &Upstream{
		Protocol: k.Protocol, Addr: "127.0.0.1:" + strconv.Itoa(upPort),
		TLS:         &tls.Config{ServerName: "upstream.test", RootCAs: upPool},
		DialTimeout: 2 * time.Second, Hostname: "mail.a.com", Log: log,
	}
	s := &Server{
		Listener:       config.Listener{Kind: kind, Protocol: k.Protocol, Implicit: k.Implicit},
		TLS:            &tls.Config{Certificates: []tls.Certificate{frontCert}},
		Upstream:       up,
		Guard:          guard.New(gcfg, log),
		Hostname:       "mail.a.com",
		MaxConnsPerIP:  5,
		PreAuthTimeout: 5 * time.Second,
		IdleTimeout:    5 * time.Second,
		Log:            log,
	}
	for _, m := range mods {
		m(s)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	up.Probe(ctx)
	go s.Serve(ctx, ln)
	return &harness{t: t, addr: ln.Addr().String(), front: frontPool, up: f, srv: s}
}

type client struct {
	t    *testing.T
	conn net.Conn
	r    *bufio.Reader
	h    *harness
}

func (h *harness) dial(implicit bool) *client {
	var c net.Conn
	var err error
	if implicit {
		c, err = tls.Dial("tcp", h.addr, &tls.Config{ServerName: "mail.a.com", RootCAs: h.front})
	} else {
		c, err = net.Dial("tcp", h.addr)
	}
	if err != nil {
		h.t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	h.t.Cleanup(func() { c.Close() })
	return &client{t: h.t, conn: c, r: bufio.NewReader(c), h: h}
}

func (c *client) send(s string) { io.WriteString(c.conn, s) }

func (c *client) expect(want ...string) {
	c.t.Helper()
	for _, w := range want {
		got, err := c.r.ReadString('\n')
		if err != nil {
			c.t.Fatalf("reading (want %q): %v", w, err)
		}
		if got != w {
			c.t.Fatalf("got %q, want %q", got, w)
		}
	}
}

func (c *client) expectClosed() {
	c.t.Helper()
	if l, err := c.r.ReadString('\n'); err == nil {
		c.t.Fatalf("expected connection to be closed, got %q", l)
	}
}

func (c *client) upgrade() {
	c.t.Helper()
	if c.r.Buffered() > 0 {
		c.t.Fatal("unexpected buffered data")
	}
	tc := tls.Client(c.conn, &tls.Config{ServerName: "mail.a.com", RootCAs: c.h.front})
	if err := tc.Handshake(); err != nil {
		c.t.Fatal(err)
	}
	c.conn, c.r = tc, bufio.NewReader(tc)
}

func b64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

const (
	imapTLSCaps   = "IMAP4rev1 IDLE LITERAL+ SASL-IR AUTH=PLAIN AUTH=LOGIN"
	imapPlainCaps = "IMAP4rev1 IDLE LITERAL+ STARTTLS LOGINDISABLED"
)

// ---------- IMAP ----------

func TestIMAPLocalUntilLogin(t *testing.T) {
	h := newHarness(t, "imaps")
	before := h.up.conns.Load()
	c := h.dial(true)
	c.expect("* OK [CAPABILITY " + imapTLSCaps + "] mail.a.com IMAP ready\r\n")
	c.send("a1 CAPABILITY\r\n")
	c.expect("* CAPABILITY "+imapTLSCaps+"\r\n", "a1 OK CAPABILITY completed\r\n")
	c.send("a2 ID (\"name\" \"x\")\r\n")
	c.expect("* ID NIL\r\n", "a2 OK ID completed\r\n")
	c.send("a3 SELECT INBOX\r\n")
	c.expect("a3 BAD Command not allowed before login\r\n")
	c.send("a4 LOGOUT\r\n")
	c.expect("* BYE Logging out\r\n", "a4 OK LOGOUT completed\r\n")
	if n := h.up.conns.Load(); n != before {
		t.Fatalf("upstream contacted %d times before login", n-before)
	}
}

func TestIMAPLogin(t *testing.T) {
	c := newHarness(t, "imaps").dial(true)
	c.expect("* OK [CAPABILITY " + imapTLSCaps + "] mail.a.com IMAP ready\r\n")
	c.send("a1 LOGIN u@a.com \"s3cret pw\"\r\n")
	c.expect("a1 OK [CAPABILITY IMAP4rev1 IDLE] Logged in\r\n")
	c.send("a2 SELECT INBOX\r\n")
	c.expect("ECHO a2 SELECT INBOX\r\n")
}

func TestIMAPLoginLiterals(t *testing.T) {
	c := newHarness(t, "imaps").dial(true)
	c.expect("* OK [CAPABILITY " + imapTLSCaps + "] mail.a.com IMAP ready\r\n")
	c.send("a1 LOGIN {7}\r\n")
	c.expect("+ Ready for literal data\r\n")
	c.send("u@a.com {9+}\r\ns3cret pw\r\n")
	c.expect("a1 OK [CAPABILITY IMAP4rev1 IDLE] Logged in\r\n")
}

func TestIMAPLoginNonASCIIUsesUpstreamLiteral(t *testing.T) {
	h := newHarness(t, "imaps")
	c := h.dial(true)
	c.expect("* OK [CAPABILITY " + imapTLSCaps + "] mail.a.com IMAP ready\r\n")
	c.send("a1 LOGIN u@a.com {6+}\r\npässw\r\n")
	c.expect("a1 NO [AUTHENTICATIONFAILED] Authentication failed\r\n")
	if h.up.logins.Load() != 1 {
		t.Fatal("login not forwarded")
	}
}

func TestIMAPAuthenticatePlain(t *testing.T) {
	c := newHarness(t, "imaps").dial(true)
	c.expect("* OK [CAPABILITY " + imapTLSCaps + "] mail.a.com IMAP ready\r\n")
	c.send("a1 AUTHENTICATE PLAIN\r\n")
	c.expect("+ \r\n")
	c.send(b64("\x00u@a.com\x00s3cret pw") + "\r\n")
	c.expect("a1 OK [CAPABILITY IMAP4rev1 IDLE] Logged in\r\n")
}

func TestIMAPAuthenticateLoginSASLIR(t *testing.T) {
	c := newHarness(t, "imaps").dial(true)
	c.expect("* OK [CAPABILITY " + imapTLSCaps + "] mail.a.com IMAP ready\r\n")
	c.send("a1 AUTHENTICATE LOGIN " + b64(goodUser) + "\r\n")
	c.expect("+ UGFzc3dvcmQ6\r\n")
	c.send(b64(goodPass) + "\r\n")
	c.expect("a1 OK [CAPABILITY IMAP4rev1 IDLE] Logged in\r\n")
}

func TestIMAPUnsupportedMechanism(t *testing.T) {
	h := newHarness(t, "imaps")
	c := h.dial(true)
	c.expect("* OK [CAPABILITY " + imapTLSCaps + "] mail.a.com IMAP ready\r\n")
	c.send("a1 AUTHENTICATE CRAM-MD5\r\n")
	c.expect("a1 NO Unsupported authentication mechanism\r\n")
	if h.up.logins.Load() != 0 {
		t.Fatal("unsupported mechanism forwarded")
	}
}

func TestIMAPBanAfterFailures(t *testing.T) {
	h := newHarness(t, "imaps")
	c := h.dial(true)
	c.expect("* OK [CAPABILITY " + imapTLSCaps + "] mail.a.com IMAP ready\r\n")
	c.send("a1 LOGIN u@a.com wrong1\r\n")
	c.expect("a1 NO [AUTHENTICATIONFAILED] Authentication failed\r\n")
	// Same wrong password again: answered locally.
	c.send("a2 LOGIN u@a.com wrong1\r\n")
	c.expect("a2 NO [AUTHENTICATIONFAILED] Authentication failed\r\n")
	if n := h.up.logins.Load(); n != 1 {
		t.Fatalf("upstream saw %d logins, want 1", n)
	}
	c.send("a3 LOGIN u@a.com wrong2\r\n")
	c.expect("a3 NO [AUTHENTICATIONFAILED] Authentication failed\r\n", "* BYE Too many failed logins\r\n")
	c.expectClosed()

	c = h.dial(true)
	c.expect("* OK [CAPABILITY " + imapTLSCaps + "] mail.a.com IMAP ready\r\n")
	c.send("b1 LOGIN u@a.com wrong3\r\n")
	c.expect("b1 NO [AUTHENTICATIONFAILED] Authentication failed\r\n", "* BYE Too many failed logins\r\n")
	c.expectClosed()

	// Banned: the TLS handshake is not even started.
	raw, err := net.Dial("tcp", h.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	raw.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := raw.Read(make([]byte, 1)); err == nil {
		t.Fatal("banned client got data")
	}
}

func TestIMAPUnknownDomainNotForwarded(t *testing.T) {
	h := newHarness(t, "imaps")
	c := h.dial(true)
	c.expect("* OK [CAPABILITY " + imapTLSCaps + "] mail.a.com IMAP ready\r\n")
	c.send("a1 LOGIN admin password\r\n")
	c.expect("a1 NO [AUTHENTICATIONFAILED] Authentication failed\r\n")
	if h.up.conns.Load() != 1 { // the probe only
		t.Fatal("unknown-domain login reached upstream")
	}
}

func TestPlainIMAPRequiresTLS(t *testing.T) {
	c := newHarness(t, "imap").dial(false)
	c.expect("* OK [CAPABILITY " + imapPlainCaps + "] mail.a.com IMAP ready\r\n")
	c.send("a1 LOGIN u@a.com \"s3cret pw\"\r\n")
	c.expect("a1 NO [PRIVACYREQUIRED] Use STARTTLS before logging in\r\n")
	c.send("a2 STARTTLS\r\n")
	c.expect("a2 OK Begin TLS negotiation now\r\n")
	c.upgrade()
	c.send("a3 CAPABILITY\r\n")
	c.expect("* CAPABILITY "+imapTLSCaps+"\r\n", "a3 OK CAPABILITY completed\r\n")
	c.send("a4 LOGIN u@a.com \"s3cret pw\"\r\n")
	c.expect("a4 OK [CAPABILITY IMAP4rev1 IDLE] Logged in\r\n")
	c.send("a5 NOOP\r\n")
	c.expect("ECHO a5 NOOP\r\n")
}

func TestPlainIMAPAllowPlainAuth(t *testing.T) {
	c := newHarness(t, "imap", func(s *Server) { s.AllowPlainAuth = true }).dial(false)
	c.expect("* OK [CAPABILITY IMAP4rev1 IDLE LITERAL+ STARTTLS SASL-IR AUTH=PLAIN AUTH=LOGIN] mail.a.com IMAP ready\r\n")
	c.send("a1 LOGIN u@a.com \"s3cret pw\"\r\n")
	c.expect("a1 OK [CAPABILITY IMAP4rev1 IDLE] Logged in\r\n")
}

func TestStartTLSInjectionRejected(t *testing.T) {
	c := newHarness(t, "imap").dial(false)
	c.expect("* OK [CAPABILITY " + imapPlainCaps + "] mail.a.com IMAP ready\r\n")
	c.send("a1 STARTTLS\r\na2 LOGIN u p\r\n")
	c.expect("a1 OK Begin TLS negotiation now\r\n")
	c.expectClosed()
}

func TestBannedPlainClientGetsBye(t *testing.T) {
	h := newHarness(t, "imap", func(s *Server) { s.AllowPlainAuth = true })
	for i := range 3 {
		h.srv.Guard.LoginResult("127.0.0.1", goodUser, "x"+strconv.Itoa(i), false)
	}
	c := h.dial(false)
	c.expect("* BYE Access denied\r\n")
	c.expectClosed()
}

// ---------- POP3 ----------

func TestPOP3(t *testing.T) {
	h := newHarness(t, "pop3s")
	c := h.dial(true)
	c.expect("+OK mail.a.com POP3 ready\r\n")
	c.send("CAPA\r\n")
	c.expect("+OK Capability list follows\r\n", "TOP\r\n", "USER\r\n", "SASL PLAIN LOGIN\r\n", ".\r\n")
	c.send("STAT\r\n")
	c.expect("-ERR Command not allowed before login\r\n")
	c.send("USER u@a.com\r\n")
	c.expect("+OK\r\n")
	c.send("PASS nope\r\n")
	c.expect("-ERR [AUTH] Authentication failed\r\n")
	c.send("USER u@a.com\r\n")
	c.expect("+OK\r\n")
	c.send("PASS s3cret pw\r\n")
	c.expect("+OK logged in\r\n")
	c.send("STAT\r\n")
	c.expect("ECHO STAT\r\n")
}

func TestPOP3AuthLogin(t *testing.T) {
	c := newHarness(t, "pop3s").dial(true)
	c.expect("+OK mail.a.com POP3 ready\r\n")
	c.send("AUTH LOGIN\r\n")
	c.expect("+ VXNlcm5hbWU6\r\n")
	c.send(b64(goodUser) + "\r\n")
	c.expect("+ UGFzc3dvcmQ6\r\n")
	c.send(b64(goodPass) + "\r\n")
	c.expect("+OK logged in\r\n")
}

func TestPlainPOP3(t *testing.T) {
	c := newHarness(t, "pop3").dial(false)
	c.expect("+OK mail.a.com POP3 ready\r\n")
	c.send("CAPA\r\n")
	c.expect("+OK Capability list follows\r\n", "TOP\r\n", "STLS\r\n", ".\r\n")
	c.send("USER u@a.com\r\n")
	c.expect("-ERR Use STLS before logging in\r\n")
	c.send("STLS\r\n")
	c.expect("+OK Begin TLS negotiation\r\n")
	c.upgrade()
	c.send("AUTH PLAIN " + b64("\x00u@a.com\x00s3cret pw") + "\r\n")
	c.expect("+OK logged in\r\n")
}

// ---------- SMTP ----------

func TestSMTPImplicit(t *testing.T) {
	c := newHarness(t, "smtps").dial(true)
	c.expect("220 mail.a.com ESMTP ready\r\n")
	c.send("MAIL FROM:<a@a.com>\r\n")
	c.expect("530 5.7.0 Authentication required\r\n")
	c.send("EHLO me\r\n")
	c.expect("250-mail.a.com\r\n", "250-SIZE 1000\r\n", "250-8BITMIME\r\n", "250 AUTH PLAIN LOGIN\r\n")
	c.send("AUTH PLAIN " + b64("\x00u@a.com\x00s3cret pw") + "\r\n")
	c.expect("235 2.7.0 Authentication successful\r\n")
	c.send("MAIL FROM:<a@a.com>\r\n")
	c.expect("ECHO MAIL FROM:<a@a.com>\r\n")
}

func TestSMTPAuthLogin(t *testing.T) {
	c := newHarness(t, "smtps").dial(true)
	c.expect("220 mail.a.com ESMTP ready\r\n")
	c.send("EHLO me\r\n")
	c.expect("250-mail.a.com\r\n", "250-SIZE 1000\r\n", "250-8BITMIME\r\n", "250 AUTH PLAIN LOGIN\r\n")
	c.send("AUTH LOGIN\r\n")
	c.expect("334 VXNlcm5hbWU6\r\n")
	c.send(b64(goodUser) + "\r\n")
	c.expect("334 UGFzc3dvcmQ6\r\n")
	c.send(b64("bad") + "\r\n")
	c.expect("535 5.7.8 Authentication credentials invalid\r\n")
	c.send("AUTH LOGIN " + b64(goodUser) + "\r\n")
	c.expect("334 UGFzc3dvcmQ6\r\n")
	c.send("*\r\n")
	c.expect("501 5.7.0 Authentication canceled\r\n")
}

func TestStartTLSSMTP(t *testing.T) {
	h := newHarness(t, "submission")
	c := h.dial(false)
	c.expect("220 mail.a.com ESMTP ready\r\n")
	c.send("EHLO me\r\n")
	c.expect("250-mail.a.com\r\n", "250-SIZE 1000\r\n", "250-8BITMIME\r\n", "250 STARTTLS\r\n")
	c.send("AUTH PLAIN " + b64("\x00u@a.com\x00s3cret pw") + "\r\n")
	c.expect("530 5.7.0 Must issue a STARTTLS command first\r\n")
	c.send("STARTTLS\r\n")
	c.expect("220 2.0.0 Ready to start TLS\r\n")
	c.upgrade()
	c.send("AUTH PLAIN " + b64("\x00u@a.com\x00s3cret pw") + "\r\n")
	c.expect("503 5.5.1 Send EHLO first\r\n")
	c.send("EHLO me\r\n")
	c.expect("250-mail.a.com\r\n", "250-SIZE 1000\r\n", "250-8BITMIME\r\n", "250 AUTH PLAIN LOGIN\r\n")
	c.send("AUTH PLAIN\r\n")
	c.expect("334 \r\n")
	c.send(b64("\x00u@a.com\x00s3cret pw") + "\r\n")
	c.expect("235 2.7.0 Authentication successful\r\n")
	c.send("MAIL FROM:<a@a.com>\r\n")
	c.expect("ECHO MAIL FROM:<a@a.com>\r\n")
	if n := h.up.logins.Load(); n != 1 {
		t.Fatalf("upstream saw %d logins, want 1", n)
	}
}

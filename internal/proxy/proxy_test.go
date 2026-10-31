package proxy

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coolify-mail-proxy/mailproxy/internal/config"
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

// fakeUpstream emulates a minimal implicit-TLS mail server. Commands it does
// not know are echoed back as "ECHO <line>".
func fakeUpstream(t *testing.T, proto string) (int, *x509.CertPool) {
	t.Helper()
	cert, pool := testCert(t, "upstream.test")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveFake(c, proto)
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port, pool
}

func serveFake(c net.Conn, proto string) {
	defer c.Close()
	w := func(s string) { io.WriteString(c, s) }
	switch proto {
	case config.ProtoIMAP:
		w("* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] ready\r\n")
	case config.ProtoPOP3:
		w("+OK ready\r\n")
	case config.ProtoSMTP:
		w("220-upstream.test ESMTP\r\n220 hello\r\n")
	}
	r := bufio.NewReader(c)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		f := strings.Fields(line)
		switch {
		case proto == config.ProtoIMAP && len(f) >= 2 && strings.EqualFold(f[1], "CAPABILITY"):
			w("* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n" + f[0] + " OK done\r\n")
		case proto == config.ProtoPOP3 && len(f) >= 1 && strings.EqualFold(f[0], "CAPA"):
			w("+OK caps\r\nUSER\r\nSASL PLAIN\r\n.\r\n")
		case proto == config.ProtoSMTP && len(f) >= 1 && strings.EqualFold(f[0], "EHLO"):
			w("250-upstream.test\r\n250-AUTH PLAIN\r\n250 8BITMIME\r\n")
		default:
			w("ECHO " + line)
		}
	}
}

type harness struct {
	t     *testing.T
	addr  string
	front *x509.CertPool
}

func newHarness(t *testing.T, kind string) *harness {
	t.Helper()
	k := config.Kinds[kind]
	upPort, upPool := fakeUpstream(t, k.Protocol)
	frontCert, frontPool := testCert(t, "mail.a.com")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{
		Listener: config.Listener{Kind: kind, Protocol: k.Protocol, Implicit: k.Implicit,
			Upstream: config.Upstream{Host: "127.0.0.1", Port: upPort}},
		TLS:           &tls.Config{Certificates: []tls.Certificate{frontCert}},
		UpstreamTLS:   &tls.Config{ServerName: "upstream.test", RootCAs: upPool},
		MaxConnsPerIP: 5,
		IdleTimeout:   5 * time.Second,
		DialTimeout:   2 * time.Second,
		Log:           slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go s.Serve(ctx, ln)
	return &harness{t: t, addr: "127.0.0.1:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port), front: frontPool}
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

func TestImplicitIMAP(t *testing.T) {
	c := newHarness(t, "imaps").dial(true)
	c.expect("* OK [CAPABILITY IMAP4rev1 AUTH=PLAIN] ready\r\n")
	c.send("a1 CAPABILITY\r\n")
	c.expect("* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n", "a1 OK done\r\n")
}

func TestPlainIMAP(t *testing.T) {
	c := newHarness(t, "imap").dial(false)
	c.expect("* OK [CAPABILITY STARTTLS IMAP4rev1 AUTH=PLAIN] ready\r\n")
	c.send("a1 CAPABILITY\r\n")
	c.expect("* CAPABILITY STARTTLS IMAP4rev1 AUTH=PLAIN\r\n", "a1 OK done\r\n")
	c.send("a2 LOGIN u p\r\n")
	c.expect("ECHO a2 LOGIN u p\r\n")
	c.send("a3 SELECT INBOX\r\n")
	c.expect("ECHO a3 SELECT INBOX\r\n")
}

func TestStartTLSIMAP(t *testing.T) {
	c := newHarness(t, "imap").dial(false)
	c.expect("* OK [CAPABILITY STARTTLS IMAP4rev1 AUTH=PLAIN] ready\r\n")
	c.send("a1 STARTTLS\r\n")
	c.expect("a1 OK Begin TLS negotiation now\r\n")
	c.upgrade()
	c.send("a2 CAPABILITY\r\n")
	c.expect("* CAPABILITY IMAP4rev1 AUTH=PLAIN\r\n", "a2 OK done\r\n")
	c.send("a3 LOGIN u p\r\n")
	c.expect("ECHO a3 LOGIN u p\r\n")
}

func TestStartTLSInjectionRejected(t *testing.T) {
	c := newHarness(t, "imap").dial(false)
	c.expect("* OK [CAPABILITY STARTTLS IMAP4rev1 AUTH=PLAIN] ready\r\n")
	c.send("a1 STARTTLS\r\na2 LOGIN u p\r\n")
	c.expect("a1 OK Begin TLS negotiation now\r\n")
	if _, err := c.r.ReadString('\n'); err == nil {
		t.Fatal("expected connection to be closed")
	}
}

func TestImplicitPOP3(t *testing.T) {
	c := newHarness(t, "pop3s").dial(true)
	c.expect("+OK ready\r\n")
	c.send("CAPA\r\n")
	c.expect("+OK caps\r\n", "USER\r\n", "SASL PLAIN\r\n", ".\r\n")
}

func TestPlainPOP3(t *testing.T) {
	c := newHarness(t, "pop3").dial(false)
	c.expect("+OK ready\r\n")
	c.send("CAPA\r\n")
	c.expect("+OK caps\r\n", "USER\r\n", "SASL PLAIN\r\n", "STLS\r\n", ".\r\n")
	c.send("USER bob\r\n")
	c.expect("ECHO USER bob\r\n")
}

func TestStartTLSPOP3(t *testing.T) {
	c := newHarness(t, "pop3").dial(false)
	c.expect("+OK ready\r\n")
	c.send("STLS\r\n")
	c.expect("+OK Begin TLS negotiation\r\n")
	c.upgrade()
	c.send("CAPA\r\n")
	c.expect("+OK caps\r\n", "USER\r\n", "SASL PLAIN\r\n", ".\r\n")
}

func TestImplicitSMTP(t *testing.T) {
	c := newHarness(t, "smtps").dial(true)
	c.expect("220-upstream.test ESMTP\r\n", "220 hello\r\n")
	c.send("EHLO me\r\n")
	c.expect("250-upstream.test\r\n", "250-AUTH PLAIN\r\n", "250 8BITMIME\r\n")
}

func TestPlainSMTP(t *testing.T) {
	c := newHarness(t, "submission").dial(false)
	c.expect("220-upstream.test ESMTP\r\n", "220 hello\r\n")
	c.send("EHLO me\r\n")
	c.expect("250-upstream.test\r\n", "250-AUTH PLAIN\r\n", "250-8BITMIME\r\n", "250 STARTTLS\r\n")
	c.send("AUTH PLAIN xyz\r\n")
	c.expect("ECHO AUTH PLAIN xyz\r\n")
}

func TestStartTLSSMTP(t *testing.T) {
	c := newHarness(t, "submission").dial(false)
	c.expect("220-upstream.test ESMTP\r\n", "220 hello\r\n")
	c.send("EHLO me\r\n")
	c.expect("250-upstream.test\r\n", "250-AUTH PLAIN\r\n", "250-8BITMIME\r\n", "250 STARTTLS\r\n")
	c.send("STARTTLS\r\n")
	c.expect("220 2.0.0 Ready to start TLS\r\n")
	c.upgrade()
	c.send("EHLO me\r\n")
	c.expect("250-upstream.test\r\n", "250-AUTH PLAIN\r\n", "250 8BITMIME\r\n")
	c.send("MAIL FROM:<a@a.com>\r\n")
	c.expect("ECHO MAIL FROM:<a@a.com>\r\n")
}

func TestSMTPAddStartTLSSingleLine(t *testing.T) {
	got := smtpAddStartTLS([]string{"250 host\r\n"})
	if strings.Join(got, "") != "250-host\r\n250 STARTTLS\r\n" {
		t.Fatalf("%q", got)
	}
}

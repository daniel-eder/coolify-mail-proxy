// SPDX-FileCopyrightText: 2026 Daniel Eder
//
// SPDX-License-Identifier: CC0-1.0

package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/daniel-eder/coolify-mail-proxy/internal/config"
)

const (
	maxLine          = 8192
	maxResponseLines = 1000
	// maxPreAuthCommands limits commands before login per connection.
	maxPreAuthCommands = 50
	// maxLoginAttempts per connection; the connection is closed afterwards.
	maxLoginAttempts = 3
	// upstreamLoginTimeout bounds the upstream exchange during login.
	upstreamLoginTimeout = 30 * time.Second
)

var (
	errLogout       = errors.New("client logged out")
	errTooMany      = errors.New("too many commands before login")
	errBanned       = errors.New("client banned")
	errMaxAttempts  = errors.New("too many failed logins on this connection")
	errSASLCanceled = errors.New("authentication canceled")
	errSASLSyntax   = errors.New("invalid authentication data")
	errSASLMech     = errors.New("unsupported mechanism")
)

// session holds both ends of a connection.
type session struct {
	srv     *Server
	ctx     context.Context
	ip      string
	log     *slog.Logger
	client  net.Conn
	cic     *idleConn
	clientR *bufio.Reader
	tls     bool // client side encrypted

	upstream *tls.Conn
	uic      *idleConn
	upR      *bufio.Reader

	user     string // logged-in user
	attempts int
	commands int
}

type creds struct{ authz, user, pass string }

type outcome int

const (
	authOK outcome = iota
	authFail
	authTemp
)

// loginResult is returned by tryLogin.
type loginResult struct {
	out   outcome
	reply []string // upstream reply lines (success only)
	ban   bool     // client IP is banned: close the connection
}

func (s *session) front() error {
	switch s.srv.Listener.Protocol {
	case config.ProtoIMAP:
		return s.imap()
	case config.ProtoPOP3:
		return s.pop3()
	case config.ProtoSMTP:
		return s.smtp()
	}
	return fmt.Errorf("unsupported protocol %q", s.srv.Listener.Protocol)
}

func (s *session) authAllowed() bool { return s.tls || s.srv.AllowPlainAuth }

// starttlsOffered reports whether STARTTLS/STLS should be advertised.
func (s *session) starttlsOffered() bool { return !s.tls && !s.srv.Listener.Implicit }

func (s *session) countCommand() error {
	s.commands++
	if s.commands > maxPreAuthCommands {
		return errTooMany
	}
	return nil
}

func readLine(r *bufio.Reader) (string, error) {
	var b []byte
	for {
		chunk, err := r.ReadSlice('\n')
		b = append(b, chunk...)
		if len(b) > maxLine {
			return "", errors.New("line too long")
		}
		if err == nil {
			return string(b), nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			if err == io.EOF && len(b) > 0 {
				return string(b), nil
			}
			return "", err
		}
	}
}

func trimCRLF(s string) string { return strings.TrimRight(s, "\r\n") }

func (s *session) toClient(lines ...string) error {
	_, err := io.WriteString(s.client, strings.Join(lines, ""))
	return err
}

// startTLS upgrades the client connection after the protocol's "go ahead"
// response has been sent.
func (s *session) startTLS() error {
	// Data pipelined after the STARTTLS command would be injected into the
	// encrypted session (CVE-2011-0411 style); refuse it.
	if s.clientR.Buffered() > 0 {
		return errors.New("client sent data after STARTTLS before handshake")
	}
	tc, err := s.srv.handshake(s.ctx, s.client)
	if err != nil {
		return fmt.Errorf("starttls handshake: %w", err)
	}
	s.client = tc
	s.cic = &idleConn{Conn: tc, timeout: s.srv.PreAuthTimeout}
	s.clientR = bufio.NewReader(s.cic)
	s.tls = true
	s.log = s.log.With("starttls", true, "sni", tc.ConnectionState().ServerName)
	return nil
}

// saslCollect obtains credentials for SASL PLAIN or LOGIN from the client.
// cont sends a continuation request carrying a base64 challenge.
func (s *session) saslCollect(mech, ir string, hasIR bool, cont func(challenge string) error) (creds, error) {
	read := func(challenge string) (string, error) {
		if err := cont(challenge); err != nil {
			return "", err
		}
		l, err := readLine(s.clientR)
		if err != nil {
			return "", err
		}
		l = strings.TrimSpace(l)
		if l == "*" {
			return "", errSASLCanceled
		}
		return l, nil
	}
	decode := func(v string) (string, error) {
		if v == "=" {
			return "", nil
		}
		b, err := base64.StdEncoding.DecodeString(v)
		if err != nil {
			return "", errSASLSyntax
		}
		return string(b), nil
	}
	var c creds
	switch strings.ToUpper(mech) {
	case "PLAIN":
		v := ir
		if !hasIR {
			var err error
			if v, err = read(""); err != nil {
				return c, err
			}
		}
		d, err := decode(v)
		if err != nil {
			return c, err
		}
		p := strings.SplitN(d, "\x00", 3)
		if len(p) != 3 {
			return c, errSASLSyntax
		}
		c = creds{authz: p[0], user: p[1], pass: p[2]}
	case "LOGIN":
		v := ir
		var err error
		if !hasIR {
			if v, err = read("VXNlcm5hbWU6"); err != nil { // "Username:"
				return c, err
			}
		}
		if c.user, err = decode(v); err != nil {
			return c, err
		}
		if v, err = read("UGFzc3dvcmQ6"); err != nil { // "Password:"
			return c, err
		}
		if c.pass, err = decode(v); err != nil {
			return c, err
		}
	default:
		return c, errSASLMech
	}
	if c.authz == c.user {
		c.authz = ""
	}
	if !validCred(c.user) || !validCred(c.pass) || !validCred(c.authz) || c.user == "" {
		return c, errSASLSyntax
	}
	return c, nil
}

// validCred rejects values that could inject protocol lines upstream.
func validCred(v string) bool { return !strings.ContainsAny(v, "\r\n\x00") }

// tryLogin checks the guard, logs in upstream and records the result. On
// success s.upstream/s.upR are set and the session is ready to be relayed.
// login performs the protocol-specific upstream exchange on a fresh
// connection.
func (s *session) tryLogin(c creds, login func(r *bufio.Reader, w io.Writer, c creds) (outcome, []string, error)) loginResult {
	s.attempts++
	g := s.srv.Guard
	log := s.log.With("user", c.user)
	if ok, reason, ban := g.CheckLogin(s.ip, c.user, c.pass); !ok {
		log.Info("login rejected locally", "reason", reason, "banned", ban)
		s.failDelay()
		return loginResult{out: authFail, ban: ban}
	}

	up, err := s.srv.Upstream.Dial(s.ctx)
	if err != nil {
		log.Error("upstream connect failed", "err", err)
		return loginResult{out: authTemp}
	}
	_ = up.SetDeadline(time.Now().Add(upstreamLoginTimeout))
	uic := &idleConn{Conn: up, timeout: 0}
	upR := bufio.NewReader(uic)
	out, reply, err := login(upR, up, c)
	if err != nil {
		up.Close()
		log.Error("upstream login exchange failed", "err", err)
		return loginResult{out: authTemp}
	}
	switch out {
	case authOK:
		g.LoginResult(s.ip, c.user, c.pass, true)
		s.upstream, s.uic, s.upR, s.user = up, uic, upR, c.user
		s.log = log
		log.Info("login ok")
		return loginResult{out: authOK, reply: reply}
	case authFail:
		up.Close()
		ban := g.LoginResult(s.ip, c.user, c.pass, false)
		log.Info("login failed", "banned", ban, "upstream", trimCRLF(strings.Join(reply, " ")))
		s.failDelay()
		return loginResult{out: authFail, ban: ban}
	default:
		up.Close()
		log.Warn("upstream login temporarily failed", "upstream", trimCRLF(strings.Join(reply, " ")))
		return loginResult{out: authTemp}
	}
}

func (s *session) failDelay() {
	if d := s.srv.AuthFailDelay; d > 0 {
		select {
		case <-time.After(d):
		case <-s.ctx.Done():
		}
	}
}

// afterFailure returns the error that ends the session after a failed login,
// or nil if the client may try again.
func (s *session) afterFailure(r loginResult) error {
	if r.ban {
		return errBanned
	}
	if s.attempts >= maxLoginAttempts {
		return errMaxAttempts
	}
	return nil
}

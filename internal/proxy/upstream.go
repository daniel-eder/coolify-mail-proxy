// SPDX-FileCopyrightText: 2026 Daniel Eder
//
// SPDX-License-Identifier: CC0-1.0

package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/daniel-eder/coolify-mail-proxy/internal/config"
)

// Upstream is an implicit-TLS endpoint of the provider. It caches the
// provider's pre-login capabilities, so clients can be answered locally until
// they log in.
type Upstream struct {
	Protocol    string
	Addr        string
	TLS         *tls.Config // ServerName must be set
	DialTimeout time.Duration
	// Hostname is used as EHLO name by probes.
	Hostname string
	Log      *slog.Logger

	mu      sync.Mutex
	caps    []string
	lastTry time.Time
}

// NewUpstream creates an upstream for a listener's protocol.
func NewUpstream(proto string, u config.Upstream, dialTimeout time.Duration, hostname string, log *slog.Logger) *Upstream {
	return &Upstream{
		Protocol:    proto,
		Addr:        u.Addr(),
		TLS:         &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Host},
		DialTimeout: dialTimeout,
		Hostname:    hostname,
		Log:         log,
	}
}

// Dial connects to the upstream with TLS.
func (u *Upstream) Dial(ctx context.Context) (*tls.Conn, error) {
	return DialUpstream(ctx, u.Log.With("protocol", u.Protocol), u.Addr, u.TLS.Clone(), u.DialTimeout)
}

// Caps returns the cached capabilities (IMAP capability atoms, POP3 CAPA
// lines or SMTP EHLO keyword lines). If nothing is cached it probes the
// upstream, at most every 30 seconds; nil means unknown.
func (u *Upstream) Caps(ctx context.Context) []string {
	u.mu.Lock()
	if u.caps != nil || time.Since(u.lastTry) < 30*time.Second {
		c := u.caps
		u.mu.Unlock()
		return c
	}
	u.lastTry = time.Now()
	u.mu.Unlock()
	u.Probe(ctx)
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.caps
}

// Probe dials the upstream, logs its greeting and refreshes the capability
// cache. It is used at startup, periodically, and when the cache is empty.
func (u *Upstream) Probe(ctx context.Context) {
	t0 := time.Now()
	u.mu.Lock()
	u.lastTry = t0
	u.mu.Unlock()
	log := u.Log.With("probe", u.Protocol)
	c, err := DialUpstream(ctx, log, u.Addr, u.TLS.Clone(), u.DialTimeout)
	if err != nil {
		u.Log.Error("upstream probe failed", "protocol", u.Protocol, "addr", u.Addr, "err", err)
		return
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	greeting, caps, err := fetchCaps(u.Protocol, c, bufio.NewReader(c), u.Hostname)
	if err != nil {
		u.Log.Error("upstream probe: no usable greeting", "protocol", u.Protocol, "addr", u.Addr, "remote", c.RemoteAddr().String(), "err", err, "got", greeting)
		return
	}
	u.mu.Lock()
	u.caps = caps
	u.mu.Unlock()
	u.Log.Info("upstream probe ok", "protocol", u.Protocol, "addr", u.Addr, "remote", c.RemoteAddr().String(),
		"greeting", greeting, "caps", strings.Join(caps, " | "), "took", time.Since(t0).String())
}

// fetchCaps reads the greeting and asks for the pre-login capabilities.
func fetchCaps(proto string, c io.Writer, r *bufio.Reader, hostname string) (string, []string, error) {
	switch proto {
	case config.ProtoIMAP:
		g, err := readLine(r)
		if err != nil {
			return g, nil, err
		}
		if !hasPrefixFold(g, "* OK") {
			return g, nil, errors.New("unexpected greeting")
		}
		if _, err := io.WriteString(c, "p1 CAPABILITY\r\n"); err != nil {
			return g, nil, err
		}
		caps := []string{}
		for i := 0; i < maxResponseLines; i++ {
			l, err := readLine(r)
			if err != nil {
				return g, nil, err
			}
			if hasPrefixFold(l, "* CAPABILITY ") {
				caps = strings.Fields(l[len("* CAPABILITY "):])
			}
			if strings.HasPrefix(l, "p1 ") {
				break
			}
		}
		_, _ = io.WriteString(c, "p2 LOGOUT\r\n")
		return g, caps, nil
	case config.ProtoPOP3:
		g, err := readLine(r)
		if err != nil {
			return g, nil, err
		}
		if !strings.HasPrefix(g, "+OK") {
			return g, nil, errors.New("unexpected greeting")
		}
		if _, err := io.WriteString(c, "CAPA\r\n"); err != nil {
			return g, nil, err
		}
		caps := []string{}
		first, err := readLine(r)
		if err != nil {
			return g, nil, err
		}
		if strings.HasPrefix(first, "+OK") {
			for i := 0; ; i++ {
				l, err := readLine(r)
				if err != nil {
					return g, nil, err
				}
				l = strings.TrimSpace(l)
				if l == "." {
					break
				}
				if i > maxResponseLines {
					return g, nil, errors.New("CAPA response too long")
				}
				caps = append(caps, l)
			}
		}
		_, _ = io.WriteString(c, "QUIT\r\n")
		return g, caps, nil
	case config.ProtoSMTP:
		lines, err := readSMTPReply(r)
		g := strings.Join(lines, "")
		if err != nil {
			return g, nil, err
		}
		if smtpCode(lines) != 220 {
			return g, nil, errors.New("unexpected greeting")
		}
		if _, err := fmt.Fprintf(c, "EHLO %s\r\n", ehloName(hostname)); err != nil {
			return g, nil, err
		}
		reply, err := readSMTPReply(r)
		if err != nil {
			return g, nil, err
		}
		caps := []string{}
		if smtpCode(reply) == 250 {
			for _, l := range reply[1:] {
				if len(l) > 4 {
					caps = append(caps, strings.TrimSpace(l[4:]))
				}
			}
		}
		_, _ = io.WriteString(c, "QUIT\r\n")
		return g, caps, nil
	}
	return "", nil, fmt.Errorf("unsupported protocol %q", proto)
}

func ehloName(h string) string {
	if h == "" {
		return "localhost"
	}
	return h
}

// DialUpstream connects to addr with implicit TLS. It retries transient
// failures and logs which stage (tcp or tls) failed, with addresses and timings.
func DialUpstream(ctx context.Context, log *slog.Logger, addr string, tc *tls.Config, timeout time.Duration) (*tls.Conn, error) {
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		t0 := time.Now()
		nd := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
		raw, err := nd.DialContext(ctx, "tcp", addr)
		if err != nil {
			lastErr = fmt.Errorf("dial %s (tcp stage): %w", addr, err)
			log.Warn("upstream tcp connect failed", "attempt", attempt, "addr", addr, "err", err, "took", time.Since(t0).String())
		} else {
			tcpTook := time.Since(t0)
			tconn := tls.Client(raw, tc)
			hsCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			err = tconn.HandshakeContext(hsCtx)
			cancel()
			if err == nil {
				return tconn, nil
			}
			lastErr = fmt.Errorf("dial %s (tls stage): %w", addr, err)
			log.Warn("upstream tls handshake failed", "attempt", attempt, "remote", raw.RemoteAddr().String(),
				"local", raw.LocalAddr().String(), "sni", tc.ServerName, "err", err,
				"tcp_took", tcpTook.String(), "tls_took", (time.Since(t0) - tcpTook).String())
			raw.Close()
		}
		if ctx.Err() != nil {
			break
		}
		time.Sleep(time.Duration(attempt) * 300 * time.Millisecond)
	}
	return nil, lastErr
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

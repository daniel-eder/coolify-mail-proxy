// SPDX-FileCopyrightText: 2026 Daniel Eder
//
// SPDX-License-Identifier: CC0-1.0

// Package proxy implements the TLS-terminating TCP listeners.
//
// Implicit listeners (imaps, pop3s, smtps) terminate TLS from the first byte.
// Plaintext listeners (imap, pop3, submission) accept unencrypted clients and
// offer STARTTLS/STLS. In both cases the proxy itself answers the client
// until it logs in (greeting, capabilities, STARTTLS, SASL PLAIN/LOGIN); only
// then does it connect to the upstream's implicit-TLS port, log in there with
// the client's credentials and switch to a transparent byte relay. Login
// attempts are checked by the guard (bans, whitelist) before they reach the
// provider.
package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/daniel-eder/coolify-mail-proxy/internal/config"
	"github.com/daniel-eder/coolify-mail-proxy/internal/guard"
)

// Server runs one listener (one public port).
type Server struct {
	Listener config.Listener
	TLS      *tls.Config
	Upstream *Upstream
	Guard    *guard.Guard
	// Hostname is shown in greetings.
	Hostname string
	// AllowPlainAuth accepts logins on plaintext ports without STARTTLS.
	AllowPlainAuth bool
	// AuthFailDelay slows down failed logins.
	AuthFailDelay time.Duration
	MaxConnsPerIP int
	// PreAuthTimeout limits idle time before login, IdleTimeout after.
	PreAuthTimeout time.Duration
	IdleTimeout    time.Duration
	Log            *slog.Logger

	mu     sync.Mutex
	perIP  map[string]int
	wg     sync.WaitGroup
	nextID atomic.Uint64
}

// Serve accepts connections on ln until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.mu.Lock()
	s.perIP = map[string]int{}
	s.mu.Unlock()
	go func() { <-ctx.Done(); ln.Close() }()
	s.Log.Info("listening", "port", s.Listener.Port, "kind", s.Listener.Kind, "upstream", s.Upstream.Addr)
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(ctx, c)
		}()
	}
}

// Wait blocks until all active sessions have ended.
func (s *Server) Wait() { s.wg.Wait() }

func (s *Server) acquire(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.MaxConnsPerIP > 0 && s.perIP[ip] >= s.MaxConnsPerIP {
		return false
	}
	s.perIP[ip]++
	return true
}

func (s *Server) release(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.perIP[ip]--; s.perIP[ip] <= 0 {
		delete(s.perIP, ip)
	}
}

// rejectLine is sent to plaintext clients that are refused at connect time.
var rejectLine = map[string]string{
	config.ProtoIMAP: "* BYE Access denied\r\n",
	config.ProtoPOP3: "-ERR Access denied\r\n",
	config.ProtoSMTP: "554 5.7.1 Access denied\r\n",
}

func (s *Server) handle(ctx context.Context, raw net.Conn) {
	start := time.Now()
	ip, _, _ := net.SplitHostPort(raw.RemoteAddr().String())
	log := s.Log.With("id", s.nextID.Add(1), "client", ip, "port", s.Listener.Port, "kind", s.Listener.Kind)
	defer raw.Close()

	if ok, reason := s.Guard.Admit(ip); !ok {
		// Bans are logged once when they are set; repeated rejections of a
		// banned scanner would only flood the log.
		lvl := slog.LevelInfo
		if strings.HasPrefix(reason, "banned") {
			lvl = slog.LevelDebug
		}
		log.Log(ctx, lvl, "rejected", "reason", reason)
		if !s.Listener.Implicit {
			_ = raw.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, _ = io.WriteString(raw, rejectLine[s.Listener.Protocol])
		}
		return
	}
	if !s.acquire(ip) {
		log.Warn("rejected: too many connections from client")
		return
	}
	defer s.release(ip)

	sess := &session{srv: s, ctx: ctx, ip: ip, log: log, client: raw}
	if s.Listener.Implicit {
		tc, err := s.handshake(ctx, raw)
		if err != nil {
			log.Info("client handshake failed", "err", err)
			return
		}
		sess.client = tc
		sess.tls = true
		sess.log = log.With("sni", tc.ConnectionState().ServerName)
	}
	sess.cic = &idleConn{Conn: sess.client, timeout: s.PreAuthTimeout}
	sess.clientR = bufio.NewReader(sess.cic)
	defer func() { sess.client.Close() }()

	if err := sess.front(); err != nil {
		sess.log.Info("session ended before login", "err", err, "tls", sess.tls, "duration", time.Since(start).Round(time.Millisecond).String())
		return
	}
	defer sess.upstream.Close()
	sess.cic.timeout = s.IdleTimeout
	sess.uic.timeout = s.IdleTimeout
	_ = sess.upstream.SetDeadline(time.Time{})

	up, down := pipe(sess.client, sess.clientR, sess.upstream, sess.upR)
	sess.log.Info("session closed", "user", sess.user, "bytes_up", up, "bytes_down", down, "duration", time.Since(start).Round(time.Millisecond).String())
}

func (s *Server) handshake(ctx context.Context, c net.Conn) (*tls.Conn, error) {
	tc := tls.Server(c, s.TLS)
	hsCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := tc.HandshakeContext(hsCtx); err != nil {
		return nil, err
	}
	return tc, nil
}

// idleConn extends the read deadline on every read.
type idleConn struct {
	net.Conn
	timeout time.Duration
}

func (c *idleConn) Read(p []byte) (int, error) {
	if c.timeout > 0 {
		_ = c.Conn.SetReadDeadline(time.Now().Add(c.timeout))
	}
	return c.Conn.Read(p)
}

type closeWriter interface{ CloseWrite() error }

// pipe copies data in both directions until either side finishes or idles out.
// The readers may hold data buffered during protocol negotiation.
func pipe(client net.Conn, clientR io.Reader, upstream net.Conn, upR io.Reader) (up, down int64) {
	var wg sync.WaitGroup
	var once sync.Once
	var timer *time.Timer
	wg.Add(2)
	cp := func(dst net.Conn, src io.Reader, n *int64) {
		defer wg.Done()
		*n, _ = io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		// Give the other direction a moment to drain, then tear down both.
		once.Do(func() {
			timer = time.AfterFunc(5*time.Second, func() {
				client.Close()
				upstream.Close()
			})
		})
	}
	go cp(upstream, clientR, &up)
	go cp(client, upR, &down)
	wg.Wait()
	timer.Stop()
	return
}

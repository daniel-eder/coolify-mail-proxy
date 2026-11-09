// SPDX-FileCopyrightText: 2026 Daniel Eder
//
// SPDX-License-Identifier: CC0-1.0

// Package proxy implements the TLS-terminating TCP listeners.
//
// Implicit listeners (imaps, pop3s, smtps) terminate TLS from the first byte.
// Plaintext listeners (imap, pop3, submission) accept unencrypted clients,
// offer STARTTLS/STLS, and always talk to the upstream's implicit-TLS port.
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
	"sync"
	"sync/atomic"
	"time"

	"github.com/daniel-eder/coolify-mail-proxy/internal/config"
)

// Server runs one listener (one public port).
type Server struct {
	Listener config.Listener
	TLS      *tls.Config
	// UpstreamTLS is used to dial the upstream; ServerName defaults to the upstream host.
	UpstreamTLS   *tls.Config
	MaxConnsPerIP int
	IdleTimeout   time.Duration
	DialTimeout   time.Duration
	Log           *slog.Logger

	mu     sync.Mutex
	perIP  map[string]int
	wg     sync.WaitGroup
	nextID atomic.Uint64
}

// Serve accepts connections on ln until ctx is cancelled.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	s.perIP = map[string]int{}
	go func() { <-ctx.Done(); ln.Close() }()
	s.Log.Info("listening", "port", s.Listener.Port, "kind", s.Listener.Kind, "upstream", s.Listener.Upstream.Addr())
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

func (s *Server) handle(ctx context.Context, raw net.Conn) {
	start := time.Now()
	ip, _, _ := net.SplitHostPort(raw.RemoteAddr().String())
	log := s.Log.With("id", s.nextID.Add(1), "client", ip, "port", s.Listener.Port, "kind", s.Listener.Kind)
	defer raw.Close()

	if !s.acquire(ip) {
		log.Warn("rejected: too many connections from client")
		return
	}
	defer s.release(ip)

	var client net.Conn = raw
	if s.Listener.Implicit {
		tc, err := s.handshake(ctx, raw)
		if err != nil {
			log.Info("client handshake failed", "err", err)
			return
		}
		client = tc
		log = log.With("sni", tc.ConnectionState().ServerName)
	}

	upstream, err := s.dialUpstream(ctx)
	if err != nil {
		log.Error("upstream connect failed", "err", err)
		return
	}
	defer upstream.Close()

	sess := &session{
		srv:      s,
		ctx:      ctx,
		client:   client,
		clientR:  bufio.NewReader(&idleConn{Conn: client, timeout: s.IdleTimeout}),
		upstream: upstream,
		upR:      bufio.NewReader(&idleConn{Conn: upstream, timeout: s.IdleTimeout}),
	}
	if !s.Listener.Implicit {
		if err := sess.negotiate(s.Listener.Protocol); err != nil {
			log.Info("pre-auth phase ended", "err", err, "tls", sess.upgraded)
			return
		}
		if sess.upgraded {
			log = log.With("starttls", true, "sni", sess.client.(*tls.Conn).ConnectionState().ServerName)
		} else {
			log = log.With("starttls", false)
		}
	}
	defer func() { sess.client.Close() }()

	up, down := pipe(sess.client, sess.clientR, sess.upstream, sess.upR)
	log.Info("session closed", "bytes_up", up, "bytes_down", down, "duration", time.Since(start).Round(time.Millisecond).String())
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

func (s *Server) dialUpstream(ctx context.Context) (*tls.Conn, error) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if s.UpstreamTLS != nil {
		tc = s.UpstreamTLS.Clone()
	}
	if tc.ServerName == "" {
		tc.ServerName = s.Listener.Upstream.Host
	}
	return DialUpstream(ctx, s.Log.With("port", s.Listener.Port, "kind", s.Listener.Kind), s.Listener.Upstream.Addr(), tc, s.DialTimeout)
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

// ProbeUpstream dials the upstream once and logs the greeting banner. It is a
// diagnostic aid, used at startup and periodically.
func ProbeUpstream(ctx context.Context, log *slog.Logger, name, addr string, timeout time.Duration) {
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if h, _, err := net.SplitHostPort(addr); err == nil {
		tc.ServerName = h
	}
	t0 := time.Now()
	c, err := DialUpstream(ctx, log.With("probe", name), addr, tc, timeout)
	if err != nil {
		log.Error("upstream probe failed", "protocol", name, "addr", addr, "err", err)
		return
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil {
		log.Error("upstream probe: no greeting", "protocol", name, "addr", addr, "remote", c.RemoteAddr().String(), "err", err, "got", line)
		return
	}
	log.Info("upstream probe ok", "protocol", name, "addr", addr, "remote", c.RemoteAddr().String(), "greeting", line, "took", time.Since(t0).String())
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

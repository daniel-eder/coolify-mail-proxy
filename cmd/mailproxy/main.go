package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/coolify-mail-proxy/mailproxy/internal/autoconfig"
	"github.com/coolify-mail-proxy/mailproxy/internal/certs"
	"github.com/coolify-mail-proxy/mailproxy/internal/config"
	"github.com/coolify-mail-proxy/mailproxy/internal/proxy"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		return healthcheck()
	}

	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log.Info("starting", "domains", cfg.Domains, "cert_source", cfg.CertSource)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// HTTP (autoconfig + health) starts first so the container is reachable
	// while certificates are being obtained.
	httpSrv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           (&autoconfig.Handler{Cfg: cfg, Log: log}).Routes(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http server", "err", err)
			stop()
		}
	}()

	tlsCfg, err := certs.TLSConfig(ctx, cfg, log)
	if err != nil {
		return err
	}

	var servers []*proxy.Server
	var wg sync.WaitGroup
	errCh := make(chan error, len(cfg.Listeners))
	for _, l := range cfg.Listeners {
		ln, err := net.Listen("tcp", ":"+strconv.Itoa(l.Port))
		if err != nil {
			return fmt.Errorf("listen on %d: %w", l.Port, err)
		}
		s := &proxy.Server{
			Listener:      l,
			TLS:           tlsCfg,
			MaxConnsPerIP: cfg.MaxConnsPerIP,
			IdleTimeout:   cfg.IdleTimeout,
			DialTimeout:   cfg.DialTimeout,
			Log:           log,
		}
		servers = append(servers, s)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Serve(ctx, ln); err != nil {
				errCh <- err
			}
		}()
	}

	select {
	case <-ctx.Done():
	case err := <-errCh:
		stop()
		log.Error("listener failed", "err", err)
	}
	log.Info("shutting down")
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutCtx)
	wg.Wait()

	done := make(chan struct{})
	go func() {
		for _, s := range servers {
			s.Wait()
		}
		close(done)
	}()
	select {
	case <-done:
	case <-shutCtx.Done():
		log.Warn("sessions still active at shutdown deadline")
	}
	return nil
}

func healthcheck() error {
	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	c := http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get("http://127.0.0.1:" + port + "/healthz")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

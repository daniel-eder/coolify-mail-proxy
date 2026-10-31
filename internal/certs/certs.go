// Package certs provides the TLS configuration used by the mail listeners.
package certs

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/coolify-mail-proxy/mailproxy/internal/config"
	"github.com/libdns/cloudflare"
	"github.com/mholt/acmez/v3"
	"github.com/mholt/acmez/v3/acme"
	"go.uber.org/zap"
)

// TLSConfig builds a server tls.Config that serves a certificate for every
// configured mail host. Clients without SNI receive the first domain's cert.
func TLSConfig(ctx context.Context, cfg *config.Config, log *slog.Logger) (*tls.Config, error) {
	hosts := cfg.MailHosts()
	var getCert func(*tls.ClientHelloInfo) (*tls.Certificate, error)

	switch cfg.CertSource {
	case "selfsigned":
		cert, err := selfSigned(hosts)
		if err != nil {
			return nil, err
		}
		getCert = func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil }
	default:
		magic, err := acmeConfig(cfg)
		if err != nil {
			return nil, err
		}
		log.Info("obtaining/loading certificates", "hosts", hosts)
		if err := magic.ManageSync(ctx, hosts); err != nil {
			return nil, fmt.Errorf("managing certificates: %w", err)
		}
		getCert = magic.GetCertificate
	}

	allowed := map[string]bool{}
	for _, h := range hosts {
		allowed[h] = true
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
			if name == "" {
				// Copy so we do not mutate the caller's hello struct.
				h := *hello
				h.ServerName = hosts[0]
				return getCert(&h)
			}
			if !allowed[name] {
				return nil, fmt.Errorf("unknown server name %q", name)
			}
			return getCert(hello)
		},
	}, nil
}

func acmeConfig(cfg *config.Config) (*certmagic.Config, error) {
	var magic *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return magic, nil },
	})
	zl, _ := zap.NewProduction()
	magic = certmagic.New(cache, certmagic.Config{
		Storage: &certmagic.FileStorage{Path: cfg.DataDir + "/certmagic"},
		Logger:  zl,
	})

	ca := certmagic.LetsEncryptProductionCA
	if cfg.ACMEStaging {
		ca = certmagic.LetsEncryptStagingCA
	}
	issuer := certmagic.NewACMEIssuer(magic, certmagic.ACMEIssuer{
		CA:                      ca,
		Email:                   cfg.ACMEEmail,
		Agreed:                  true,
		DisableHTTPChallenge:    true,
		DisableTLSALPNChallenge: true,
		DNS01Solver:             newSolver(cfg),
		Logger:                  zl,
	})
	magic.Issuers = []certmagic.Issuer{issuer}
	return magic, nil
}

// dispatchSolver routes each DNS-01 challenge either to the direct Cloudflare
// solver or, for delegated domains, to a solver writing into the delegation zone.
type dispatchSolver struct {
	direct    *certmagic.DNS01Solver
	delegated map[string]*certmagic.DNS01Solver // mail host -> solver
}

var _ acmez.Solver = (*dispatchSolver)(nil)
var _ acmez.Waiter = (*dispatchSolver)(nil)

func newSolver(cfg *config.Config) *dispatchSolver {
	provider := &cloudflare.Provider{APIToken: cfg.CFAPIToken, ZoneToken: cfg.CFZoneToken}
	s := &dispatchSolver{
		direct:    &certmagic.DNS01Solver{DNSManager: certmagic.DNSManager{DNSProvider: provider}},
		delegated: map[string]*certmagic.DNS01Solver{},
	}
	for d := range cfg.Delegated {
		host := cfg.MailHost(d)
		s.delegated[host] = &certmagic.DNS01Solver{DNSManager: certmagic.DNSManager{
			DNSProvider:    provider,
			OverrideDomain: cfg.DelegationTarget(host),
		}}
	}
	return s
}

func (s *dispatchSolver) pick(c acme.Challenge) *certmagic.DNS01Solver {
	if d, ok := s.delegated[strings.ToLower(c.Identifier.Value)]; ok {
		return d
	}
	return s.direct
}

func (s *dispatchSolver) Present(ctx context.Context, c acme.Challenge) error {
	return s.pick(c).Present(ctx, c)
}
func (s *dispatchSolver) Wait(ctx context.Context, c acme.Challenge) error {
	return s.pick(c).Wait(ctx, c)
}
func (s *dispatchSolver) CleanUp(ctx context.Context, c acme.Challenge) error {
	return s.pick(c).CleanUp(ctx, c)
}

func selfSigned(hosts []string) (*tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: hosts[0]},
		DNSNames:     hosts,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

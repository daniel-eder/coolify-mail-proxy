// SPDX-FileCopyrightText: 2026 Daniel Eder
//
// SPDX-License-Identifier: CC0-1.0

// Package guard implements brute-force protection: escalating temporary bans
// for client IPs and mailboxes with failed logins, a whitelist of IPs with
// recent successful logins, a connection rate limit, and a manually
// maintained access file.
package guard

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Config holds the guard settings.
type Config struct {
	// Enabled turns automatic bans, whitelisting and rate limiting on. The
	// access file is honoured either way.
	Enabled bool
	// FreeFailures is the number of failed logins tolerated before bans start.
	FreeFailures int
	// Steps are the ban durations for consecutive failures beyond
	// FreeFailures; the last step repeats.
	Steps []time.Duration
	// ResetAfter forgets the failure count after this long without failures
	// (measured from the end of the last ban).
	ResetAfter time.Duration
	// WhitelistFor is how long a successful login whitelists the client IP.
	WhitelistFor time.Duration
	// WhitelistMaxFailures is the number of failed logins per hour tolerated
	// from a whitelisted IP before it is treated like any other IP.
	WhitelistMaxFailures int
	// ConnRateLimit is the number of connections per minute allowed from a
	// non-whitelisted IP (0 = unlimited).
	ConnRateLimit int
	// NegativeCacheTTL: a username/password pair rejected by the provider is
	// rejected locally for this long, without asking the provider again.
	NegativeCacheTTL time.Duration
	// Domains, if set, restricts logins to usernames user@<domain>.
	Domains []string
	// AccessFile is the manually maintained allow/deny file (optional).
	AccessFile string
	// StateFile stores bans and the whitelist across restarts (optional).
	StateFile string
}

// DefaultConfig returns the default settings.
func DefaultConfig() Config {
	return Config{
		Enabled:              true,
		FreeFailures:         2,
		Steps:                []time.Duration{30 * time.Second, 5 * time.Minute, time.Hour, 24 * time.Hour, 7 * 24 * time.Hour},
		ResetAfter:           24 * time.Hour,
		WhitelistFor:         30 * 24 * time.Hour,
		WhitelistMaxFailures: 10,
		ConnRateLimit:        15,
		NegativeCacheTTL:     15 * time.Minute,
	}
}

const (
	maxSeen    = 64
	maxRecords = 200000
)

type hash [32]byte

// record tracks failures of one IP (key) or mailbox.
type record struct {
	Strikes     int       `json:"strikes"`
	LastFailure time.Time `json:"last_failure"`
	BanUntil    time.Time `json:"ban_until,omitzero"`
	seen        map[hash]struct{}
}

type window struct {
	start time.Time
	n     int
}

// Guard is safe for concurrent use.
type Guard struct {
	cfg     Config
	log     *slog.Logger
	now     func() time.Time
	key     []byte
	domains map[string]bool

	mu        sync.Mutex
	rules     *Rules
	ips       map[string]*record
	mailboxes map[string]*record
	white     map[string]time.Time
	wfail     map[string]*window
	conns     map[string]*window
	neg       map[hash]time.Time
	dirty     bool
	accessSig string
	rateSeq   uint64
}

// New creates a guard and loads the access and state files.
func New(cfg Config, log *slog.Logger) *Guard {
	if len(cfg.Steps) == 0 {
		cfg.Steps = DefaultConfig().Steps
	}
	g := &Guard{
		cfg:       cfg,
		log:       log,
		now:       time.Now,
		key:       make([]byte, 32),
		domains:   map[string]bool{},
		ips:       map[string]*record{},
		mailboxes: map[string]*record{},
		white:     map[string]time.Time{},
		wfail:     map[string]*window{},
		conns:     map[string]*window{},
		neg:       map[hash]time.Time{},
	}
	_, _ = rand.Read(g.key)
	for _, d := range cfg.Domains {
		g.domains[strings.ToLower(d)] = true
	}
	g.reloadAccess()
	g.loadState()
	return g
}

// Run periodically reloads the access file, prunes expired entries and saves
// the state. It saves once more when ctx is cancelled.
func (g *Guard) Run(ctx context.Context) {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			g.saveState()
			return
		case <-t.C:
			g.reloadAccess()
			g.prune()
			g.saveState()
		}
	}
}

// Key returns the ban key of a client IP: the address for IPv4, the /64
// network for IPv6.
func Key(ip string) string {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return ip
	}
	a = a.Unmap()
	if a.Is4() {
		return a.String()
	}
	p, _ := a.Prefix(64)
	return p.String()
}

func parseAddr(ip string) netip.Addr {
	a, _ := netip.ParseAddr(ip)
	return a.Unmap()
}

func (g *Guard) hash(user, pass string) hash {
	m := hmac.New(sha256.New, g.key)
	m.Write([]byte(user))
	m.Write([]byte{0})
	m.Write([]byte(pass))
	var h hash
	copy(h[:], m.Sum(nil))
	return h
}

func (g *Guard) whitelisted(k string, now time.Time) bool {
	exp, ok := g.white[k]
	return ok && now.Before(exp)
}

// KnownDomain reports whether the username belongs to a configured domain.
// Without configured domains every username is accepted.
func (g *Guard) KnownDomain(user string) bool {
	if len(g.domains) == 0 {
		return true
	}
	i := strings.LastIndexByte(user, '@')
	return i >= 0 && g.domains[strings.TrimSuffix(strings.ToLower(user[i+1:]), ".")]
}

// Admit decides whether a new connection is accepted.
func (g *Guard) Admit(ip string) (bool, string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	a := parseAddr(ip)
	if g.rules.deniedIP(a) {
		return false, "denied by access file"
	}
	if g.rules.allowedIP(a) || !g.cfg.Enabled {
		return true, ""
	}
	now := g.now()
	k := Key(ip)
	if r := g.ips[k]; r != nil && now.Before(r.BanUntil) {
		return false, "banned until " + r.BanUntil.UTC().Format(time.RFC3339)
	}
	if g.whitelisted(k, now) || g.cfg.ConnRateLimit <= 0 {
		return true, ""
	}
	w := g.conns[k]
	if w == nil || now.Sub(w.start) >= time.Minute {
		w = &window{start: now}
		g.conns[k] = w
	}
	w.n++
	if w.n <= g.cfg.ConnRateLimit {
		return true, ""
	}
	// Each exceeded window counts as one failure.
	delete(g.conns, k)
	g.rateSeq++
	var seq [8]byte
	binary.BigEndian.PutUint64(seq[:], g.rateSeq)
	g.failIP(k, g.hash("\x00rate", string(seq[:])), now, "connection rate exceeded")
	return false, "connection rate exceeded"
}

// CheckLogin is called before credentials are sent to the provider. If it
// returns false the login must be rejected locally; ban reports whether the
// client IP is now banned (the connection should be closed).
func (g *Guard) CheckLogin(ip, user, pass string) (ok bool, reason string, ban bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	u := NormalizeUser(user)
	a := parseAddr(ip)
	if g.rules.deniedUser(u) {
		return false, "mailbox denied by access file", false
	}
	if !g.cfg.Enabled {
		return true, "", false
	}
	now := g.now()
	k := Key(ip)
	trusted := g.rules.allowedIP(a)
	h := g.hash(u, pass)
	if !g.KnownDomain(u) {
		if trusted {
			return false, "unknown domain", false
		}
		return false, "unknown domain", g.failIP(k, h, now, "login for unknown domain")
	}
	if exp, hit := g.neg[h]; hit && now.Before(exp) {
		return false, "password already rejected by provider", false
	}
	if trusted || g.whitelisted(k, now) || g.rules.allowedUser(u) {
		return true, "", false
	}
	if mb := g.mailboxes[u]; mb != nil && now.Before(mb.BanUntil) {
		// Treat the IP as if it had caused the mailbox ban itself.
		g.failIP(k, h, now, "login for locked mailbox")
		if r := g.ips[k]; r != nil && r.BanUntil.Before(mb.BanUntil) {
			r.BanUntil = mb.BanUntil
			g.log.Warn("ip banned", "key", k, "until", r.BanUntil.UTC().Format(time.RFC3339), "reason", "login for locked mailbox", "user", u)
		}
		return false, "mailbox locked after failed logins", true
	}
	return true, "", false
}

// LoginResult records the provider's verdict. It returns whether the client
// IP is now banned.
func (g *Guard) LoginResult(ip, user, pass string, success bool) (ban bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.cfg.Enabled {
		return false
	}
	u := NormalizeUser(user)
	now := g.now()
	k := Key(ip)
	h := g.hash(u, pass)
	if success {
		delete(g.neg, h)
		if _, had := g.white[k]; !had {
			g.log.Info("ip whitelisted", "key", k, "user", u, "days", int(g.cfg.WhitelistFor.Hours()/24))
		}
		g.white[k] = now.Add(g.cfg.WhitelistFor)
		delete(g.ips, k)
		delete(g.wfail, k)
		g.dirty = true
		return false
	}
	if len(g.neg) < maxRecords {
		g.neg[h] = now.Add(g.cfg.NegativeCacheTTL)
	}
	if !g.rules.allowedUser(u) && len(g.mailboxes) < maxRecords {
		mb := g.mailboxes[u]
		if mb == nil {
			mb = &record{}
			g.mailboxes[u] = mb
		}
		if mb.fail(h, now, &g.cfg) {
			g.log.Warn("mailbox locked", "user", u, "until", mb.BanUntil.UTC().Format(time.RFC3339), "failures", mb.Strikes)
		}
		g.dirty = true
	}
	if g.rules.allowedIP(parseAddr(ip)) {
		return false
	}
	return g.failIP(k, h, now, "failed login")
}

// failIP records a failure for an IP key and returns whether it is banned.
func (g *Guard) failIP(k string, h hash, now time.Time, reason string) bool {
	if g.whitelisted(k, now) {
		w := g.wfail[k]
		if w == nil || now.Sub(w.start) >= time.Hour {
			w = &window{start: now}
			g.wfail[k] = w
		}
		w.n++
		if w.n <= g.cfg.WhitelistMaxFailures {
			return false
		}
	}
	r := g.ips[k]
	if r == nil {
		if len(g.ips) >= maxRecords {
			return false
		}
		r = &record{}
		g.ips[k] = r
	}
	g.dirty = true
	if r.fail(h, now, &g.cfg) {
		g.log.Warn("ip banned", "key", k, "until", r.BanUntil.UTC().Format(time.RFC3339), "reason", reason, "failures", r.Strikes)
	}
	return now.Before(r.BanUntil)
}

// fail counts a failure unless the same credentials failed before. It
// returns true if a new ban was set.
func (r *record) fail(h hash, now time.Time, cfg *Config) bool {
	last := r.LastFailure
	if r.BanUntil.After(last) {
		last = r.BanUntil
	}
	if r.Strikes > 0 && now.Sub(last) > cfg.ResetAfter {
		r.Strikes = 0
		r.seen = nil
	}
	if _, dup := r.seen[h]; dup {
		return false
	}
	if r.seen == nil {
		r.seen = map[hash]struct{}{}
	}
	if len(r.seen) < maxSeen {
		r.seen[h] = struct{}{}
	}
	r.Strikes++
	r.LastFailure = now
	if r.Strikes <= cfg.FreeFailures {
		return false
	}
	i := min(r.Strikes-cfg.FreeFailures-1, len(cfg.Steps)-1)
	r.BanUntil = now.Add(cfg.Steps[i])
	return true
}

func (g *Guard) prune() {
	g.mu.Lock()
	defer g.mu.Unlock()
	now := g.now()
	expired := func(r *record) bool {
		last := r.LastFailure
		if r.BanUntil.After(last) {
			last = r.BanUntil
		}
		return now.Sub(last) > g.cfg.ResetAfter
	}
	for k, r := range g.ips {
		if expired(r) {
			delete(g.ips, k)
			g.dirty = true
		}
	}
	for k, r := range g.mailboxes {
		if expired(r) {
			delete(g.mailboxes, k)
			g.dirty = true
		}
	}
	for k, exp := range g.white {
		if now.After(exp) {
			delete(g.white, k)
			g.dirty = true
		}
	}
	for k, w := range g.wfail {
		if now.Sub(w.start) >= time.Hour {
			delete(g.wfail, k)
		}
	}
	for k, w := range g.conns {
		if now.Sub(w.start) >= time.Minute {
			delete(g.conns, k)
		}
	}
	for h, exp := range g.neg {
		if now.After(exp) {
			delete(g.neg, h)
		}
	}
}

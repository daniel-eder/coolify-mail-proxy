// SPDX-FileCopyrightText: 2026 Daniel Eder
//
// SPDX-License-Identifier: CC0-1.0

package guard

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }
func discard() *slog.Logger          { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
func newTestGuard(t *testing.T, mod func(*Config)) (*Guard, *clock) {
	t.Helper()
	cfg := DefaultConfig()
	cfg.Domains = []string{"a.com"}
	if mod != nil {
		mod(&cfg)
	}
	g := New(cfg, discard())
	c := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	g.now = c.now
	return g, c
}

// attempt runs a full login attempt and reports whether the provider was asked.
func attempt(g *Guard, ip, user, pass string, correct bool) (asked, banned bool) {
	ok, _, ban := g.CheckLogin(ip, user, pass)
	if !ok {
		return false, ban
	}
	return true, g.LoginResult(ip, user, pass, correct)
}

func admitted(g *Guard, ip string) bool { ok, _ := g.Admit(ip); return ok }

func TestEscalation(t *testing.T) {
	g, c := newTestGuard(t, nil)
	ip := "198.51.100.1"
	for i, pw := range []string{"p1", "p2"} {
		if _, ban := attempt(g, ip, "x@a.com", pw, false); ban {
			t.Fatalf("failure %d should be free", i+1)
		}
	}
	if _, ban := attempt(g, ip, "x@a.com", "p3", false); !ban {
		t.Fatal("third failure should ban")
	}
	if admitted(g, ip) {
		t.Fatal("banned IP admitted")
	}
	c.add(31 * time.Second)
	if !admitted(g, ip) {
		t.Fatal("30s ban should have expired")
	}
	attempt(g, ip, "x@a.com", "p4", false)
	c.add(time.Minute)
	if admitted(g, ip) {
		t.Fatal("second ban should last 5 minutes")
	}
	c.add(5 * time.Minute)
	if !admitted(g, ip) {
		t.Fatal("5m ban should have expired")
	}
}

func TestRepeatedPasswordCountsOnceAndIsAnsweredLocally(t *testing.T) {
	g, _ := newTestGuard(t, nil)
	ip := "198.51.100.2"
	asked, _ := attempt(g, ip, "x@a.com", "old", false)
	if !asked {
		t.Fatal("first attempt must reach the provider")
	}
	for range 10 {
		asked, ban := attempt(g, ip, "X@a.com", "old", false)
		if asked || ban {
			t.Fatalf("repeat: asked=%v ban=%v", asked, ban)
		}
	}
	if !admitted(g, ip) {
		t.Fatal("stale password must not ban")
	}
}

func TestSuccessWhitelists(t *testing.T) {
	g, c := newTestGuard(t, func(c *Config) { c.ConnRateLimit = 2 })
	ip := "198.51.100.3"
	attempt(g, ip, "x@a.com", "bad", false)
	if asked, _ := attempt(g, ip, "x@a.com", "good", true); !asked {
		t.Fatal("login not forwarded")
	}
	for range 10 {
		if !admitted(g, ip) {
			t.Fatal("whitelisted IP must not be rate limited")
		}
	}
	// Up to 10 failures per hour are tolerated.
	for i := range 10 {
		if _, ban := attempt(g, ip, "x@a.com", "w"+string(rune('a'+i)), false); ban {
			t.Fatalf("whitelisted IP banned after %d failures", i+1)
		}
	}
	for i := range 3 {
		attempt(g, ip, "x@a.com", "z"+string(rune('a'+i)), false)
	}
	if admitted(g, ip) {
		t.Fatal("whitelisted IP with many failures should be banned")
	}
	c.add(31 * 24 * time.Hour)
	if g.whitelisted(Key(ip), c.t) {
		t.Fatal("whitelist should expire after 30 days")
	}
}

func TestMailboxLock(t *testing.T) {
	g, _ := newTestGuard(t, nil)
	home := "203.0.113.9"
	attempt(g, home, "v@a.com", "right", true)
	// Three attackers, one guess each: the mailbox gets locked.
	for i, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		if asked, _ := attempt(g, ip, "v@a.com", "guess"+string(rune('0'+i)), false); !asked {
			t.Fatalf("attacker %d not forwarded", i)
		}
	}
	asked, ban := attempt(g, "192.0.2.4", "v@a.com", "guess9", false)
	if asked || !ban {
		t.Fatalf("locked mailbox: asked=%v ban=%v", asked, ban)
	}
	if admitted(g, "192.0.2.4") {
		t.Fatal("IP trying a locked mailbox should be banned")
	}
	if asked, _ := attempt(g, home, "v@a.com", "right", true); !asked {
		t.Fatal("whitelisted IP must bypass the mailbox lock")
	}
}

func TestUnknownDomainRejectedLocally(t *testing.T) {
	g, _ := newTestGuard(t, nil)
	asked, _ := attempt(g, "192.0.2.10", "admin", "x", false)
	if asked {
		t.Fatal("unknown domain must not be forwarded")
	}
	attempt(g, "192.0.2.10", "info@other.com", "x", false)
	if _, ban := attempt(g, "192.0.2.10", "test", "x", false); !ban {
		t.Fatal("unknown-domain logins should count as failures")
	}
}

func TestConnRateLimit(t *testing.T) {
	g, c := newTestGuard(t, func(c *Config) { c.ConnRateLimit = 3 })
	ip := "192.0.2.20"
	n := 0
	for range 30 {
		if admitted(g, ip) {
			n++
		}
	}
	// Two exceeded windows are free, the third bans.
	if n != 9 {
		t.Fatalf("admitted %d connections, want 9", n)
	}
	c.add(31 * time.Second)
	if !admitted(g, ip) {
		t.Fatal("ban should have expired")
	}
}

func TestIPv6Slash64(t *testing.T) {
	if Key("2001:db8:1:2:aaaa::1") != Key("2001:db8:1:2:bbbb::2") {
		t.Fatal("same /64 should share a key")
	}
	if Key("::ffff:192.0.2.1") != "192.0.2.1" {
		t.Fatal("v4-mapped address not unmapped")
	}
}

func TestResetAfterQuietPeriod(t *testing.T) {
	g, c := newTestGuard(t, nil)
	ip := "192.0.2.30"
	attempt(g, ip, "x@a.com", "1", false)
	attempt(g, ip, "x@a.com", "2", false)
	c.add(25 * time.Hour)
	if _, ban := attempt(g, ip, "x@a.com", "3", false); ban {
		t.Fatal("failure count should reset after 24h")
	}
}

func TestAccessFile(t *testing.T) {
	dir := t.TempDir()
	f := filepath.Join(dir, "access.conf")
	os.WriteFile(f, []byte("# comment\nallow 203.0.113.0/24\ndeny 203.0.113.66\ndeny Bob@a.com\nallow carol@a.com\nbogus line here\n"), 0o644)
	g, _ := newTestGuard(t, func(c *Config) { c.AccessFile = f; c.ConnRateLimit = 1 })
	for range 5 {
		if !admitted(g, "203.0.113.5") {
			t.Fatal("allowed IP rejected")
		}
		attempt(g, "203.0.113.5", "x@a.com", "bad"+time.Now().String(), false)
	}
	if admitted(g, "203.0.113.66") {
		t.Fatal("deny must win over allow")
	}
	if ok, _, _ := g.CheckLogin("203.0.113.5", "bob@a.com", "x"); ok {
		t.Fatal("denied mailbox accepted")
	}
	for i := range 5 {
		attempt(g, "192.0.2."+string(rune('1'+i)), "carol@a.com", "g"+string(rune('a'+i)), false)
	}
	if ok, _, _ := g.CheckLogin("192.0.2.100", "carol@a.com", "new"); !ok {
		t.Fatal("allowed mailbox must not be locked")
	}

	os.WriteFile(f, []byte("deny 198.51.100.0/24\n"), 0o644)
	g.reloadAccess()
	if admitted(g, "198.51.100.7") {
		t.Fatal("reloaded deny not applied")
	}
}

func TestStatePersistence(t *testing.T) {
	f := filepath.Join(t.TempDir(), "state.json")
	g, c := newTestGuard(t, func(c *Config) { c.StateFile = f })
	attempt(g, "203.0.113.1", "x@a.com", "ok", true)
	for _, p := range []string{"1", "2", "3"} {
		attempt(g, "192.0.2.50", "x@a.com", p, false)
	}
	g.saveState()
	b, _ := os.ReadFile(f)
	if !strings.Contains(string(b), "192.0.2.50") {
		t.Fatalf("state missing ban: %s", b)
	}

	g2 := New(g.cfg, discard())
	g2.now = c.now
	if admitted(g2, "192.0.2.50") {
		t.Fatal("ban not restored")
	}
	if !g2.whitelisted("203.0.113.1", c.t) {
		t.Fatal("whitelist not restored")
	}
}

func TestDisabled(t *testing.T) {
	g, _ := newTestGuard(t, func(c *Config) { c.Enabled = false; c.ConnRateLimit = 1 })
	for i := range 10 {
		if !admitted(g, "192.0.2.60") {
			t.Fatal("disabled guard rejected connection")
		}
		if asked, _ := attempt(g, "192.0.2.60", "nobody", string(rune('a'+i)), false); !asked {
			t.Fatal("disabled guard rejected login")
		}
	}
}

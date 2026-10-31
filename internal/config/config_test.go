package config

import "testing"

func envMap(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestLoadDefaults(t *testing.T) {
	c, err := LoadFrom(envMap(map[string]string{
		"MAIL_DOMAINS":  " A.com, b.com;a.com ",
		"ACME_EMAIL":    "x@y.z",
		"CF_API_TOKEN":  "tok",
		"UPSTREAM_IMAP": "imap.provider.test",
		"UPSTREAM_POP3": "imap.provider.test",
		"UPSTREAM_SMTP": "smtp.provider.test:2465",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Domains) != 2 || c.Domains[0] != "a.com" || c.Domains[1] != "b.com" {
		t.Fatalf("domains: %v", c.Domains)
	}
	if c.MailHost("a.com") != "mail.a.com" {
		t.Fatal(c.MailHost("a.com"))
	}
	want := []struct {
		port     int
		kind     string
		implicit bool
		up       string
	}{
		{993, "imaps", true, "imap.provider.test:993"},
		{143, "imap", false, "imap.provider.test:993"},
		{995, "pop3s", true, "imap.provider.test:995"},
		{110, "pop3", false, "imap.provider.test:995"},
		{465, "smtps", true, "smtp.provider.test:2465"},
		{587, "submission", false, "smtp.provider.test:2465"},
	}
	if len(c.Listeners) != len(want) {
		t.Fatalf("listeners: %+v", c.Listeners)
	}
	for i, w := range want {
		l := c.Listeners[i]
		if l.Port != w.port || l.Kind != w.kind || l.Implicit != w.implicit || l.Upstream.Addr() != w.up {
			t.Errorf("listener %d: got %+v want %+v", i, l, w)
		}
	}
}

func TestPlaintextDisabledAndPartial(t *testing.T) {
	c, err := LoadFrom(envMap(map[string]string{
		"MAIL_DOMAINS": "a.com", "CERT_SOURCE": "selfsigned",
		"UPSTREAM_IMAP": "imap.p.test", "ENABLE_PLAINTEXT": "false",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Listeners) != 1 || c.Listeners[0].Port != 993 {
		t.Fatalf("%+v", c.Listeners)
	}
}

func TestListenersOverride(t *testing.T) {
	l, err := ParseListeners("10993:imaps,2525:submission:smtp.x.test:465",
		map[string]Upstream{ProtoIMAP: {"imap.x.test", 993}})
	if err != nil {
		t.Fatal(err)
	}
	if l[0].Upstream.Addr() != "imap.x.test:993" || l[1].Protocol != ProtoSMTP || l[1].Implicit || l[1].Upstream.Addr() != "smtp.x.test:465" {
		t.Fatalf("%+v", l)
	}
}

func TestLoadErrors(t *testing.T) {
	base := func(extra map[string]string) map[string]string {
		m := map[string]string{"MAIL_DOMAINS": "a.com", "CERT_SOURCE": "selfsigned", "UPSTREAM_IMAP": "imap.p.test"}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	cases := []map[string]string{
		{},
		{"MAIL_DOMAINS": "a.com", "CERT_SOURCE": "selfsigned"},    // no upstream
		{"MAIL_DOMAINS": "a.com", "UPSTREAM_IMAP": "imap.p.test"}, // missing acme email/token
		base(map[string]string{"LISTENERS": "993:bogus"}),
		base(map[string]string{"LISTENERS": "465:smtps"}), // no smtp upstream
		base(map[string]string{"LISTENERS": "993:imaps,993:imap"}),
		base(map[string]string{"ACME_DELEGATED_DOMAINS": "c.com"}),
		base(map[string]string{"MAIL_DOMAINS": "https://a.com"}),
		base(map[string]string{"UPSTREAM_SMTP": "smtp.p.test:x"}),
		{"MAIL_DOMAINS": "a.com", "UPSTREAM_IMAP": "i.p.test", "ACME_EMAIL": "e@x.y", "CF_API_TOKEN": "t", "ACME_DELEGATED_DOMAINS": "a.com"},
	}
	for i, m := range cases {
		if _, err := LoadFrom(envMap(m)); err == nil {
			t.Errorf("case %d: expected error", i)
		}
	}
}

func TestDelegationTarget(t *testing.T) {
	c := &Config{DelegationZone: "acme.example.net"}
	if got := c.DelegationTarget("mail.x.com"); got != "mail-x-com.acme.example.net" {
		t.Fatal(got)
	}
}

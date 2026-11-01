// SPDX-FileCopyrightText: 2026 Daniel Eder
//
// SPDX-License-Identifier: CC0-1.0

// Package config parses the environment-based configuration of mailproxy.
package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	ProtoIMAP = "imap"
	ProtoPOP3 = "pop3"
	ProtoSMTP = "smtp"
)

// Protocols lists the supported protocols in display order.
var Protocols = []string{ProtoIMAP, ProtoPOP3, ProtoSMTP}

// Kind describes a listener type.
type Kind struct {
	Protocol string
	// Implicit means the client speaks TLS from the first byte. Otherwise the
	// client connects in plaintext and may upgrade with STARTTLS/STLS.
	Implicit    bool
	DefaultPort int
}

// Kinds maps listener kind names to their properties.
var Kinds = map[string]Kind{
	"imaps":      {ProtoIMAP, true, 993},
	"imap":       {ProtoIMAP, false, 143},
	"pop3s":      {ProtoPOP3, true, 995},
	"pop3":       {ProtoPOP3, false, 110},
	"smtps":      {ProtoSMTP, true, 465},
	"submission": {ProtoSMTP, false, 587},
}

var implicitKind = map[string]string{ProtoIMAP: "imaps", ProtoPOP3: "pop3s", ProtoSMTP: "smtps"}
var plainKind = map[string]string{ProtoIMAP: "imap", ProtoPOP3: "pop3", ProtoSMTP: "submission"}

// Upstream is an implicit-TLS endpoint of the target provider.
type Upstream struct {
	Host string
	Port int
}

func (u Upstream) Addr() string { return net.JoinHostPort(u.Host, strconv.Itoa(u.Port)) }

type Listener struct {
	Port     int
	Kind     string
	Protocol string
	Implicit bool
	Upstream Upstream
}

type Config struct {
	Domains        []string // customer domains, e.g. "a.com"
	HostPrefix     string   // e.g. "mail" -> mail.a.com
	Upstreams      map[string]Upstream
	Listeners      []Listener
	HTTPAddr       string
	DataDir        string
	CertSource     string // "acme" or "selfsigned"
	ACMEEmail      string
	ACMEStaging    bool
	CFAPIToken     string
	CFZoneToken    string
	DelegationZone string
	Delegated      map[string]bool
	MaxConnsPerIP  int
	IdleTimeout    time.Duration
	DialTimeout    time.Duration
	DisplayName    string
	// Redirects maps a lowercase request hostname to a target URL template
	// (may contain {domain}). Served as temporary (307) redirects.
	Redirects map[string]string
}

// RedirectTarget returns the redirect URL for a request host, if any.
func (c *Config) RedirectTarget(host string) (string, bool) {
	t, ok := c.Redirects[host]
	return t, ok
}

// MailHost returns the client-facing mail hostname for a customer domain.
func (c *Config) MailHost(domain string) string {
	return c.HostPrefix + "." + domain
}

// MailHosts returns all client-facing mail hostnames.
func (c *Config) MailHosts() []string {
	out := make([]string, 0, len(c.Domains))
	for _, d := range c.Domains {
		out = append(out, c.MailHost(d))
	}
	return out
}

// HasDomain reports whether d is a configured customer domain.
func (c *Config) HasDomain(d string) bool {
	d = strings.ToLower(strings.TrimSuffix(d, "."))
	for _, x := range c.Domains {
		if x == d {
			return true
		}
	}
	return false
}

// ListenersFor returns the listeners of a protocol, implicit TLS first.
func (c *Config) ListenersFor(proto string) []Listener {
	var imp, plain []Listener
	for _, l := range c.Listeners {
		if l.Protocol != proto {
			continue
		}
		if l.Implicit {
			imp = append(imp, l)
		} else {
			plain = append(plain, l)
		}
	}
	return append(imp, plain...)
}

// Load reads configuration from the process environment.
func Load() (*Config, error) { return LoadFrom(os.Getenv) }

// LoadFrom reads configuration using the given lookup function.
func LoadFrom(get func(string) string) (*Config, error) {
	env := func(k, def string) string {
		if v := strings.TrimSpace(get(k)); v != "" {
			return v
		}
		return def
	}

	c := &Config{
		HostPrefix:     strings.Trim(env("MAIL_HOST_PREFIX", "mail"), "."),
		Upstreams:      map[string]Upstream{},
		HTTPAddr:       env("HTTP_ADDR", ":8080"),
		DataDir:        env("DATA_DIR", "/data"),
		CertSource:     strings.ToLower(env("CERT_SOURCE", "acme")),
		ACMEEmail:      env("ACME_EMAIL", ""),
		CFAPIToken:     env("CF_API_TOKEN", ""),
		CFZoneToken:    env("CF_ZONE_TOKEN", ""),
		DelegationZone: strings.Trim(strings.ToLower(env("ACME_DELEGATION_ZONE", "")), "."),
		Delegated:      map[string]bool{},
		DisplayName:    env("DISPLAY_NAME", ""),
	}

	var err error
	if c.Domains, err = parseDomains(env("MAIL_DOMAINS", "")); err != nil {
		return nil, err
	}
	if len(c.Domains) == 0 {
		return nil, fmt.Errorf("MAIL_DOMAINS must contain at least one domain")
	}

	for _, p := range Protocols {
		key := "UPSTREAM_" + strings.ToUpper(p)
		v := env(key, "")
		if v == "" {
			continue
		}
		u, err := parseUpstream(v, Kinds[implicitKind[p]].DefaultPort)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		c.Upstreams[p] = u
	}
	if len(c.Upstreams) == 0 {
		return nil, fmt.Errorf("set at least one of UPSTREAM_IMAP, UPSTREAM_POP3, UPSTREAM_SMTP")
	}

	if c.Redirects, err = ParseRedirects(env("REDIRECTS", ""), c.Domains); err != nil {
		return nil, err
	}

	plaintext, err := strconv.ParseBool(env("ENABLE_PLAINTEXT", "true"))
	if err != nil {
		return nil, fmt.Errorf("ENABLE_PLAINTEXT: %w", err)
	}
	port25, err := strconv.ParseBool(env("ENABLE_PORT_25", "false"))
	if err != nil {
		return nil, fmt.Errorf("ENABLE_PORT_25: %w", err)
	}
	if spec := env("LISTENERS", ""); spec != "" {
		if c.Listeners, err = ParseListeners(spec, c.Upstreams); err != nil {
			return nil, err
		}
	} else {
		c.Listeners = defaultListeners(c.Upstreams, plaintext)
		if port25 {
			u, ok := c.Upstreams[ProtoSMTP]
			if !ok {
				return nil, fmt.Errorf("ENABLE_PORT_25 requires UPSTREAM_SMTP")
			}
			// Some clients default to port 25 for unencrypted submission.
			c.Listeners = append(c.Listeners, Listener{Port: 25, Kind: "submission", Protocol: ProtoSMTP, Upstream: u})
		}
	}

	if c.ACMEStaging, err = strconv.ParseBool(env("ACME_STAGING", "false")); err != nil {
		return nil, fmt.Errorf("ACME_STAGING: %w", err)
	}
	if c.MaxConnsPerIP, err = strconv.Atoi(env("MAX_CONNS_PER_IP", "20")); err != nil {
		return nil, fmt.Errorf("MAX_CONNS_PER_IP: %w", err)
	}
	if c.IdleTimeout, err = time.ParseDuration(env("IDLE_TIMEOUT", "35m")); err != nil {
		return nil, fmt.Errorf("IDLE_TIMEOUT: %w", err)
	}
	if c.DialTimeout, err = time.ParseDuration(env("DIAL_TIMEOUT", "10s")); err != nil {
		return nil, fmt.Errorf("DIAL_TIMEOUT: %w", err)
	}

	delegated, err := parseDomains(env("ACME_DELEGATED_DOMAINS", ""))
	if err != nil {
		return nil, fmt.Errorf("ACME_DELEGATED_DOMAINS: %w", err)
	}
	for _, d := range delegated {
		if !c.HasDomain(d) {
			return nil, fmt.Errorf("ACME_DELEGATED_DOMAINS: %q is not listed in MAIL_DOMAINS", d)
		}
		c.Delegated[d] = true
	}

	switch c.CertSource {
	case "acme":
		if c.ACMEEmail == "" {
			return nil, fmt.Errorf("ACME_EMAIL is required when CERT_SOURCE=acme")
		}
		if c.CFAPIToken == "" {
			return nil, fmt.Errorf("CF_API_TOKEN is required when CERT_SOURCE=acme")
		}
		if len(c.Delegated) > 0 && c.DelegationZone == "" {
			return nil, fmt.Errorf("ACME_DELEGATION_ZONE is required when ACME_DELEGATED_DOMAINS is set")
		}
	case "selfsigned":
	default:
		return nil, fmt.Errorf("CERT_SOURCE must be 'acme' or 'selfsigned', got %q", c.CertSource)
	}
	return c, nil
}

// DelegationTarget returns the TXT record name used for a delegated mail host:
// _acme-challenge.mail.x.com CNAME -> mail-x-com.<DelegationZone>
func (c *Config) DelegationTarget(mailHost string) string {
	return strings.ReplaceAll(mailHost, ".", "-") + "." + c.DelegationZone
}

func defaultListeners(ups map[string]Upstream, plaintext bool) []Listener {
	var out []Listener
	for _, p := range Protocols {
		u, ok := ups[p]
		if !ok {
			continue
		}
		kinds := []string{implicitKind[p]}
		if plaintext {
			kinds = append(kinds, plainKind[p])
		}
		for _, k := range kinds {
			out = append(out, Listener{Port: Kinds[k].DefaultPort, Kind: k, Protocol: p, Implicit: Kinds[k].Implicit, Upstream: u})
		}
	}
	return out
}

func parseUpstream(s string, defPort int) (Upstream, error) {
	host, port := s, defPort
	if h, p, err := net.SplitHostPort(s); err == nil {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return Upstream{}, fmt.Errorf("invalid port in %q", s)
		}
		host, port = h, n
	}
	host = strings.ToLower(strings.Trim(host, "."))
	if host == "" || strings.ContainsAny(host, "/@ ") {
		return Upstream{}, fmt.Errorf("invalid host %q", s)
	}
	return Upstream{Host: host, Port: port}, nil
}

func parseDomains(s string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == ';' }) {
		d := strings.ToLower(strings.Trim(strings.TrimSpace(f), "."))
		if d == "" {
			continue
		}
		if !strings.Contains(d, ".") || strings.ContainsAny(d, "/:@*") {
			return nil, fmt.Errorf("invalid domain %q", f)
		}
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out, nil
}

// ParseRedirects parses "source=target,..." entries (separated by commas,
// semicolons, spaces or newlines). A source without a dot is a label applied
// to every customer domain (webmail -> webmail.a.com, webmail.b.com); a
// source with dots is a full hostname. "{domain}" in the target is replaced
// with the customer domain the request host belongs to.
func ParseRedirects(s string, domains []string) (map[string]string, error) {
	out := map[string]string{}
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' || r == ';' }) {
		src, target, ok := strings.Cut(f, "=")
		src = strings.ToLower(strings.Trim(strings.TrimSpace(src), "."))
		target = strings.TrimSpace(target)
		if !ok || src == "" || target == "" {
			return nil, fmt.Errorf("REDIRECTS: %q must be source=https://target", f)
		}
		u, err := url.Parse(strings.ReplaceAll(target, "{domain}", "example.com"))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return nil, fmt.Errorf("REDIRECTS: invalid target URL in %q (must be http:// or https://)", f)
		}
		if strings.ContainsAny(src, "/:@*") {
			return nil, fmt.Errorf("REDIRECTS: invalid source %q", src)
		}
		hosts := []string{src}
		if !strings.Contains(src, ".") {
			hosts = hosts[:0]
			for _, d := range domains {
				hosts = append(hosts, src+"."+d)
			}
		}
		for _, h := range hosts {
			if _, dup := out[h]; dup {
				return nil, fmt.Errorf("REDIRECTS: duplicate source %q", h)
			}
			// Resolve {domain}: the customer domain is the longest configured
			// domain that is a suffix of the host.
			dom := ""
			for _, d := range domains {
				if (h == d || strings.HasSuffix(h, "."+d)) && len(d) > len(dom) {
					dom = d
				}
			}
			if strings.Contains(target, "{domain}") && dom == "" {
				return nil, fmt.Errorf("REDIRECTS: %q uses {domain} but %q is not under a MAIL_DOMAINS domain", f, h)
			}
			out[h] = strings.ReplaceAll(target, "{domain}", dom)
		}
	}
	return out, nil
}

// ParseListeners parses "listenPort:kind[:upstreamHost:upstreamPort],...".
// Without an explicit upstream, the protocol's UPSTREAM_* setting is used.
func ParseListeners(s string, ups map[string]Upstream) ([]Listener, error) {
	var out []Listener
	ports := map[int]bool{}
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		parts := strings.Split(f, ":")
		if len(parts) != 2 && len(parts) != 4 {
			return nil, fmt.Errorf("LISTENERS: %q must be listenPort:kind[:upstreamHost:upstreamPort]", f)
		}
		lp, err := strconv.Atoi(parts[0])
		if err != nil || lp < 1 || lp > 65535 {
			return nil, fmt.Errorf("LISTENERS: invalid port in %q", f)
		}
		name := strings.ToLower(parts[1])
		k, ok := Kinds[name]
		if !ok {
			return nil, fmt.Errorf("LISTENERS: unknown kind %q (use imaps, imap, pop3s, pop3, smtps, submission)", name)
		}
		u, ok := ups[k.Protocol]
		if len(parts) == 4 {
			if u, err = parseUpstream(parts[2]+":"+parts[3], 0); err != nil || u.Port == 0 {
				return nil, fmt.Errorf("LISTENERS: invalid upstream in %q", f)
			}
		} else if !ok {
			return nil, fmt.Errorf("LISTENERS: %q needs UPSTREAM_%s or an explicit upstream", f, strings.ToUpper(k.Protocol))
		}
		if ports[lp] {
			return nil, fmt.Errorf("LISTENERS: duplicate port %d", lp)
		}
		ports[lp] = true
		out = append(out, Listener{Port: lp, Kind: name, Protocol: k.Protocol, Implicit: k.Implicit, Upstream: u})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("LISTENERS must define at least one listener")
	}
	return out, nil
}

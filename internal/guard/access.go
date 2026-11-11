// SPDX-FileCopyrightText: 2026 Daniel Eder
//
// SPDX-License-Identifier: CC0-1.0

package guard

import (
	"bufio"
	"fmt"
	"io"
	"net/netip"
	"strings"
)

// Rules are the manually maintained allow/deny entries of the access file.
//
// File format, one entry per line, '#' starts a comment:
//
//	allow 203.0.113.7          # single IP: never banned or rate limited
//	allow 198.51.100.0/24      # CIDR range
//	deny  192.0.2.0/24         # connections are refused
//	allow alice@a.com          # mailbox is never locked by mailbox-based bans
//	deny  bob@a.com            # logins for this mailbox are refused locally
//
// A deny entry wins over a matching allow entry.
type Rules struct {
	allowNets  []netip.Prefix
	denyNets   []netip.Prefix
	allowUsers map[string]bool
	denyUsers  map[string]bool
}

// ParseRules parses an access file. Invalid lines are returned as warnings
// and skipped, so one typo does not disable the whole file.
func ParseRules(r io.Reader) (*Rules, []string) {
	rules := &Rules{allowUsers: map[string]bool{}, denyUsers: map[string]bool{}}
	var warnings []string
	sc := bufio.NewScanner(r)
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) != 2 {
			warnings = append(warnings, fmt.Sprintf("line %d: expected \"allow|deny <ip|cidr|mailbox>\"", n))
			continue
		}
		action := strings.ToLower(f[0])
		if action != "allow" && action != "deny" {
			warnings = append(warnings, fmt.Sprintf("line %d: unknown action %q (use allow or deny)", n, f[0]))
			continue
		}
		target := f[1]
		if strings.Contains(target, "@") {
			u := NormalizeUser(target)
			if action == "allow" {
				rules.allowUsers[u] = true
			} else {
				rules.denyUsers[u] = true
			}
			continue
		}
		p, err := parsePrefix(target)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("line %d: %v", n, err))
			continue
		}
		if action == "allow" {
			rules.allowNets = append(rules.allowNets, p)
		} else {
			rules.denyNets = append(rules.denyNets, p)
		}
	}
	if err := sc.Err(); err != nil {
		warnings = append(warnings, err.Error())
	}
	return rules, warnings
}

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid CIDR %q", s)
		}
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid IP address %q", s)
	}
	a = a.Unmap()
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func matchAny(nets []netip.Prefix, a netip.Addr) bool {
	if !a.IsValid() {
		return false
	}
	for _, p := range nets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func (r *Rules) deniedIP(a netip.Addr) bool { return r != nil && matchAny(r.denyNets, a) }
func (r *Rules) allowedIP(a netip.Addr) bool {
	return r != nil && !r.deniedIP(a) && matchAny(r.allowNets, a)
}
func (r *Rules) deniedUser(u string) bool  { return r != nil && r.denyUsers[u] }
func (r *Rules) allowedUser(u string) bool { return r != nil && !r.denyUsers[u] && r.allowUsers[u] }

// Count returns the number of entries, for logging.
func (r *Rules) Count() int {
	if r == nil {
		return 0
	}
	return len(r.allowNets) + len(r.denyNets) + len(r.allowUsers) + len(r.denyUsers)
}

// NormalizeUser returns the canonical form of a login name.
func NormalizeUser(u string) string { return strings.ToLower(strings.TrimSpace(u)) }

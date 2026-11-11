// SPDX-FileCopyrightText: 2026 Daniel Eder
//
// SPDX-License-Identifier: CC0-1.0

package proxy

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

// imapCaps builds the capability list advertised to the client from the
// upstream's capabilities.
func (s *session) imapCaps() string {
	up := s.srv.Upstream.Caps(s.ctx)
	if up == nil {
		up = []string{"IMAP4rev1"}
	}
	out := make([]string, 0, len(up)+4)
	hasRev := false
	for _, c := range up {
		u := strings.ToUpper(c)
		switch {
		case u == "STARTTLS", u == "LOGINDISABLED", u == "SASL-IR", strings.HasPrefix(u, "AUTH="):
			continue
		case strings.HasPrefix(u, "IMAP4REV"):
			hasRev = true
		}
		out = append(out, c)
	}
	if !hasRev {
		out = append([]string{"IMAP4rev1"}, out...)
	}
	if s.starttlsOffered() {
		out = append(out, "STARTTLS")
	}
	if s.authAllowed() {
		out = append(out, "SASL-IR", "AUTH=PLAIN", "AUTH=LOGIN")
	} else {
		out = append(out, "LOGINDISABLED")
	}
	return strings.Join(out, " ")
}

var imapLiteral = regexp.MustCompile(`\{(\d+)(\+?)\}$`)

// readIMAPCommand reads one command including literals and splits it into
// tag, command name and arguments (atoms, quoted strings and literals).
func (s *session) readIMAPCommand() (tag, cmd string, args []string, err error) {
	var toks []string
	for {
		line, err := readLine(s.clientR)
		if err != nil {
			return "", "", nil, err
		}
		line = trimCRLF(line)
		m := imapLiteral.FindStringSubmatchIndex(line)
		if m == nil {
			toks = append(toks, imapTokens(line)...)
			break
		}
		n, err := strconv.Atoi(line[m[2]:m[3]])
		if err != nil || n > maxLine {
			return "", "", nil, errors.New("literal too large")
		}
		toks = append(toks, imapTokens(line[:m[0]])...)
		if m[4] == m[5] { // synchronizing literal
			if err := s.toClient("+ Ready for literal data\r\n"); err != nil {
				return "", "", nil, err
			}
		}
		buf := make([]byte, n)
		if _, err := io.ReadFull(s.clientR, buf); err != nil {
			return "", "", nil, err
		}
		toks = append(toks, string(buf))
		if len(toks) > 20 {
			return "", "", nil, errors.New("command too long")
		}
	}
	if len(toks) > 0 {
		tag = toks[0]
	}
	if len(toks) > 1 {
		cmd = strings.ToUpper(toks[1])
	}
	if len(toks) > 2 {
		args = toks[2:]
	}
	return tag, cmd, args, nil
}

// imapTokens splits atoms and quoted strings. Parentheses are kept inside
// atoms; they only occur in commands whose arguments are ignored.
func imapTokens(s string) []string {
	var out []string
	for i := 0; i < len(s); {
		switch {
		case s[i] == ' ':
			i++
		case s[i] == '"':
			var b strings.Builder
			i++
			for i < len(s) && s[i] != '"' {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				b.WriteByte(s[i])
				i++
			}
			i++
			out = append(out, b.String())
		default:
			j := strings.IndexByte(s[i:], ' ')
			if j < 0 {
				j = len(s) - i
			}
			out = append(out, s[i:i+j])
			i += j
		}
	}
	return out
}

func (s *session) imap() error {
	if err := s.toClient("* OK [CAPABILITY " + s.imapCaps() + "] " + s.greetName() + " IMAP ready\r\n"); err != nil {
		return err
	}
	for {
		if err := s.countCommand(); err != nil {
			_ = s.toClient("* BYE Too many commands\r\n")
			return err
		}
		tag, cmd, args, err := s.readIMAPCommand()
		if err != nil {
			return err
		}
		if tag == "" || cmd == "" {
			if err := s.toClient("* BAD Missing command\r\n"); err != nil {
				return err
			}
			continue
		}
		switch cmd {
		case "CAPABILITY":
			err = s.toClient("* CAPABILITY "+s.imapCaps()+"\r\n", tag+" OK CAPABILITY completed\r\n")
		case "NOOP":
			err = s.toClient(tag + " OK NOOP completed\r\n")
		case "ID":
			err = s.toClient("* ID NIL\r\n", tag+" OK ID completed\r\n")
		case "LOGOUT":
			_ = s.toClient("* BYE Logging out\r\n", tag+" OK LOGOUT completed\r\n")
			return errLogout
		case "STARTTLS":
			if !s.starttlsOffered() {
				err = s.toClient(tag + " BAD TLS already active\r\n")
				break
			}
			if err := s.toClient(tag + " OK Begin TLS negotiation now\r\n"); err != nil {
				return err
			}
			err = s.startTLS()
		case "LOGIN", "AUTHENTICATE":
			if !s.authAllowed() {
				err = s.toClient(tag + " NO [PRIVACYREQUIRED] Use STARTTLS before logging in\r\n")
				break
			}
			var c creds
			if cmd == "LOGIN" {
				if len(args) != 2 || !validCred(args[0]) || !validCred(args[1]) || args[0] == "" {
					err = s.toClient(tag + " BAD Invalid LOGIN arguments\r\n")
					break
				}
				c = creds{user: args[0], pass: args[1]}
			} else {
				if len(args) == 0 {
					err = s.toClient(tag + " BAD Missing mechanism\r\n")
					break
				}
				ir, hasIR := "", len(args) > 1
				if hasIR {
					ir = args[1]
				}
				var serr error
				c, serr = s.saslCollect(args[0], ir, hasIR, func(ch string) error { return s.toClient("+ " + ch + "\r\n") })
				switch {
				case errors.Is(serr, errSASLCanceled):
					err = s.toClient(tag + " BAD Authentication canceled\r\n")
				case errors.Is(serr, errSASLMech):
					err = s.toClient(tag + " NO Unsupported authentication mechanism\r\n")
				case errors.Is(serr, errSASLSyntax):
					err = s.toClient(tag + " BAD Invalid authentication data\r\n")
				case serr != nil:
					return serr
				}
				if serr != nil {
					break
				}
			}
			done, lerr := s.imapLogin(tag, c)
			if done || lerr != nil {
				return lerr
			}
		default:
			err = s.toClient(tag + " BAD Command not allowed before login\r\n")
		}
		if err != nil {
			return err
		}
	}
}

// imapLogin returns done=true once the client is logged in.
func (s *session) imapLogin(tag string, c creds) (bool, error) {
	r := s.tryLogin(c, imapUpstreamLogin)
	switch r.out {
	case authOK:
		var lines []string
		for _, l := range r.reply {
			if t, ok := strings.CutPrefix(l, imapUpTag+" "); ok {
				l = tag + " " + t
			}
			lines = append(lines, l)
		}
		return true, s.toClient(lines...)
	case authFail:
		if err := s.toClient(tag + " NO [AUTHENTICATIONFAILED] Authentication failed\r\n"); err != nil {
			return false, err
		}
		if err := s.afterFailure(r); err != nil {
			_ = s.toClient("* BYE Too many failed logins\r\n")
			return false, err
		}
		return false, nil
	default:
		return false, s.toClient(tag + " NO [UNAVAILABLE] Temporary failure, try again later\r\n")
	}
}

const imapUpTag = "px1"

// imapUpstreamLogin logs in on a fresh upstream connection.
func imapUpstreamLogin(r *bufio.Reader, w io.Writer, c creds) (outcome, []string, error) {
	g, err := readLine(r)
	if err != nil {
		return 0, nil, err
	}
	if !hasPrefixFold(g, "* OK") {
		return authTemp, []string{g}, nil
	}
	var early string
	if c.authz != "" {
		early, err = imapSend(r, w, imapUpTag+" AUTHENTICATE PLAIN\r\n",
			base64.StdEncoding.EncodeToString([]byte(c.authz+"\x00"+c.user+"\x00"+c.pass))+"\r\n")
	} else {
		early, err = imapSendLogin(r, w, c.user, c.pass)
	}
	if err != nil {
		return 0, nil, err
	}
	var lines []string
	l := early
	for i := 0; ; i++ {
		if l == "" {
			if l, err = readLine(r); err != nil {
				return 0, nil, err
			}
		}
		lines = append(lines, l)
		if strings.HasPrefix(l, imapUpTag+" ") {
			break
		}
		if i > maxResponseLines {
			return 0, nil, errors.New("upstream response too long")
		}
		l = ""
	}
	f := strings.Fields(lines[len(lines)-1])
	status := ""
	if len(f) > 1 {
		status = strings.ToUpper(f[1])
	}
	last := strings.ToUpper(lines[len(lines)-1])
	switch {
	case status == "OK":
		return authOK, lines, nil
	case status == "NO" && !containsAny(last, "[UNAVAILABLE]", "[SERVERBUG]", "[INUSE]", "[LIMIT]"):
		return authFail, lines, nil
	default:
		return authTemp, lines, nil
	}
}

// imapSend writes parts, waiting for a "+" continuation between them. If the
// server answers with anything else, that line is returned as early.
func imapSend(r *bufio.Reader, w io.Writer, parts ...string) (early string, err error) {
	for i, p := range parts {
		if i > 0 {
			l, err := readLine(r)
			if err != nil {
				return "", err
			}
			if !strings.HasPrefix(l, "+") {
				return l, nil
			}
		}
		if _, err := io.WriteString(w, p); err != nil {
			return "", err
		}
	}
	return "", nil
}

func imapSendLogin(r *bufio.Reader, w io.Writer, user, pass string) (string, error) {
	if quotable(user) && quotable(pass) {
		return imapSend(r, w, imapUpTag+" LOGIN "+quote(user)+" "+quote(pass)+"\r\n")
	}
	return imapSend(r, w,
		fmt.Sprintf("%s LOGIN {%d}\r\n", imapUpTag, len(user)),
		fmt.Sprintf("%s {%d}\r\n", user, len(pass)),
		pass+"\r\n")
}

func quotable(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == 0 || s[i] >= 0x80 || s[i] == '\r' || s[i] == '\n' {
			return false
		}
	}
	return true
}

func quote(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

func (s *session) greetName() string {
	if s.srv.Hostname != "" {
		return s.srv.Hostname
	}
	return "mail proxy"
}

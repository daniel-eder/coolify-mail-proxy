// SPDX-FileCopyrightText: 2026 Daniel Eder
//
// SPDX-License-Identifier: CC0-1.0

package proxy

import (
	"bufio"
	"encoding/base64"
	"errors"
	"io"
	"strings"
)

// pop3Caps builds the CAPA lines advertised to the client.
func (s *session) pop3Caps() []string {
	up := s.srv.Upstream.Caps(s.ctx)
	if up == nil {
		up = []string{"TOP", "UIDL"}
	}
	var out []string
	for _, c := range up {
		u := strings.ToUpper(strings.TrimSpace(c))
		if u == "STLS" || u == "USER" || u == "SASL" || strings.HasPrefix(u, "SASL ") {
			continue
		}
		out = append(out, c)
	}
	if s.authAllowed() {
		out = append(out, "USER", "SASL PLAIN LOGIN")
	}
	if s.starttlsOffered() {
		out = append(out, "STLS")
	}
	return out
}

func (s *session) pop3() error {
	if err := s.toClient("+OK " + s.greetName() + " POP3 ready\r\n"); err != nil {
		return err
	}
	user := ""
	for {
		if err := s.countCommand(); err != nil {
			_ = s.toClient("-ERR Too many commands\r\n")
			return err
		}
		line, err := readLine(s.clientR)
		if err != nil {
			return err
		}
		line = trimCRLF(line)
		cmd, arg, _ := strings.Cut(line, " ")
		cmd = strings.ToUpper(cmd)
		switch cmd {
		case "CAPA":
			lines := []string{"+OK Capability list follows\r\n"}
			for _, c := range s.pop3Caps() {
				lines = append(lines, c+"\r\n")
			}
			err = s.toClient(append(lines, ".\r\n")...)
		case "STLS":
			if !s.starttlsOffered() {
				err = s.toClient("-ERR TLS already active\r\n")
				break
			}
			if err := s.toClient("+OK Begin TLS negotiation\r\n"); err != nil {
				return err
			}
			user = ""
			err = s.startTLS()
		case "QUIT":
			_ = s.toClient("+OK Bye\r\n")
			return errLogout
		case "USER":
			if !s.authAllowed() {
				err = s.toClient("-ERR Use STLS before logging in\r\n")
				break
			}
			if arg == "" || !validCred(arg) {
				err = s.toClient("-ERR Invalid user name\r\n")
				break
			}
			user = arg
			err = s.toClient("+OK\r\n")
		case "PASS":
			if user == "" {
				err = s.toClient("-ERR USER first\r\n")
				break
			}
			if !validCred(arg) {
				err = s.toClient("-ERR Invalid password\r\n")
				break
			}
			c := creds{user: user, pass: arg}
			user = ""
			done, lerr := s.pop3Login(c)
			if done || lerr != nil {
				return lerr
			}
		case "AUTH":
			if !s.authAllowed() {
				err = s.toClient("-ERR Use STLS before logging in\r\n")
				break
			}
			f := strings.Fields(arg)
			if len(f) == 0 {
				err = s.toClient("+OK\r\n", "PLAIN\r\n", "LOGIN\r\n", ".\r\n")
				break
			}
			ir, hasIR := "", len(f) > 1
			if hasIR {
				ir = f[1]
			}
			c, serr := s.saslCollect(f[0], ir, hasIR, func(ch string) error { return s.toClient("+ " + ch + "\r\n") })
			switch {
			case errors.Is(serr, errSASLCanceled):
				err = s.toClient("-ERR Authentication canceled\r\n")
			case errors.Is(serr, errSASLMech):
				err = s.toClient("-ERR Unsupported authentication mechanism\r\n")
			case errors.Is(serr, errSASLSyntax):
				err = s.toClient("-ERR Invalid authentication data\r\n")
			case serr != nil:
				return serr
			default:
				done, lerr := s.pop3Login(c)
				if done || lerr != nil {
					return lerr
				}
			}
		case "APOP":
			err = s.toClient("-ERR APOP not supported\r\n")
		default:
			err = s.toClient("-ERR Command not allowed before login\r\n")
		}
		if err != nil {
			return err
		}
	}
}

func (s *session) pop3Login(c creds) (bool, error) {
	useUser := c.authz == ""
	if caps := s.srv.Upstream.Caps(s.ctx); caps != nil && useUser {
		useUser = false
		for _, x := range caps {
			if strings.EqualFold(strings.TrimSpace(x), "USER") {
				useUser = true
			}
		}
	}
	r := s.tryLogin(c, func(r *bufio.Reader, w io.Writer, c creds) (outcome, []string, error) {
		return pop3UpstreamLogin(r, w, c, useUser)
	})
	switch r.out {
	case authOK:
		return true, s.toClient(r.reply...)
	case authFail:
		if err := s.toClient("-ERR [AUTH] Authentication failed\r\n"); err != nil {
			return false, err
		}
		return false, s.afterFailure(r)
	default:
		return false, s.toClient("-ERR [SYS/TEMP] Temporary failure, try again later\r\n")
	}
}

func pop3UpstreamLogin(r *bufio.Reader, w io.Writer, c creds, useUser bool) (outcome, []string, error) {
	g, err := readLine(r)
	if err != nil {
		return 0, nil, err
	}
	if !strings.HasPrefix(g, "+OK") {
		return authTemp, []string{g}, nil
	}
	cmd := func(line string) (string, error) {
		if _, err := io.WriteString(w, line); err != nil {
			return "", err
		}
		return readLine(r)
	}
	var resp string
	if useUser {
		if resp, err = cmd("USER " + c.user + "\r\n"); err != nil {
			return 0, nil, err
		}
		if strings.HasPrefix(resp, "+OK") {
			if resp, err = cmd("PASS " + c.pass + "\r\n"); err != nil {
				return 0, nil, err
			}
		}
	} else {
		ir := base64.StdEncoding.EncodeToString([]byte(c.authz + "\x00" + c.user + "\x00" + c.pass))
		if resp, err = cmd("AUTH PLAIN " + ir + "\r\n"); err != nil {
			return 0, nil, err
		}
		if strings.HasPrefix(resp, "+ ") || strings.TrimSpace(resp) == "+" {
			if resp, err = cmd(ir + "\r\n"); err != nil {
				return 0, nil, err
			}
		}
	}
	switch {
	case strings.HasPrefix(resp, "+OK"):
		return authOK, []string{resp}, nil
	case containsAny(strings.ToUpper(resp), "[SYS/TEMP]", "[IN-USE]", "[LOGIN-DELAY]"):
		return authTemp, []string{resp}, nil
	default:
		return authFail, []string{resp}, nil
	}
}

// SPDX-FileCopyrightText: 2026 Daniel Eder
//
// SPDX-License-Identifier: CC0-1.0

package proxy

import (
	"bufio"
	"encoding/base64"
	"errors"
	"io"
	"strconv"
	"strings"
)

// readSMTPReply reads a (possibly multi-line) SMTP reply.
func readSMTPReply(r *bufio.Reader) ([]string, error) {
	var lines []string
	for i := 0; i < maxResponseLines; i++ {
		l, err := readLine(r)
		if err != nil {
			return nil, err
		}
		lines = append(lines, l)
		if len(l) < 4 || l[3] != '-' {
			return lines, nil
		}
	}
	return nil, errors.New("upstream reply too long")
}

func smtpCode(lines []string) int {
	if len(lines) == 0 || len(lines[0]) < 3 {
		return 0
	}
	n, _ := strconv.Atoi(lines[0][:3])
	return n
}

// smtpExtensions builds the EHLO keyword lines advertised to the client.
func (s *session) smtpExtensions() []string {
	up := s.srv.Upstream.Caps(s.ctx)
	if up == nil {
		up = []string{"PIPELINING", "8BITMIME"}
	}
	var out []string
	for _, c := range up {
		u := strings.ToUpper(strings.TrimSpace(c))
		if u == "STARTTLS" || u == "AUTH" || strings.HasPrefix(u, "AUTH ") || strings.HasPrefix(u, "AUTH=") {
			continue
		}
		out = append(out, c)
	}
	if s.starttlsOffered() {
		out = append(out, "STARTTLS")
	}
	if s.authAllowed() {
		out = append(out, "AUTH PLAIN LOGIN")
	}
	return out
}

func (s *session) smtp() error {
	if err := s.toClient("220 " + s.greetName() + " ESMTP ready\r\n"); err != nil {
		return err
	}
	helo := ""
	for {
		if err := s.countCommand(); err != nil {
			_ = s.toClient("421 4.7.0 Too many commands\r\n")
			return err
		}
		line, err := readLine(s.clientR)
		if err != nil {
			return err
		}
		line = trimCRLF(line)
		f := strings.Fields(line)
		cmd := ""
		if len(f) > 0 {
			cmd = strings.ToUpper(f[0])
		}
		switch cmd {
		case "EHLO":
			helo = "localhost"
			if len(f) > 1 {
				helo = f[1]
			}
			ext := s.smtpExtensions()
			lines := []string{"250-" + s.greetName() + "\r\n"}
			if len(ext) == 0 {
				lines[0] = "250 " + s.greetName() + "\r\n"
			}
			for i, e := range ext {
				sep := "-"
				if i == len(ext)-1 {
					sep = " "
				}
				lines = append(lines, "250"+sep+e+"\r\n")
			}
			err = s.toClient(lines...)
		case "HELO":
			helo = "localhost"
			if len(f) > 1 {
				helo = f[1]
			}
			err = s.toClient("250 " + s.greetName() + "\r\n")
		case "NOOP", "RSET":
			err = s.toClient("250 2.0.0 OK\r\n")
		case "QUIT":
			_ = s.toClient("221 2.0.0 Bye\r\n")
			return errLogout
		case "STARTTLS":
			if !s.starttlsOffered() {
				err = s.toClient("503 5.5.1 TLS already active\r\n")
				break
			}
			if err := s.toClient("220 2.0.0 Ready to start TLS\r\n"); err != nil {
				return err
			}
			// The client must send EHLO again after the handshake.
			helo = ""
			err = s.startTLS()
		case "AUTH":
			switch {
			case !s.authAllowed():
				err = s.toClient("530 5.7.0 Must issue a STARTTLS command first\r\n")
			case helo == "":
				err = s.toClient("503 5.5.1 Send EHLO first\r\n")
			case len(f) < 2:
				err = s.toClient("501 5.5.4 Missing mechanism\r\n")
			default:
				ir, hasIR := "", len(f) > 2
				if hasIR {
					ir = f[2]
				}
				c, serr := s.saslCollect(f[1], ir, hasIR, func(ch string) error { return s.toClient("334 " + ch + "\r\n") })
				switch {
				case errors.Is(serr, errSASLCanceled):
					err = s.toClient("501 5.7.0 Authentication canceled\r\n")
				case errors.Is(serr, errSASLMech):
					err = s.toClient("504 5.5.4 Unrecognized authentication type\r\n")
				case errors.Is(serr, errSASLSyntax):
					err = s.toClient("501 5.5.2 Invalid authentication data\r\n")
				case serr != nil:
					return serr
				default:
					done, lerr := s.smtpLogin(c, helo)
					if done || lerr != nil {
						return lerr
					}
				}
			}
		case "MAIL", "RCPT", "DATA", "BDAT":
			err = s.toClient("530 5.7.0 Authentication required\r\n")
		default:
			err = s.toClient("502 5.5.1 Command not implemented before login\r\n")
		}
		if err != nil {
			return err
		}
	}
}

func (s *session) smtpLogin(c creds, helo string) (bool, error) {
	r := s.tryLogin(c, func(r *bufio.Reader, w io.Writer, c creds) (outcome, []string, error) {
		return smtpUpstreamLogin(r, w, c, helo)
	})
	switch r.out {
	case authOK:
		return true, s.toClient(r.reply...)
	case authFail:
		if err := s.toClient("535 5.7.8 Authentication credentials invalid\r\n"); err != nil {
			return false, err
		}
		if err := s.afterFailure(r); err != nil {
			_ = s.toClient("421 4.7.0 Too many failed logins\r\n")
			return false, err
		}
		return false, nil
	default:
		return false, s.toClient("454 4.7.0 Temporary authentication failure, try again later\r\n")
	}
}

func smtpUpstreamLogin(r *bufio.Reader, w io.Writer, c creds, helo string) (outcome, []string, error) {
	g, err := readSMTPReply(r)
	if err != nil {
		return 0, nil, err
	}
	if smtpCode(g) != 220 {
		return authTemp, g, nil
	}
	cmd := func(line string) ([]string, error) {
		if _, err := io.WriteString(w, line); err != nil {
			return nil, err
		}
		return readSMTPReply(r)
	}
	ehlo, err := cmd("EHLO " + helo + "\r\n")
	if err != nil {
		return 0, nil, err
	}
	if smtpCode(ehlo) != 250 {
		return authTemp, ehlo, nil
	}
	plain, login := false, false
	for _, l := range ehlo[1:] {
		if len(l) < 4 {
			continue
		}
		u := strings.ToUpper(strings.TrimSpace(l[4:]))
		if strings.HasPrefix(u, "AUTH ") || strings.HasPrefix(u, "AUTH=") {
			for _, m := range strings.Fields(u[5:]) {
				plain = plain || m == "PLAIN"
				login = login || m == "LOGIN"
			}
		}
	}
	var resp []string
	if plain || !login {
		ir := base64.StdEncoding.EncodeToString([]byte(c.authz + "\x00" + c.user + "\x00" + c.pass))
		if resp, err = cmd("AUTH PLAIN " + ir + "\r\n"); err != nil {
			return 0, nil, err
		}
	} else {
		b64 := func(v string) string { return base64.StdEncoding.EncodeToString([]byte(v)) + "\r\n" }
		if resp, err = cmd("AUTH LOGIN\r\n"); err == nil && smtpCode(resp) == 334 {
			if resp, err = cmd(b64(c.user)); err == nil && smtpCode(resp) == 334 {
				resp, err = cmd(b64(c.pass))
			}
		}
		if err != nil {
			return 0, nil, err
		}
	}
	switch code := smtpCode(resp); {
	case code == 235:
		return authOK, resp, nil
	case code == 334:
		// Unexpected challenge: cancel and report a temporary failure.
		_, _ = cmd("*\r\n")
		return authTemp, resp, nil
	case code >= 400 && code < 500:
		return authTemp, resp, nil
	default:
		return authFail, resp, nil
	}
}

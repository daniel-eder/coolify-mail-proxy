// SPDX-FileCopyrightText: 2026 Daniel Eder
//
// SPDX-License-Identifier: CC0-1.0

package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/daniel-eder/coolify-mail-proxy/internal/config"
)

const (
	maxLine          = 8192
	maxResponseLines = 1000
)

// session holds both ends of a connection. During negotiation it relays the
// pre-authentication dialogue line by line, so it can advertise and perform
// STARTTLS towards the client while the upstream is already TLS-encrypted.
type session struct {
	srv      *Server
	ctx      context.Context
	client   net.Conn
	clientR  *bufio.Reader
	upstream net.Conn
	upR      *bufio.Reader
	upgraded bool
}

func (s *session) negotiate(proto string) error {
	switch proto {
	case config.ProtoIMAP:
		return s.imap()
	case config.ProtoPOP3:
		return s.pop3()
	case config.ProtoSMTP:
		return s.smtp()
	}
	return fmt.Errorf("unsupported protocol %q", proto)
}

func readLine(r *bufio.Reader) (string, error) {
	var b []byte
	for {
		chunk, err := r.ReadSlice('\n')
		b = append(b, chunk...)
		if len(b) > maxLine {
			return "", errors.New("line too long")
		}
		if err == nil {
			return string(b), nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			if err == io.EOF && len(b) > 0 {
				return string(b), nil
			}
			return "", err
		}
	}
}

func (s *session) toClient(lines ...string) error {
	_, err := io.WriteString(s.client, strings.Join(lines, ""))
	return err
}

func (s *session) toUpstream(line string) error {
	_, err := io.WriteString(s.upstream, line)
	return err
}

// startTLS upgrades the client connection after the protocol's "go ahead"
// response has been sent.
func (s *session) startTLS() error {
	// Data pipelined after the STARTTLS command would be injected into the
	// encrypted session (CVE-2011-0411 style); refuse it.
	if s.clientR.Buffered() > 0 {
		return errors.New("client sent data after STARTTLS before handshake")
	}
	tc, err := s.srv.handshake(s.ctx, s.client)
	if err != nil {
		return fmt.Errorf("starttls handshake: %w", err)
	}
	s.client = tc
	s.clientR = bufio.NewReader(&idleConn{Conn: tc, timeout: s.srv.IdleTimeout})
	s.upgraded = true
	return nil
}

func firstWords(line string, n int) []string {
	f := strings.Fields(line)
	if len(f) > n {
		f = f[:n]
	}
	return f
}

// ---------- IMAP ----------

// imapAddStartTLS adds STARTTLS to CAPABILITY data in untagged responses
// and [CAPABILITY ...] response codes.
func imapAddStartTLS(line string) string {
	up := strings.ToUpper(line)
	if strings.Contains(up, " STARTTLS") {
		return line
	}
	idx := -1
	if strings.HasPrefix(up, "* CAPABILITY") {
		idx = len("* CAPABILITY")
	} else if i := strings.Index(up, "[CAPABILITY"); i >= 0 {
		idx = i + len("[CAPABILITY")
	}
	if idx < 0 {
		return line
	}
	return line[:idx] + " STARTTLS" + line[idx:]
}

func (s *session) imap() error {
	greeting, err := readLine(s.upR)
	if err != nil {
		return fmt.Errorf("upstream greeting: %w", err)
	}
	if err := s.toClient(imapAddStartTLS(greeting)); err != nil {
		return err
	}
	for {
		line, err := readLine(s.clientR)
		if err != nil {
			return err
		}
		w := firstWords(line, 2)
		if len(w) < 2 {
			return s.toUpstream(line)
		}
		tag, cmd := w[0], strings.ToUpper(w[1])
		switch cmd {
		case "STARTTLS":
			if s.upgraded {
				return s.toClient(tag + " BAD TLS already active\r\n")
			}
			if err := s.toClient(tag + " OK Begin TLS negotiation now\r\n"); err != nil {
				return err
			}
			return s.startTLS()
		case "CAPABILITY", "NOOP", "ID":
			if err := s.toUpstream(line); err != nil {
				return err
			}
			for i := 0; ; i++ {
				resp, err := readLine(s.upR)
				if err != nil {
					return err
				}
				if err := s.toClient(imapAddStartTLS(resp)); err != nil {
					return err
				}
				if strings.HasPrefix(resp, tag+" ") {
					break
				}
				if i > maxResponseLines {
					return errors.New("upstream response too long")
				}
			}
		default:
			// LOGIN, AUTHENTICATE, LOGOUT, ...: hand over to the raw relay.
			return s.toUpstream(line)
		}
	}
}

// ---------- POP3 ----------

func (s *session) pop3() error {
	greeting, err := readLine(s.upR)
	if err != nil {
		return fmt.Errorf("upstream greeting: %w", err)
	}
	if err := s.toClient(greeting); err != nil {
		return err
	}
	for {
		line, err := readLine(s.clientR)
		if err != nil {
			return err
		}
		w := firstWords(line, 1)
		cmd := ""
		if len(w) == 1 {
			cmd = strings.ToUpper(w[0])
		}
		switch cmd {
		case "STLS":
			if s.upgraded {
				return s.toClient("-ERR TLS already active\r\n")
			}
			if err := s.toClient("+OK Begin TLS negotiation\r\n"); err != nil {
				return err
			}
			return s.startTLS()
		case "CAPA":
			if err := s.toUpstream(line); err != nil {
				return err
			}
			first, err := readLine(s.upR)
			if err != nil {
				return err
			}
			if err := s.toClient(first); err != nil {
				return err
			}
			if !strings.HasPrefix(first, "+OK") {
				continue
			}
			hasSTLS := false
			for i := 0; ; i++ {
				resp, err := readLine(s.upR)
				if err != nil {
					return err
				}
				if strings.TrimRight(resp, "\r\n") == "." {
					if !hasSTLS {
						if err := s.toClient("STLS\r\n"); err != nil {
							return err
						}
					}
					if err := s.toClient(resp); err != nil {
						return err
					}
					break
				}
				if strings.EqualFold(strings.TrimSpace(resp), "STLS") {
					hasSTLS = true
				}
				if err := s.toClient(resp); err != nil {
					return err
				}
				if i > maxResponseLines {
					return errors.New("upstream response too long")
				}
			}
		default:
			// USER, PASS, APOP, AUTH, QUIT, ...: hand over to the raw relay.
			return s.toUpstream(line)
		}
	}
}

// ---------- SMTP ----------

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

// smtpAddStartTLS appends STARTTLS to a successful EHLO reply.
func smtpAddStartTLS(lines []string) []string {
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "250") {
		return lines
	}
	for _, l := range lines {
		if len(l) >= 4 && strings.EqualFold(strings.TrimSpace(l[4:]), "STARTTLS") {
			return lines
		}
	}
	out := make([]string, 0, len(lines)+1)
	for _, l := range lines {
		text := ""
		if len(l) > 4 {
			text = l[4:]
		} else {
			text = "\r\n"
		}
		out = append(out, "250-"+text)
	}
	return append(out, "250 STARTTLS\r\n")
}

func (s *session) smtp() error {
	greeting, err := readSMTPReply(s.upR)
	if err != nil {
		return fmt.Errorf("upstream greeting: %w", err)
	}
	if err := s.toClient(greeting...); err != nil {
		return err
	}
	for {
		line, err := readLine(s.clientR)
		if err != nil {
			return err
		}
		w := firstWords(line, 1)
		cmd := ""
		if len(w) == 1 {
			cmd = strings.ToUpper(w[0])
		}
		switch cmd {
		case "STARTTLS":
			if s.upgraded {
				return s.toClient("503 5.5.1 TLS already active\r\n")
			}
			if err := s.toClient("220 2.0.0 Ready to start TLS\r\n"); err != nil {
				return err
			}
			// After the handshake the client re-sends EHLO; the upstream
			// accepts a repeated EHLO as a session reset.
			return s.startTLS()
		case "EHLO", "HELO", "NOOP", "RSET":
			if err := s.toUpstream(line); err != nil {
				return err
			}
			reply, err := readSMTPReply(s.upR)
			if err != nil {
				return err
			}
			if cmd == "EHLO" {
				reply = smtpAddStartTLS(reply)
			}
			if err := s.toClient(reply...); err != nil {
				return err
			}
		default:
			// AUTH, MAIL, QUIT, ...: hand over to the raw relay.
			return s.toUpstream(line)
		}
	}
}

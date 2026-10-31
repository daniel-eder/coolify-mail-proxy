// SPDX-FileCopyrightText: 2026 Daniel Eder
//
// SPDX-License-Identifier: CC0-1.0

// Package autoconfig serves Thunderbird autoconfig and Outlook autodiscover
// documents pointing mail clients at the per-customer proxy hostname.
package autoconfig

import (
	"encoding/xml"
	"io"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"strings"
	"text/template"

	"github.com/daniel-eder/coolify-mail-proxy/internal/config"
)

type Handler struct {
	Cfg *config.Config
	Log *slog.Logger
}

type service struct {
	Type   string // imap, pop3, smtp
	Port   int
	Socket string // SSL or STARTTLS
}

type data struct {
	Domain, MailHost, DisplayName, Email string
	Incoming, Outgoing                   []service
	// Outlook gets one entry per protocol, preferring implicit TLS.
	Outlook []service
}

func (h *Handler) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { io.WriteString(w, "ok\n") })
	mux.HandleFunc("/mail/config-v1.1.xml", h.thunderbird)
	mux.HandleFunc("/.well-known/autoconfig/mail/config-v1.1.xml", h.thunderbird)
	mux.HandleFunc("/autodiscover/autodiscover.xml", h.outlook)
	mux.HandleFunc("/Autodiscover/Autodiscover.xml", h.outlook)
	return mux
}

// domainFromHost maps autoconfig.a.com / autodiscover.a.com / a.com to a
// configured customer domain.
func (h *Handler) domainFromHost(host string) string {
	if hst, _, err := net.SplitHostPort(host); err == nil {
		host = hst
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, p := range []string{"autoconfig.", "autodiscover."} {
		host = strings.TrimPrefix(host, p)
	}
	if h.Cfg.HasDomain(host) {
		return host
	}
	return ""
}

func domainFromEmail(email string) string {
	if i := strings.LastIndex(email, "@"); i >= 0 {
		return strings.ToLower(strings.TrimSpace(email[i+1:]))
	}
	return ""
}

func (h *Handler) build(domain, email string) data {
	d := data{Domain: domain, MailHost: h.Cfg.MailHost(domain), DisplayName: h.Cfg.DisplayName, Email: email}
	if d.DisplayName == "" {
		d.DisplayName = domain
	}
	for _, p := range config.Protocols {
		var ls []config.Listener
		for _, l := range h.Cfg.ListenersFor(p) {
			// Port 25 is a compatibility fallback only; never advertise it.
			if l.Port != 25 {
				ls = append(ls, l)
			}
		}
		for i, l := range ls {
			svc := service{Type: p, Port: l.Port, Socket: "STARTTLS"}
			if l.Implicit {
				svc.Socket = "SSL"
			}
			if p == config.ProtoSMTP {
				d.Outgoing = append(d.Outgoing, svc)
			} else {
				d.Incoming = append(d.Incoming, svc)
			}
			if i == 0 {
				d.Outlook = append(d.Outlook, svc)
			}
		}
	}
	return d
}

var funcs = template.FuncMap{"x": xmlEscape, "upper": strings.ToUpper}

var tbTmpl = template.Must(template.New("tb").Funcs(funcs).Parse(`<?xml version="1.0" encoding="UTF-8"?>
<clientConfig version="1.1">
  <emailProvider id="{{x .Domain}}">
    <domain>{{x .Domain}}</domain>
    <displayName>{{x .DisplayName}}</displayName>
    <displayShortName>{{x .DisplayName}}</displayShortName>
{{- range .Incoming}}
    <incomingServer type="{{.Type}}">
      <hostname>{{x $.MailHost}}</hostname>
      <port>{{.Port}}</port>
      <socketType>{{.Socket}}</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </incomingServer>
{{- end}}
{{- range .Outgoing}}
    <outgoingServer type="smtp">
      <hostname>{{x $.MailHost}}</hostname>
      <port>{{.Port}}</port>
      <socketType>{{.Socket}}</socketType>
      <authentication>password-cleartext</authentication>
      <username>%EMAILADDRESS%</username>
    </outgoingServer>
{{- end}}
  </emailProvider>
</clientConfig>
`))

func (h *Handler) thunderbird(w http.ResponseWriter, r *http.Request) {
	domain := h.domainFromHost(r.Host)
	if domain == "" {
		if d := domainFromEmail(r.URL.Query().Get("emailaddress")); h.Cfg.HasDomain(d) {
			domain = d
		}
	}
	if domain == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	if err := tbTmpl.Execute(w, h.build(domain, "")); err != nil {
		h.Log.Error("thunderbird template", "err", err)
	}
}

var olTmpl = template.Must(template.New("ol").Funcs(funcs).Parse(`<?xml version="1.0" encoding="utf-8"?>
<Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/responseschema/2006">
  <Response xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a">
    <Account>
      <AccountType>email</AccountType>
      <Action>settings</Action>
{{- range .Outlook}}
      <Protocol>
        <Type>{{if eq .Type "pop3"}}POP3{{else}}{{upper .Type}}{{end}}</Type>
        <Server>{{x $.MailHost}}</Server>
        <Port>{{.Port}}</Port>
        <LoginName>{{x $.Email}}</LoginName>
        <DomainRequired>off</DomainRequired>
        <SPA>off</SPA>
        <SSL>on</SSL>
        <Encryption>{{if eq .Socket "SSL"}}SSL{{else}}TLS{{end}}</Encryption>
        <AuthRequired>on</AuthRequired>
{{- if eq .Type "smtp"}}
        <UsePOPAuth>on</UsePOPAuth>
        <SMTPLast>off</SMTPLast>
{{- end}}
      </Protocol>
{{- end}}
    </Account>
  </Response>
</Autodiscover>
`))

func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

var emailRe = regexp.MustCompile(`(?i)<EMailAddress>\s*([^<\s]+)\s*</EMailAddress>`)

func (h *Handler) outlook(w http.ResponseWriter, r *http.Request) {
	email := ""
	if r.Method == http.MethodPost {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		if m := emailRe.FindSubmatch(body); m != nil {
			email = string(m[1])
		}
	}
	if email == "" {
		email = r.URL.Query().Get("emailaddress")
	}
	domain := domainFromEmail(email)
	if !h.Cfg.HasDomain(domain) {
		domain = h.domainFromHost(r.Host)
	}
	if domain == "" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	if err := olTmpl.Execute(w, h.build(domain, email)); err != nil {
		h.Log.Error("autodiscover template", "err", err)
	}
}

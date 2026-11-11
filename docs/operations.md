<!--
SPDX-FileCopyrightText: 2026 Daniel Eder

SPDX-License-Identifier: CC0-1.0
-->

# Operations and development

## Operational notes

* **Plaintext logins:** the plaintext ports require STARTTLS before login. `ALLOW_PLAINTEXT_AUTH=true` accepts unencrypted logins from legacy devices; their passwords then travel unencrypted between client and proxy. Set `ENABLE_PLAINTEXT=false` if you don't need the plaintext ports at all.
* **Shared source IP:** the provider sees every login coming from your server's IP, so one customer's failed logins could trigger rate limiting for everyone. The [login protection](security.md) prevents most of this. Consider telling the provider about the proxy anyway. `MAX_CONNS_PER_IP` limits concurrent connections per client.
* **Client IPs** appear only in this proxy's logs (JSON `session closed` lines with kind, SNI, STARTTLS flag, user, byte counts and duration; login and ban events), not at the provider.
* Ports 465/587 are SMTP *submission* (authenticated sending). They are not used for server-to-server delivery.
* Greetings before login come from the proxy (`mail.<first domain>`). Capabilities are the provider's, with STARTTLS and the SASL mechanisms adjusted. After login, all responses come from the provider unchanged.

## Development

```sh
go test ./...
docker build -t mailproxy .
docker run --rm -e MAIL_DOMAINS=a.com -e CERT_SOURCE=selfsigned \
  -e UPSTREAM_IMAP=imap.provider.com -e UPSTREAM_POP3=pop.provider.com -e UPSTREAM_SMTP=smtp.provider.com \
  -p 993:993 -p 143:143 -p 995:995 -p 110:110 -p 465:465 -p 587:587 -p 8080:8080 mailproxy
openssl s_client -connect localhost:993 -servername mail.a.com
openssl s_client -connect localhost:143 -starttls imap -servername mail.a.com
curl -H 'Host: autoconfig.a.com' localhost:8080/mail/config-v1.1.xml
```

Code layout:

```
cmd/mailproxy/        entrypoint, healthcheck subcommand
internal/config/      environment parsing and validation
internal/certs/       certmagic + Cloudflare DNS-01 (with CNAME delegation), self-signed mode
internal/proxy/       TLS-terminating listeners, upstream TLS, piping, limits
                      session.go: pre-login front end (SASL, login flow)
                      imap.go, pop3.go, smtp.go: protocol front ends and upstream login
                      upstream.go: upstream dialing, probe, capability cache
internal/guard/       login protection: bans, whitelist, rate limit, access file, state
internal/autoconfig/  Thunderbird autoconfig / Outlook autodiscover
```

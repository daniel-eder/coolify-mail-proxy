<!--
SPDX-FileCopyrightText: 2026 Daniel Eder

SPDX-License-Identifier: CC0-1.0
-->

# Operations and development

## Operational notes

* **Plaintext logins:** with `ENABLE_PLAINTEXT=true`, a client that doesn't use STARTTLS sends its password unencrypted between client and proxy. Only the hop to the provider is encrypted. That is the purpose of the setting (legacy devices, scanners, …). Set `ENABLE_PLAINTEXT=false` if you don't need it.
* **Shared source IP:** the provider sees every login coming from your server's IP, so one customer's failed logins can trigger rate limiting for everyone. Consider telling the provider about the proxy. `MAX_CONNS_PER_IP` limits single abusive clients.
* **Client IPs** appear only in this proxy's logs (JSON `session closed` lines with kind, SNI, STARTTLS flag, byte counts and duration), not at the provider.
* Ports 465/587 are SMTP *submission* (authenticated sending). They are not used for server-to-server delivery.
* Protocol greetings and capability lines from the provider are passed through unchanged, apart from the added STARTTLS capability, so they may contain the provider's hostname.

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
                      starttls.go: plaintext/STARTTLS front end for IMAP, POP3, SMTP
internal/autoconfig/  Thunderbird autoconfig / Outlook autodiscover
```

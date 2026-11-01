<!--
SPDX-FileCopyrightText: 2026 Daniel Eder

SPDX-License-Identifier: CC0-1.0
-->

# Configuration reference

All settings are environment variables, editable in Coolify's **Environment Variables** tab.

| Variable | Default | Description |
|---|---|---|
| `MAIL_DOMAINS` | – (required) | Comma/space/semicolon separated customer domains |
| `MAIL_HOST_PREFIX` | `mail` | Hostname prefix: `mail` → `mail.a.com` |
| `UPSTREAM_IMAP` | – | Provider IMAPS `host[:port]` (port 993) |
| `UPSTREAM_POP3` | – | Provider POP3S `host[:port]` (port 995) |
| `UPSTREAM_SMTP` | – | Provider SMTPS `host[:port]` (port 465) |
| `ENABLE_PLAINTEXT` | `true` | Also listen on 143/110/587 for unencrypted and STARTTLS clients |
| `ENABLE_PORT_25` | `false` | Also accept SMTP submission on port 25, see below |
| `LISTENERS` | derived | Advanced override, see below |
| `ACME_EMAIL` | – (required) | |
| `ACME_STAGING` | `false` | Use the Let's Encrypt staging CA |
| `CF_API_TOKEN` | – (required) | Cloudflare token with DNS edit rights |
| `CF_ZONE_TOKEN` | – | Optional separate `Zone:Read` token if `CF_API_TOKEN` is scoped narrowly |
| `ACME_DELEGATION_ZONE` | – | See [setup §5](setup.md#5-customers-whose-dns-is-not-in-your-cloudflare-account) |
| `ACME_DELEGATED_DOMAINS` | – | See [setup §5](setup.md#5-customers-whose-dns-is-not-in-your-cloudflare-account) |
| `DISPLAY_NAME` | domain | Provider name shown in Thunderbird |
| `REDIRECTS` | – | HTTP redirects, e.g. `webmail=https://webmail.provider.com/`, see [Redirects](#redirects) |
| `MAX_CONNS_PER_IP` | `20` | Concurrent connections per client IP and port (0 = unlimited) |
| `IDLE_TIMEOUT` | `35m` | Closes sessions idle longer than this (IMAP IDLE refreshes every ≤29 min) |
| `DIAL_TIMEOUT` | `10s` | Upstream connect timeout |
| `CERT_SOURCE` | `acme` | `selfsigned` for local testing only |

## Listeners

| Kind | Default port | Client side | Upstream |
|---|---|---|---|
| `imaps` | 993 | TLS from the first byte | `UPSTREAM_IMAP` (TLS) |
| `imap` | 143 | plaintext, `STARTTLS` offered | `UPSTREAM_IMAP` (TLS) |
| `pop3s` | 995 | TLS from the first byte | `UPSTREAM_POP3` (TLS) |
| `pop3` | 110 | plaintext, `STLS` offered | `UPSTREAM_POP3` (TLS) |
| `smtps` | 465 | TLS from the first byte | `UPSTREAM_SMTP` (TLS) |
| `submission` | 587 | plaintext, `STARTTLS` offered | `UPSTREAM_SMTP` (TLS) |

How the plaintext ports work: the proxy connects to the provider over TLS straight away
and relays the greeting and capability exchange (`CAPABILITY`/`CAPA`/`EHLO`), adding
`STARTTLS`/`STLS` to the advertised capabilities. If the client upgrades, the proxy performs
the TLS handshake with the customer's certificate. As soon as the client authenticates or sends
any other command, the proxy switches to a transparent byte relay. Data pipelined behind a
`STARTTLS` command is rejected, to block STARTTLS command injection.

`LISTENERS` replaces the derived set when you need non-standard ports or a different upstream:

```
LISTENERS=993:imaps,143:imap,2525:submission:smtp.other.com:465
#          port:kind[:upstreamHost:upstreamPort]
```

Every listener port must also be published under `ports:` in `docker-compose.yaml`.

## Redirects

`REDIRECTS` sends browsers visiting a hostname to another URL, e.g. so `webmail.a.com` always
leads to your current provider's webmail. Switching providers only means changing this variable.

```
REDIRECTS=webmail=https://webmail.provider.com/,portal.a.com=https://example.org/{domain}
#         source=target[,source=target...]
```

- A **source without a dot** is a label applied to every domain in `MAIL_DOMAINS`
  (`webmail` → `webmail.a.com`, `webmail.b.com`). A source with dots is a full hostname.
- `{domain}` in the target is replaced by the customer domain of the requested host.
- Redirects are **temporary** (HTTP 307, `Cache-Control: no-store`), so browsers don't remember
  an old provider. The browser address bar shows the target URL, not the proxy's hostname.
- The request path and query are not forwarded; the target is used as given.
- Entries are separated by commas, semicolons, spaces or newlines.

The redirect is served by the HTTP port (`HTTP_ADDR`, default 8080), so each source hostname must
point at this container (DNS record, proxied by Cloudflare is fine). Traefik routes it through\nthe `REDIRECT_HOST` compose variable (a single full hostname, e.g. `webmail.a.com`), for which it\nrequests a Let's Encrypt certificate via Coolify's `letsencrypt` resolver, so Cloudflare\n*Full (strict)* works. Set `REDIRECT_HOST` in Coolify to the same host as in `REDIRECTS`.

## Port 25

Some clients (e.g. Outlook with encryption set to *None*) default to port 25 for outgoing mail.
`ENABLE_PORT_25=true` adds a `submission` listener on port 25 (plaintext or STARTTLS, authenticated,
forwarded to `UPSTREAM_SMTP`). Port 25 is never advertised in autoconfig.

> **Warning:** port 25 is also where other mail servers deliver incoming mail. If `mail.<domain>`
> (or this server's IP) is listed as an **MX** for any served domain, remove that MX record first.
> Otherwise senders that reach this host get a permanent `530 Authentication required` and bounce
> the message instead of trying the next MX. Many residential ISPs also block outbound port 25,
> so 587 or 465 remain the recommended client ports.

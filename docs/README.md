<!--
SPDX-FileCopyrightText: 2026 Daniel Eder

SPDX-License-Identifier: CC0-1.0
-->

# Documentation

* [Overview](#overview)
* [Setup in Coolify](setup.md): prerequisites, deployment, DNS, adding customers, customer zones outside Cloudflare
* [Configuration reference](configuration.md): all environment variables and listener kinds
* [Autoconfig / Autodiscover](autoconfig.md): mail client auto-configuration and Traefik routing
* [Operations and development](operations.md): security notes, logs, local testing, code layout

## Overview

Each customer uses **their own hostname** (`mail.a.com`, `mail.b.com`, …) with a
valid Let's Encrypt certificate, while the mailboxes are hosted at a mail provider
that only offers one shared IMAP/POP3/SMTP hostname.

```
                      ┌──────────────── mailproxy ────────────────┐
Client ─TLS mail.a.com─▶ 993 imaps       ─┐                        │
Client ─plain/STARTTLS─▶ 143 imap        ─┴─TLS─▶ UPSTREAM_IMAP:993 │
Client ─TLS mail.a.com─▶ 995 pop3s       ─┐                        │
Client ─plain/STLS─────▶ 110 pop3        ─┴─TLS─▶ UPSTREAM_POP3:995 │
Client ─TLS mail.a.com─▶ 465 smtps       ─┐                        │
Client ─plain/STARTTLS─▶ 587 submission  ─┴─TLS─▶ UPSTREAM_SMTP:465 │
                      └────────────────────────────────────────────┘
Client ─HTTPS─▶ Cloudflare Tunnel ─▶ Coolify Traefik ─▶ mailproxy :8080  (autoconfig / autodiscover)
```

* **IMAP, POP3 and SMTP submission** are supported on both their implicit-TLS ports and their plaintext ports.
* Plaintext ports (143/110/587) accept unencrypted clients and also offer STARTTLS/STLS. In both cases the connection to the provider is always made over its **implicit-TLS port**.
* Certificates come from ACME **DNS-01 using the Cloudflare API**. This needs no inbound HTTP and works alongside Cloudflare Tunnel.
* One certificate per customer hostname, selected by SNI. Clients without SNI get the first domain's certificate.
* Thunderbird autoconfig and Outlook autodiscover for every configured domain.
* The provider's certificate is fully verified on every upstream connection.
* Per-client-IP connection limit, idle timeout, JSON logs and a health check.

Incoming mail (MX, port 25) is **not** proxied. Point MX/SPF/DKIM/DMARC directly at the provider.

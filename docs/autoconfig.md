<!--
SPDX-FileCopyrightText: 2026 Daniel Eder

SPDX-License-Identifier: CC0-1.0
-->

# Autoconfig / Autodiscover

The proxy serves mail client auto-configuration on port 8080:

* `GET /mail/config-v1.1.xml` and `GET /.well-known/autoconfig/mail/config-v1.1.xml`: Thunderbird and many other clients
* `POST|GET /autodiscover/autodiscover.xml`: Outlook (POX autodiscover, IMAP/POP3/SMTP settings)
* `GET /healthz`

The generated settings always use `mail.<customer-domain>` and never reveal the upstream
provider. Implicit TLS is listed first and the STARTTLS ports second. Outlook gets one entry
per protocol and prefers implicit TLS.

## Routing

`docker-compose.yaml` carries static Traefik labels with a catch-all rule:

```
HostRegexp(`^(autoconfig|autodiscover)\..+$`)   priority=1
```

Traefik sends every `autoconfig.*` and `autodiscover.*` request to the container. The app answers
only for domains in `MAIL_DOMAINS` and returns 404 for anything else. Because it has the lowest
priority, any explicit router for such a hostname elsewhere in Coolify still takes precedence.

## Fallback

If a Coolify update ever ignores custom labels: add `- SERVICE_FQDN_MAILPROXY_8080` to the
`environment` list, delete the labels, and put every autoconfig host into the service's
**Domains** field, using `http://` because TLS is terminated by Cloudflare:

```
http://autoconfig.a.com,http://autodiscover.a.com,http://autoconfig.b.com,…
```

<!--
SPDX-FileCopyrightText: 2026 Daniel Eder

SPDX-License-Identifier: CC0-1.0
-->

# Setup in Coolify

## 1. Prerequisites

1. **Public IP on the Coolify host** with the TCP ports you use (993, 143, 995, 110, 465, 587) open in every firewall and security group. Nothing else on the host may use them.
2. **Cloudflare API token** (*My Profile → API Tokens → Create Token → "Edit zone DNS"* template):
   * Permissions: `Zone → DNS → Edit` (and `Zone → Zone → Read`)
   * Zone resources: every customer zone (or "All zones from an account").
3. Each customer domain set up at your mail provider, including MX/SPF/DKIM/DMARC as the provider instructs.
4. The provider's **implicit-TLS** hostnames and ports (e.g. `imap.provider.com:993`, `pop.provider.com:995`, `smtp.provider.com:465`).

## 2. Deploy

1. **+ New Resource → Public Repository → Build Pack: Docker Compose**, pointing at this repository (`docker-compose.yaml`).
2. In **Environment Variables** set at least:

   | Variable | Example | Notes |
   |---|---|---|
   | `MAIL_DOMAINS` | `a.com,b.com` | Customer domains. Each becomes `mail.<domain>` |
   | `UPSTREAM_IMAP` | `imap.provider.com` | Provider IMAPS endpoint, `host[:port]`, default port 993 |
   | `UPSTREAM_POP3` | `pop.provider.com` | Provider POP3S endpoint, default port 995 |
   | `UPSTREAM_SMTP` | `smtp.provider.com` | Provider SMTPS endpoint, default port 465 |
   | `ACME_EMAIL` | `you@example.com` | Let's Encrypt account email |
   | `CF_API_TOKEN` | `…` | Cloudflare token, see above |

   A protocol whose `UPSTREAM_*` is empty is disabled. Remove its ports from `docker-compose.yaml` as well.
   See the [configuration reference](configuration.md) for all settings.
3. Leave the service's **Domains** field empty. Autoconfig routing is handled by static Traefik labels (see [autoconfig](autoconfig.md)).
4. For the first deploy, consider `ACME_STAGING=true` to check that issuance works without hitting Let's Encrypt rate limits. Then set it to `false` and redeploy. Staging and production certificates are stored separately, so nothing needs to be cleaned up.
5. Deploy. The logs show `obtaining/loading certificates` and then one `listening` line per port. The first issuance takes about 30–90 s per hostname.

Certificates and the ACME account live in the `mailproxy-data` volume and are renewed automatically.

## 3. DNS records per customer (`a.com`, zone in Cloudflare)

| Name | Type | Value | Proxy status |
|---|---|---|---|
| `mail.a.com` | A (and AAAA if you have IPv6) | your Coolify server's public IP | **DNS only (grey cloud)**, required, since Cloudflare can't proxy mail protocols |
| `autoconfig.a.com` | Tunnel public hostname | → Traefik (same target as your other Coolify apps) | proxied |
| `autodiscover.a.com` | Tunnel public hostname | → Traefik | proxied |
| `_imaps._tcp.a.com` | SRV (optional) | `0 1 993 mail.a.com` | – |
| `_pop3s._tcp.a.com` | SRV (optional) | `0 1 995 mail.a.com` | – |
| `_submissions._tcp.a.com` | SRV (optional) | `0 1 465 mail.a.com` | – |
| `_imap._tcp`, `_pop3._tcp`, `_submission._tcp` | SRV (optional) | `0 1 143/110/587 mail.a.com` | – |
| MX / SPF / DKIM / DMARC | | as specified by your provider | – |

For the tunnel hostnames: in *Zero Trust → Networks → Tunnels → your tunnel → Public Hostnames*, add `autoconfig.a.com` and `autodiscover.a.com` with the same service you use for Coolify apps, e.g. `http://localhost:80` or `https://localhost:443` with *No TLS Verify*. Both Traefik entrypoints are covered by the labels.

## 4. Adding a customer

1. Add the customer domain at your mail provider and create their mailboxes.
2. Create the DNS records from §3.
3. In Coolify, append the domain to `MAIL_DOMAINS` (e.g. `a.com,b.com,c.com`) and **Redeploy**.
4. Check:
   ```sh
   openssl s_client -connect mail.c.com:993 -servername mail.c.com </dev/null 2>/dev/null | openssl x509 -noout -subject -dates
   openssl s_client -connect mail.c.com:587 -starttls smtp -servername mail.c.com </dev/null 2>/dev/null | openssl x509 -noout -subject
   curl -s https://autoconfig.c.com/mail/config-v1.1.xml
   ```

Removing a customer: delete it from `MAIL_DOMAINS` and redeploy. The proxy immediately refuses TLS connections for that hostname.

## 5. Customers whose DNS is NOT in your Cloudflare account

DNS-01 needs a TXT record at `_acme-challenge.mail.x.com`. If you can't edit the
`x.com` zone, the customer delegates that one name to a zone you control. This is a
one-time CNAME, so you never need access to their DNS again.

1. Choose a zone in your Cloudflare account for challenges, e.g. `acme.example.net`. A subdomain of a zone you own is fine and needs no extra Cloudflare setup.
2. Ask the customer to create:

   | Name | Type | Value |
   |---|---|---|
   | `_acme-challenge.mail.x.com` | CNAME | `mail-x-com.acme.example.net` |
   | `mail.x.com` | A | your server's public IP |
   | `autoconfig.x.com`, `autodiscover.x.com` | CNAME | a hostname of yours that is routed through your tunnel to Traefik |

   The CNAME target is the mail hostname with dots replaced by dashes, followed by the delegation zone.
3. Set in Coolify:
   ```
   MAIL_DOMAINS=a.com,b.com,x.com
   ACME_DELEGATION_ZONE=acme.example.net
   ACME_DELEGATED_DOMAINS=x.com
   ```
4. Redeploy. The proxy writes the challenge TXT record to `mail-x-com.acme.example.net`, and Let's Encrypt follows the CNAME.

> Autoconfig for external zones: the hostnames must reach Traefik. Through Cloudflare Tunnel
> that only works for zones in your Cloudflare account. For external zones, either
> skip autoconfig (clients can be configured manually or through SRV records) or move the zone to
> Cloudflare, which is free.

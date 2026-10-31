# coolify-mail-proxy

TLS-terminating mail proxy that lets each customer use **their own hostname**
(`mail.a.com`, `mail.b.com`, …) with a valid Let's Encrypt certificate, while
the mailboxes are hosted at a mail provider that only offers a single shared
IMAP/POP3/SMTP hostname (e.g. `imap.provider.com`, `smtp.provider.com`).

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
* Plaintext ports (143/110/587) accept unencrypted clients and also offer STARTTLS/STLS. In both cases the connection to the provider is always made over its **implicit-TLS port**, so the upgrade to encryption happens transparently.
* Certificates come from ACME **DNS-01 using the Cloudflare API**. This needs no inbound HTTP and works alongside Cloudflare Tunnel.
* One certificate per customer hostname, selected by SNI. Clients without SNI get the first domain's certificate.
* Thunderbird autoconfig and Outlook autodiscover for every configured domain.
* The provider's certificate is fully verified on every upstream connection.
* Per-client-IP connection limit, idle timeout, JSON logs and a health check.

Incoming mail (MX, port 25) is **not** proxied. Point MX/SPF/DKIM/DMARC directly at the provider.

---

## 1. Prerequisites

1. **Public IP on the Coolify host** with the TCP ports you use (993, 143, 995, 110, 465, 587) open in every firewall and security group. Nothing else on the host may use them.
2. **Cloudflare API token** (*My Profile → API Tokens → Create Token → "Edit zone DNS"* template):
   * Permissions: `Zone → DNS → Edit` (and `Zone → Zone → Read`)
   * Zone resources: every customer zone (or "All zones from an account").
3. Each customer domain set up at your mail provider, including MX/SPF/DKIM/DMARC as the provider instructs.
4. The provider's **implicit-TLS** hostnames and ports (e.g. `imap.provider.com:993`, `pop.provider.com:995`, `smtp.provider.com:465`).

## 2. Deploy in Coolify

1. **+ New Resource → Public/Private Repository → Build Pack: Docker Compose**, pointing at this repo (`docker-compose.yaml`).
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
3. Leave the service's **Domains** field empty. Autoconfig routing is handled by the static Traefik labels in the compose file (see §5).
4. For the first deploy, consider `ACME_STAGING=true` to check that issuance works without hitting Let's Encrypt rate limits. Then set it to `false` and redeploy. Staging and production certificates are stored separately, so nothing needs to be cleaned up.
5. Deploy. The logs show `obtaining/loading certificates` and then one `listening` line per port. The first issuance takes about 30–90 s per hostname.

Certificates and the ACME account live in the `mailproxy-data` volume and are renewed automatically.

### All settings

| Variable | Default | Description |
|---|---|---|
| `MAIL_DOMAINS` | – (required) | Comma/space/semicolon separated customer domains |
| `MAIL_HOST_PREFIX` | `mail` | Hostname prefix: `mail` → `mail.a.com` |
| `UPSTREAM_IMAP` | – | Provider IMAPS `host[:port]` (port 993) |
| `UPSTREAM_POP3` | – | Provider POP3S `host[:port]` (port 995) |
| `UPSTREAM_SMTP` | – | Provider SMTPS `host[:port]` (port 465) |
| `ENABLE_PLAINTEXT` | `true` | Also listen on 143/110/587 for unencrypted and STARTTLS clients |
| `LISTENERS` | derived | Advanced override, see §7 |
| `ACME_EMAIL` | – (required) | |
| `ACME_STAGING` | `false` | Use the Let's Encrypt staging CA |
| `CF_API_TOKEN` | – (required) | Cloudflare token with DNS edit rights |
| `CF_ZONE_TOKEN` | – | Optional separate `Zone:Read` token if `CF_API_TOKEN` is scoped narrowly |
| `ACME_DELEGATION_ZONE` | – | See §6 |
| `ACME_DELEGATED_DOMAINS` | – | See §6 |
| `DISPLAY_NAME` | domain | Provider name shown in Thunderbird |
| `MAX_CONNS_PER_IP` | `20` | Concurrent connections per client IP and port (0 = unlimited) |
| `IDLE_TIMEOUT` | `35m` | Closes sessions idle longer than this (IMAP IDLE refreshes every ≤29 min) |
| `DIAL_TIMEOUT` | `10s` | Upstream connect timeout |
| `CERT_SOURCE` | `acme` | `selfsigned` for local testing only |

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

## 5. How autoconfig routing works

`docker-compose.yaml` carries static Traefik labels with a catch-all rule:

```
HostRegexp(`^(autoconfig|autodiscover)\..+$`)   priority=1
```

Traefik sends every `autoconfig.*` and `autodiscover.*` request to the container. The app answers only for domains in `MAIL_DOMAINS` and returns 404 for anything else. Because it has the lowest priority, any explicit router for such a hostname elsewhere in Coolify still takes precedence.

The generated settings always use `mail.<customer-domain>` and never reveal the upstream provider. Implicit TLS is listed first and the STARTTLS ports second. Outlook gets one entry per protocol and prefers implicit TLS.

Endpoints:

* `GET /mail/config-v1.1.xml` and `GET /.well-known/autoconfig/mail/config-v1.1.xml`: Thunderbird and many other clients
* `POST|GET /autodiscover/autodiscover.xml`: Outlook (POX autodiscover, IMAP/POP3/SMTP settings)
* `GET /healthz`

**Fallback (if a Coolify update ever ignores custom labels):** add
`- SERVICE_FQDN_MAILPROXY_8080` to the `environment` list, delete the labels, and put
every autoconfig host into the service's **Domains** field, using `http://` because TLS is
terminated by Cloudflare:
`http://autoconfig.a.com,http://autodiscover.a.com,http://autoconfig.b.com,…`

## 6. Customers whose DNS is NOT in your Cloudflare account

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

## 7. Listeners in detail

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

## 8. Operational notes

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

Layout:

```
cmd/mailproxy/        entrypoint, healthcheck subcommand
internal/config/      environment parsing and validation
internal/certs/       certmagic + Cloudflare DNS-01 (with CNAME delegation), self-signed mode
internal/proxy/       TLS-terminating listeners, upstream TLS, piping, limits
                      starttls.go: plaintext/STARTTLS front end for IMAP, POP3, SMTP
internal/autoconfig/  Thunderbird autoconfig / Outlook autodiscover
```

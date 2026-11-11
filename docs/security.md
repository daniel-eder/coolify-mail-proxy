<!--
SPDX-FileCopyrightText: 2026 Daniel Eder

SPDX-License-Identifier: CC0-1.0
-->

# Login protection

The provider sees every login coming from the proxy's IP address. Without protection, a
brute-force attack against one mailbox would get the **proxy itself** blocked by the provider,
and all customers would lose access. The proxy therefore checks every login attempt before it
reaches the provider.

## How it works

* **No provider connection before login.** The proxy answers greetings, capability requests and
  STARTTLS itself and only connects to the provider when a client actually logs in. Port scanners
  and clients that never log in don't reach the provider at all.
* **Escalating bans for failed logins.** Each client IP may fail `BAN_FREE_FAILURES` (2) logins.
  Further failures ban the IP for `30s`, then `5m`, `1h`, `24h` and `7d`; the last step repeats.
  A banned IP is turned away at connect time. On implicit-TLS ports the connection is closed;
  on plaintext ports it receives `* BYE` / `-ERR` / `554`. After `BAN_RESET_AFTER` (24h) without
  failures, counted from the end of the last ban, the count starts over.
* **A repeated wrong password counts once.** A phone that keeps retrying an outdated password
  causes one failure, not dozens. A username/password pair the provider rejected is answered
  locally for 15 minutes without asking the provider again. Passwords are kept only as salted
  hashes in memory and are never written to disk or logs.
* **Mailbox-based bans.** Failures are also counted per mailbox, across all IPs, with the same
  steps. While a mailbox is locked, any IP that tries to log in to it is banned as if it had
  caused the failures itself. This stops attacks spread over many IPs. **Whitelisted IPs are not
  affected by mailbox locks**, so attackers can't lock real users out of their usual devices.
* **Whitelist after successful logins.** A successful login whitelists the client IP for
  `WHITELIST_DURATION` (30 days, renewed on every login). Whitelisted IPs are not rate limited and
  may fail up to `WHITELIST_MAX_FAILURES` (10) logins per hour before normal bans apply. They are
  not fully exempt because a whitelisted IP may be a shared carrier/office NAT address.
* **Connection rate limit.** Non-whitelisted IPs may open `CONN_RATE_LIMIT` (15) connections per
  minute. Each exceeded minute counts as one failed login.
* **Unknown domains are rejected locally.** With `REQUIRE_KNOWN_DOMAIN=true`, logins whose username
  is not `user@<one of MAIL_DOMAINS>` (e.g. `admin`, `test`, `info@other.com`) never reach the
  provider and count as failures.
* **No passwords before encryption.** On plaintext ports, logins are only accepted after
  STARTTLS/STLS (`LOGINDISABLED` is advertised before). Set `ALLOW_PLAINTEXT_AUTH=true` for
  legacy devices that can't use TLS.
* **IPv6 is handled per /64 network**, because one host typically controls a whole /64.
* Failed logins are answered after `AUTH_FAIL_DELAY` (1s). A connection is closed after 3 failed
  logins.
* Logins are offered with the SASL mechanisms `PLAIN` and `LOGIN` (and IMAP `LOGIN`), which let the
  proxy see the username. Challenge-response mechanisms of the provider (e.g. `CRAM-MD5`) are not
  advertised.

Temporary provider errors, such as an unreachable provider, `[UNAVAILABLE]` or SMTP `4xx`, are not
counted as failures.

## Access file (manual allow/deny)

In Coolify, open the application, go to **Persistent Storage** and edit the file mounted at
`/config/access.conf`. Changes are picked up within about 10 seconds, without a restart.

```
# One entry per line, '#' starts a comment.
allow 203.0.113.7          # office IP: never banned or rate limited
allow 198.51.100.0/24      # same for a network (IPv4 or IPv6 CIDR)
deny  192.0.2.0/24         # connections are refused
allow alice@a.com          # this mailbox is never locked by mailbox-based bans
deny  bob@a.com            # logins for this mailbox are refused locally
```

* A `deny` entry wins over a matching `allow` entry.
* **To lift an automatic ban**, add an `allow` entry for the IP. Remove it again later if
  you like.
* Invalid lines are skipped and logged (`guard: access file` warnings); the rest of the file
  still applies.
* Edit the file in Coolify's Persistent Storage tab, not in `docker-compose.yaml`. The compose
  file only provides the initial content.

## Automatic state

Bans, failure counts and the whitelist are stored in `/data/access-state.json`, in the data volume.
They survive restarts and redeploys. The proxy rewrites the file every few seconds, so treat it as
read-only and use the access file for manual changes. The image has no shell, so to inspect the
file, copy it out on the server: `docker cp <container>:/data/access-state.json .`.
The log messages below cover day-to-day use.

## Logs

Relevant JSON log messages:

| `msg` | Meaning |
|---|---|
| `login ok` / `login failed` | Login result from the provider, with `user` |
| `login rejected locally` | Not forwarded; `reason` explains why (unknown domain, locked mailbox, repeated password, …) |
| `ip banned` | New ban, with `key` (IP or /64), `until`, `reason` |
| `mailbox locked` | New mailbox-based ban |
| `ip whitelisted` | First successful login from an IP |
| `rejected` | Connection refused at connect time (`connection rate exceeded`, `denied by access file`). Connections from already-banned IPs are not logged. |

## Settings

| Variable | Default | Description |
|---|---|---|
| `LOGIN_GUARD` | `true` | Automatic bans, whitelist and rate limit. The access file applies either way. |
| `BAN_FREE_FAILURES` | `2` | Failed logins tolerated before bans start |
| `BAN_STEPS` | `30s,5m,1h,24h,7d` | Ban duration for each further failure; the last one repeats |
| `BAN_RESET_AFTER` | `24h` | Forget failures after this long without new ones |
| `WHITELIST_DURATION` | `30d` | Whitelist duration after a successful login |
| `WHITELIST_MAX_FAILURES` | `10` | Failed logins per hour tolerated from a whitelisted IP |
| `CONN_RATE_LIMIT` | `15` | Connections per minute from a non-whitelisted IP (0 = off) |
| `REQUIRE_KNOWN_DOMAIN` | `true` | Reject usernames outside `MAIL_DOMAINS` locally |
| `ALLOW_PLAINTEXT_AUTH` | `false` | Accept logins on plaintext ports without STARTTLS |
| `AUTH_FAIL_DELAY` | `1s` | Delay before answering a failed login |
| `ACCESS_FILE` | `/config/access.conf` | Manual allow/deny file |
| `STATE_FILE` | `/data/access-state.json` | Automatic bans and whitelist |

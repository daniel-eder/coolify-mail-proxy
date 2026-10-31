<!--
SPDX-FileCopyrightText: 2026 Daniel Eder

SPDX-License-Identifier: CC0-1.0
-->

# Coolify Mail Proxy

[![REUSE Compliance Check](../../actions/workflows/reuse-compliance.yml/badge.svg)](../../actions/workflows/reuse-compliance.yml)

A Coolify service for proxying mail.
The purpose of the mail proxy is to allow securely accessing a mail service that only offers SSL certificates for a single domain via own domains instead.
The proxy handles the SSL termination and forwards the mail traffic to the actual mail service, allowing the service to be securely accessed under the user's own domain.
This enables providers to switch out the backend mail service without affecting the user's access, as the proxy abstracts the underlying service and maintains consistent SSL termination.

* IMAP, POP3 and SMTP submission, on implicit-TLS ports (993/995/465) and plaintext/STARTTLS ports (143/110/587)
* Per-domain Let's Encrypt certificates via Cloudflare DNS-01
* Thunderbird autoconfig and Outlook autodiscover

See the [documentation](docs/README.md) for setup and configuration.

## Licensing

Copyright (c) 2026 Daniel Eder

This project follows the [REUSE standard for software licensing](https://reuse.software/).
Each file contains copyright and license information, and license texts can be found in the [./LICENSES](./LICENSES) folder. For more information visit https://reuse.software/.

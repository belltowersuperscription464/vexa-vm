# Security policy

## Supported versions

The newest tagged release receives security fixes. Pre-release branches and old tags are not
supported unless a maintainer says otherwise in the release notes.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability
reporting feature on the repository **Security** tab. Include the affected version, impact,
reproduction steps, and any proposed mitigation. Remove live credentials and customer data from all
evidence.

Maintainers will acknowledge a complete report as soon as practical, coordinate validation and a
fix, and credit reporters who want attribution. Please allow a reasonable remediation window before
public disclosure.

## Deployment responsibility

Vexa-VM controls privileged virtualization and network operations. Operators must use TLS, restrict
management access, protect the master encryption key, back up SQLite and VM storage, review host
network changes, and test recovery. Read [`docs/SECURITY.md`](docs/SECURITY.md) for the technical
threat model and hardening guidance.

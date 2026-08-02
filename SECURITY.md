# Security Policy

## Supported Versions

Only the latest stable release of `@nekzus/tokenly` receives security updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.5.x   | Yes                |
| < 1.5.0 | No                 |

## Reporting a Vulnerability

We take the security of Tokenly seriously. If you believe you have discovered a security vulnerability, please do **NOT** open a public issue.

Instead, please report it responsibly by contacting our core security team:

- **Email:** `security@nekzus.com`
- **Response Time:** We acknowledge reports within 24 hours and aim to provide a remediation plan within 72 hours.

## Supply Chain Integrity & OIDC Trusted Publishing

Tokenly enforces strict supply chain security standards:

1. **SLSA Provenance Level 3:** All npm releases are built and published using **OpenID Connect (OIDC) Trusted Publishing** from GitHub Actions. Releases include cryptographic provenance attestations verified directly by npmjs.com.
2. **Zero Static NPM Tokens:** No long-lived static `NPM_TOKEN` credentials are stored in repository secrets.
3. **Mandatory GPG Commit Signing:** All commits integrated into `main`, `beta`, or `alpha` branches must be cryptographically signed using GPG (`git commit -S -m "..."`).

## Zero PII Policy

This repository adheres to a strict Zero PII (Personally Identifiable Information) policy:
- No real user names, credentials, private API tokens, or actual JWT secrets are stored in the source code or test suites.
- All test fixtures use anonymized mocks or placeholder values (`YOUR_SECRET_KEY_HERE`).

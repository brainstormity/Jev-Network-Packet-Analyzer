# Security Policy

## Supported Versions

NetworkSentinel is actively maintained. Security updates and patches are applied to the latest release on the `main` branch.

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

We take the security of NetworkSentinel seriously. If you discover a security vulnerability, please report it responsibly:

1. **Do Not File a Public GitHub Issue**: To protect users, please do not disclose vulnerabilities publicly until a patch has been released.
2. **Contact**: Open a confidential security advisory directly on GitHub via the **Security** tab -> **Report a vulnerability**, or email the maintainer.
3. **Information to Include**:
   * Description of the vulnerability and its potential impact.
   * Steps to reproduce the issue (proof of concept script or sample payload).
   * Any suggested mitigation or patch.
4. **Response Timeline**:
   * We will acknowledge receipt of your vulnerability report within 48 hours.
   * We will provide regular status updates until the vulnerability is resolved and patched.

## Safe Usage & Operational Guidelines

* **Capturing Network Traffic**: NetworkSentinel is designed for monitoring networks you own or have explicit authorization to inspect. Capturing traffic on third-party networks without authorization may violate local laws and privacy regulations.
* **Credentials & Secrets**: Never commit `.env` or production API keys (`TYPESAFE_API_KEY`, `RESEND_API_KEY`) to version control. The repository's `.gitignore` automatically prevents `.env` and SQLite database files from being tracked.

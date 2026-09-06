# Security Policy

## Supported Versions
We release security fixes only for the latest minor release of Jam.
Older versions are **not** patched — please update to the latest version.

| Version | Supported          |
|---------|--------------------|
| 3.3.0  | ✅ latest release   |
| < 3.3.0 | ❌ not supported    |

## Reporting a Vulnerability
If you discover a security vulnerability, please **do not** create a public issue.  
Instead, report it confidentially via:

- Email: [adrianmakridenko@duck.com](mailto:adrianmakridenko@duck.com)
- GitHub Security Advisories: [link to repo advisories](https://github.com/mkrdnk/jam/security/advisories)

We will acknowledge your report within **48 hours** and provide a timeline for the fix.

## Security Best Practices for Users
To use Jam securely, we recommend:
- Always keep Jam updated to the latest version.
- Use strong, random `secret_key` values and rotate them periodically.
- Do not hardcode secrets in your repository — use environment variables.
- Configure short TTLs for JWTs and sessions.
- Revoke tokens via lists/blacklists when user permissions change.
- Protect your Redis/JSON (if used as a backend) with authentication and network isolation.
- When using OTP, ensure clock synchronization for TOTP.

## Disclosure Policy
We follow **responsible disclosure**:
- Report privately first.
- We fix the issue and release a patch.
- We publish an advisory after users have had a chance to update.

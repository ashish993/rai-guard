# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅        |

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

To report a vulnerability:

1. Open a [GitHub Security Advisory](https://github.com/YOUR_GITHUB_USERNAME/rai-guard/security/advisories/new) (preferred — keeps the report private until fixed).
2. Or email the maintainer directly (see the email in `pyproject.toml`).

Please include:
- A clear description of the vulnerability
- Steps to reproduce
- Potential impact
- Any suggested mitigations you have already considered

You will receive an acknowledgement within **48 hours** and a resolution timeline within **7 days** for confirmed vulnerabilities.

## Scope

Areas of highest concern for this project:

- **SSRF** — `RAI_UPSTREAM_URL` validation and DNS resolution logic (`raiguard/proxy.py`)
- **Prompt injection bypass** — evasion of the `PromptInjectionCheck` patterns (`raiguard/checks/prompt_injection.py`)
- **PII regex false negatives** — patterns in `raiguard/checks/pii.py` that allow PII through
- **Auth bypass** — HTTP Basic Auth in the dashboard (`raiguard/dashboard/app.py`)
- **Evidence store integrity** — SQLite audit log manipulation (`raiguard/evidence/store.py`)
- **Dependency vulnerabilities** — in `fastapi`, `httpx`, `aiosqlite`, or `pydantic`

## Out of Scope

- Vulnerabilities in example scripts under `examples/` (these are for illustration only)
- Issues requiring physical access to the host machine
- Rate limiting / DoS (no rate limiting is currently implemented — see open issue)

## Disclosure Policy

We follow **coordinated disclosure**: fixes are developed privately, a new release is published, and the advisory is made public simultaneously.

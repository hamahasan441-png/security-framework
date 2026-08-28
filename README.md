# Security Framework

A safe, policy-driven Python framework for authorized defensive security assessment.

This project is intentionally non-destructive. It focuses on scope enforcement, safe discovery, structured findings, audit logging, secret redaction, and reporting.

## Features

- CIDR and domain allowlist scope enforcement
- TLS verification enabled by default
- Safe HTTP client with retries, timeouts, redirect validation, and rate limiting
- Robots-aware crawler with conservative defaults
- Structured findings with severity and confidence
- JSON, HTML, and SARIF reporting
- Plugin architecture for defensive security checks
- Secret redaction for logs and evidence
- Pytest test suite and GitHub Actions CI

## Quick start

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
python -m security_framework --config examples/config.yml
```

## Safety principles

This framework does **not** include exploit chaining, reverse shells, persistence, destructive payloads, WAF evasion, credential extraction, or database dumping.

All network operations must pass through scope enforcement before execution.

# Changelog

## 1.0.0 (2026-10-14)

First release, by Louis Wright.

- JSON manifest of sources (CSV, TSV, JSON, JSONL/NDJSON) with per-source match fields, include/exclude/redact and Article 15 metadata.
- Case-insensitive, nested and phone-normalised subject matching on one or more identifiers.
- Bundle output: `bundle.json`, one file per source, `SUMMARY.txt` and `SHA256SUMS`.
- Checks: missing/unparseable sources, match fields never present, secret fields removed, third-party emails/phones, missing purpose/category/recipients/retention, identity verification, one-month deadline (with extension) and overdue requests.
- Text/JSON/SARIF/Markdown output, `--fail-on`, exit codes 0/1/2, allowlist with expiry, severity overrides.
- Composite GitHub Action with job summary.

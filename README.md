# dsar-warden

> Assemble Data Subject Access Request exports from many systems into one structured, checksummed bundle, and catch the mistakes before you send it.

Under GDPR Article 15 (and the UK GDPR) a person can ask for a copy of everything you hold about them, and you normally have one calendar month to answer. In practice that means exporting from the CRM, the order database, the support desk and the mailing tool, filtering each export down to one person, stripping password hashes and other people's details, and adding the purposes, recipients and retention for each. `dsar-warden` does that from a small `dsar.json` manifest: it reads CSV, TSV, JSON and JSONL exports, keeps only the subject's records, writes a machine-readable bundle with checksums, and reports anything that would make the response wrong or late.

CLI, library and GitHub Action. Node.js 18+, **zero runtime dependencies**, runs offline. By Louis Wright.

## Features

- **Sources:** CSV/TSV (quotes, CRLF, BOM), JSON (array, or `recordsPath` into an object) and JSONL/NDJSON exports, paths relative to the manifest.
- **Matching:** one or more identifiers (`email`, `customer_id`, `phone`, ...) mapped to fields per source, including nested paths (`customer.id`) and several fields (`["to", "cc"]`); case-insensitive, phone numbers normalised.
- **Cleaning:** `include` to whitelist fields, `exclude` to drop them, `redact` to keep the key with `[REDACTED]`; password, token, hash, salt, OTP and session fields are always removed and reported.
- **Third-party data:** emails and phone numbers in exported records that do not belong to the subject are flagged until redacted or marked `thirdPartyReviewed`.
- **Article 15 context:** each source should state purpose, category, recipients and retention; these are carried into the bundle and `SUMMARY.txt`.
- **Deadline:** due date is one calendar month from `received` (clamped at month end; `extended: true` adds two months, or set `deadlineDays`); overdue and due-soon requests are reported, plus unverified identity.
- **Bundle:** `--out dir` writes `bundle.json`, `sources/<id>.json`, `SUMMARY.txt` and `SHA256SUMS`.

### Scope

dsar-warden works on exports you have already pulled from each system; it does not connect to databases or SaaS APIs, and it does not decide legal exemptions. Review the bundle before sending it. Not legal advice.

## Rules

| Rule | Default severity | What it means |
|---|---|---|
| `dsar-manifest-error` | high | Manifest is invalid or a source is misconfigured |
| `dsar-source-missing` | high | Source file does not exist |
| `dsar-source-parse-error` | high | Source file cannot be parsed |
| `dsar-overdue` | high | Response deadline has passed |
| `dsar-no-subject` | high | No subject identifiers were given |
| `dsar-third-party-data` | medium | Exported records contain personal data about other people (email/phone) that is not redacted |
| `dsar-deadline-near` | medium | Response is due within the warning window |
| `dsar-identity-unverified` | medium | Requester identity is not marked as verified |
| `dsar-match-field-missing` | medium | Source records never contain the configured match field |
| `dsar-secret-field` | low | Secret-looking field (password, token, hash) removed from the export; exclude it explicitly |
| `dsar-metadata-missing` | low | Source lacks Article 15 context: purpose, category, recipients or retention |
| `dsar-no-records` | info | Source holds no records for the subject |
| `allowlist-expired` | medium | An allowlist entry is past its `expires` date |
| `allowlist-unused` | info | An allowlist entry matched nothing |

## Install and run

```bash
npx dsar-warden requests/DSAR-2026-014 --out out/DSAR-2026-014
npx dsar-warden dsar.json --subject email=jane@acme.io --subject customer_id=C123 -o bundle
npx dsar-warden . --fail-on medium --format markdown
```

### Sample output

```text
dsar-warden — test/fixtures/bad/dsar.json
2 record(s) from 2/5 source(s), due 2026-02-05

HIGH     test/fixtures/bad/broken.json Source "logs": Unexpected end of JSON input [dsar-source-parse-error]
HIGH     test/fixtures/bad/dsar.json Response was due 2026-02-05 (252 day(s) ago) [dsar-overdue]
HIGH     test/fixtures/bad/dsar.json Duplicate source id "crm" [dsar-manifest-error]
HIGH     test/fixtures/bad/missing.json Source "billing": test/fixtures/bad/missing.json not found [dsar-source-missing]
MEDIUM   test/fixtures/bad/crm.csv Source "crm": no record has match field(s) email [dsar-match-field-missing]
MEDIUM   test/fixtures/bad/dsar.json Requester identity is not marked verified [dsar-identity-unverified]
```

## Options

```text
dsar-warden 1.0.0 — assemble and check Data Subject Access Request exports

Usage: dsar-warden [dsar.json|dir] [--subject key=value ...] [--out dir] [options]

Request
  -s, --subject <k=v>      Subject identifier, repeatable (e.g. email=jane@acme.io, customer_id=C123)
  -o, --out <dir>          Write the bundle: bundle.json, sources/*.json, SUMMARY.txt, SHA256SUMS
      --warn-days <n>      Warn when the response is due within n days (default 7)

Common
  -c, --config <file>     JSON config (default: .dsar-warden.json or "dsarWarden" in package.json)
  -f, --format <fmt>      text (default) | json | sarif | markdown
      --json <file>       Also write a JSON report
      --sarif <file>      Also write SARIF 2.1.0
      --markdown <file>   Also write Markdown (e.g. for a job summary)
      --fail-on <sev>     critical | high | medium | low | info | none (default: high)
      --list-rules        Print rules and default severities
      --no-fixes          Hide fix suggestions in text output
      --no-color          Disable colours
  -v, --version / -h, --help

Exit codes: 0 = passed, 1 = findings at or above --fail-on, 2 = usage, config or read error.
```

## Configuration and allowlist

Options can live in `.dsar-warden.json` (or a `"dsarWarden"` key in `package.json`, or `--config <file>`):

```json
{
  "failOn": "medium",
  "severity": {
    "dsar-manifest-error": "low"
  },
  "allowlist": [
    {
      "rule": "dsar-third-party-data",
      "subject": "support",
      "reason": "Agent names reviewed and kept per policy",
      "expires": "2027-03-31"
    }
  ],
  "warnDays": 10
}
```

- **`severity`** changes a rule's severity, or turns it `"off"`.
- **`allowlist`** entries suppress matching findings. Each needs a `reason` and matches on any combination of `rule`, `file`, `subject` (globs with `*`) and `match` (a substring of the message). Add `expires` (`YYYY-MM-DD`) so the exception is time-boxed: once it lapses the finding comes back along with an `allowlist-expired` finding (medium). Entries that no longer match anything are reported as `allowlist-unused` (info).

The config file is looked up in the target directory first, then in the current directory, so `.dsar-warden.json` can live at your repository root. Other keys: `warnDays` and `failOn`; the request and sources live in `dsar.json`.

## Output and exit codes

- `--format text` (default), `json`, `sarif` (SARIF 2.1.0 for GitHub code scanning) or `markdown` (for job summaries and PR comments). `--json`, `--sarif` and `--markdown` write extra report files in the same run.
- `--fail-on <severity>` sets the threshold (`critical`, `high`, `medium`, `low`, `info`, `none`; default `high`).
- Exit codes: **0** passed, **1** findings at or above `--fail-on`, **2** usage, config or read error.

## GitHub Action

```yaml
permissions:
  contents: read
  security-events: write   # only needed for the SARIF upload
jobs:
  dsar-warden:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
        with: { persist-credentials: false }
      - uses: MrLouisWright/dsar-warden@v1
        with:
          path: requests/DSAR-2026-014
          fail-on: high
          sarif: dsar-warden.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with: { sarif_file: dsar-warden.sarif }
```

| Input | Description | Default |
|---|---|---|
| `path` | Manifest file, or directory containing `dsar.json` | `.` |
| `fail-on` | Failure threshold | `high` |
| `config` | Config file path | |
| `sarif` / `json` | Write SARIF / JSON report to this path | |
| `job-summary` | Add the Markdown report to the job summary | `true` |
| `args` | Extra CLI arguments | |

The action runs the bundled CLI with Node 20; it has no dependencies to install. Pin it to a commit SHA if your policy requires it.

## Library

```js
import { assemble, writeBundle } from "dsar-warden";
const { bundle, raw } = assemble(manifest, { baseDir: "requests/DSAR-2026-014" });
if (!raw.some((f) => f.severity === "high")) writeBundle(bundle, "out");
```

Types are included.

## Requirements

Node.js 18 or newer. Zero runtime dependencies.

## Support

If this project is useful to you, you can support its development with a donation: [Buy me a coffee](https://donate.stripe.com/aFa00lek3cvX4Ds2Fk9EI0b). It helps keep these tools maintained, documented and free for everyone.

## Licence

MIT © Louis Wright ([Louis Wright](https://github.com/MrLouisWright))

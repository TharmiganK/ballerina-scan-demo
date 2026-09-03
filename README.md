# bal scan → SARIF → GitHub code scanning

> [!WARNING]
> **The Ballerina code in this repository is deliberately vulnerable.**
> It exists solely to exercise the [`bal scan`](https://ballerina.io/learn/scan-tool/) static analysis tool and to verify how its SARIF output behaves in GitHub code scanning. Do not copy any of it into real software.

## What this is

A single Ballerina package that triggers **all 15 `bal scan` security rules**, plus several language rules, scanned in CI and published to GitHub code scanning.

Two purposes:

1. A **reference GitHub Actions workflow** for running `bal scan` and publishing results — see [`.github/workflows/scan.yml`](.github/workflows/scan.yml).
2. **Empirical verification** of how the SARIF actually behaves once GitHub has it. Findings are recorded in [`RESULTS.md`](RESULTS.md).

## What triggers what

| File | Rules |
|---|---|
| `crypto_rules.bal` | `ballerina/crypto:1` insecure cipher mode · `:2` weak password hashing · `:3` reused IV |
| `http_rules.bal` | `ballerina/http:1` default resource accessor · `:2` permissive CORS · `:3` SSRF · `:4` open redirect |
| `file_io_rules.bal` | `ballerina/file:1` publicly writable directory · `:2` path injection · `ballerina/io:1` path injection |
| `os_rules.bal` | `ballerina/os:1` command argument injection · `:2` environment variable injection |
| `auth_rules.bal` | `ballerina/jwt:1` unsigned JWT · `ballerina/email:1` TLS hostname verification disabled |
| `log_rules.bal` | `ballerina/log:1` sensitive configurable values logged |
| `language_rules.bal` | `ballerina:1` checkpanic · `:2` unused parameter · `:10` self-assignment |

The crypto and auth samples use `public function`, so they also trigger `ballerina:3` (non-isolated public function). That is intentional — it puts more than one rule kind in the report.

## Running it locally

```bash
bal tool pull scan
bal scan --format=sarif      # writes target/report/scan_results.sarif
bal scan                     # writes target/report/scan_results.json
```

`--format=sarif` writes **only** the SARIF file; it does not also produce the JSON report. Run the command twice if you need both.

## Two things worth knowing before you copy the workflow

**`bal scan` always exits 0.** A failed scan produces an empty result set, which uploads cleanly and tells GitHub that every previous alert is fixed. The workflow asserts that the SARIF exists and is non-empty before uploading.

**The severity gate counts SARIF `level == "warning"`, not `error`.** `bal scan` derives the SARIF level from the rule *kind*: `VULNERABILITY → warning`, `CODE_SMELL → note`, `BUG → error`. Since no rule is currently classified `BUG`, **nothing ever emits `error`** — so a gate written against `error` can never fire. Today every security rule is `warning` and every language rule is `note`, which makes `warning` a usable proxy for "security finding".

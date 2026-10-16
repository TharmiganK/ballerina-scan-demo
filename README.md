# Code scanning comparison: Ballerina, Go, Java, Python

> [!WARNING]
> **Every sample in this repository is deliberately vulnerable.** It exists only to exercise static analysis tools and to compare how their findings appear in GitHub code scanning. Do not copy any of it into real software.

## What this is

The same five integrations, with the same vulnerabilities, written in four languages and scanned by each language's code scanning action:

| Language | Directory | Scanned by | Workflow |
|---|---|---|---|
| Ballerina | [`ballerina/`](ballerina) (a workspace) | [`scan-ballerina`](https://github.com/CharanaManawathilake/scan-ballerina) | [`ballerina-scan.yml`](.github/workflows/ballerina-scan.yml) |
| Go | [`go/`](go) | CodeQL, gosec | [`codeql.yml`](.github/workflows/codeql.yml), [`gosec.yml`](.github/workflows/gosec.yml) |
| Java | [`java/`](java) | CodeQL | [`codeql.yml`](.github/workflows/codeql.yml) |
| Python | [`python/`](python) | CodeQL, Bandit | [`codeql.yml`](.github/workflows/codeql.yml), [`bandit.yml`](.github/workflows/bandit.yml) |

`main` carries the baseline findings shown in the Security tab. Pull requests add new findings to compare how each tool reports them on the pull request.

**Results:** [`docs/COMPARISON.md`](docs/COMPARISON.md) maps each `bal scan` rule to what CodeQL, gosec and Bandit report for the same code, and records how each tool's findings appeared on pull request #1.

## The integrations

| Ballerina package | Scenario | `bal scan` rules |
|---|---|---|
| `order_api` | REST order service with a checkout redirect | `ballerina/http:1`, `:2`, `:4` |
| `webhook_relay` | Forwards webhooks to subscribers and emails delivery failures | `ballerina/http:3`, `ballerina/email:1`, `ballerina/log:1` |
| `document_store` | Upload, download and delete documents | `ballerina/file:1`, `:2`, `ballerina/io:1` |
| `auth_service` | Registration, JWT issuing, PII encryption | `ballerina/jwt:1`, `ballerina/crypto:1`, `:2`, `:3`, `ballerina:1`, `:3`, `:14` |
| `backup_job` | CLI database backup | `ballerina/os:1`, `:2`, `:4`, `ballerina:2`, `:10` |

The Go, Java and Python ports use the same names and reproduce each vulnerability in the shape `bal scan` detects. Every sink carries a `Vulnerable: <ballerina rule> (CWE-n)` comment, so the same finding can be traced across languages.

## Running the scanners locally

```bash
(cd ballerina && bal scan --format=sarif)        # ballerina/target/report/scan_results.sarif
(cd go && gosec -no-fail -fmt sarif -out gosec.sarif ./...)
bandit -r python -f sarif -o bandit.sarif
```

The earlier single-package experiment against scan tool 0.11.0 is kept in [`docs/archive/results-scan-0.11.0.md`](docs/archive/results-scan-0.11.0.md).

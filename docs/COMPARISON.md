# How the same findings appear across scanners

Run on 16 October 2026. Baseline: `main` at `acf265c`. Pull request: [#1](https://github.com/TharmiganK/ballerina-scan-demo/pull/1) at `cf3b584`.

**Environment:** Ballerina 2201.14.1 · scan tool 0.12.0 · `scan-ballerina` at `e477f38` · CodeQL 2.27.2 (`security-extended`) · gosec 2.29.0 · Bandit 1.8.6 (`PyCQA/bandit-action@v1.0.1`) · `upload-sarif` v4.39.0 · public repository · same-repository pull request.

## Summary

| | Ballerina (`scan-ballerina`) | CodeQL (Go, Java, Python) | gosec | Bandit |
|---|---|---|---|---|
| Baseline alerts on `main` | 23 | 15 (3 Go, 9 Java, 3 Python) | 19 | 4 |
| Rows of the mapping below matched (16) | 16 (by construction) | 8 (Java 7, Go 2, Python 2) | 8 | 3 |
| `security_severity_level` set | **No**, on all 23 | **Yes**, high or medium on all 15 | No | No |
| CWE tags in the Security tab | Yes, plus OWASP | Yes | No (CWE is in SARIF `relationships`, which GitHub does not read) | Yes |
| Rule name in the alert | **Empty** (falls back to the rule id) | Query id | Yes | Generic plugin name such as `blacklist` |
| Inline review comment on new findings | Yes, rule description and remediation | Yes, result message | Yes, rule name only | Yes, empty title |
| Code scanning check on the pull request | **failure** — "7 new alerts including 5 errors" | success — "1 new alert including 1 medium severity security vulnerability" | failure — "3 new alerts including 3 errors" | success — "2 new alerts" |

## Rule mapping

Each row is one vulnerability, reproduced in the shape `bal scan` detects. The cells show what each tool reported on `main` at that sink. "—" means no alert.

| Ballerina rule (CWE) | Go: CodeQL | Go: gosec | Java: CodeQL | Python: CodeQL | Python: Bandit |
|---|---|---|---|---|---|
| `http:1` default resource accessor (352) | — | — | — | — | — |
| `http:2` permissive CORS (942) | — | — | — | — | — |
| `http:3` SSRF via path segment (918) | — | G704 | — | — | — |
| `http:4` open redirect (601) | — | G710 | `java/unvalidated-url-redirection` | — | — |
| `log:1` secret written to the log (532) | `go/clear-text-logging` | G706 (log injection, a different issue) | `java/log-injection` (a different issue) | `py/clear-text-logging-sensitive-data` | — |
| `email:1` TLS host name not verified (297) | `go/disabled-certificate-check` | G402 | `java/insecure-smtp-ssl` | — | — |
| `file:1` publicly writable directory (377) | — | G306 (file permissions) | — | — | — |
| `io:1` path injection on read (22) | — | G304, G703 | `java/path-injection` | — | — |
| `file:2` path injection on delete (22) | — | G703 | `java/path-injection` | — | — |
| `crypto:1` ECB mode (327) | — (no ECB mode in Go, hand-rolled) | — | `java/weak-cryptographic-algorithm` | `py/weak-cryptographic-algorithm` | B305 |
| `crypto:2` BCrypt work factor 4 (916) | — | — | — | — | — |
| `crypto:3` hard-coded IV (329) | — | G407 | `java/static-initialization-vector` | — | — |
| `jwt:1` unsigned JWT (347) | — | — | — | — | — |
| `os:1` command-line input to a command (78) | — (CLI args are not a default CodeQL source) | G702, G204 | — | — | B603 (any `subprocess` call) |
| `os:2` environment variable from input (454) | — | — | — | — | — |
| `os:4` executable resolved through PATH (426) | — | — | `java/relative-path-command` | — | B607 |

`bal scan` also reported `ballerina:14` (non-configurable secret), which fires on any variable or field whose name contains a secret-like word, including computed values such as `passwordHash`. It was not ported.

Things that stand out:

- **CodeQL found 8 of the 16 rows across the three languages: 7 in Java, 2 each in Go and Python.** In Go and Python, CodeQL found neither the path injection nor the open redirect. The Python sinks are reached through Flask path parameters concatenated after a fixed prefix, and the Go ones through `r.PathValue`, which these queries apparently do not treat as tainted in this shape.
- **Nothing flags `http:1`, `http:2`, `crypto:2`, `jwt:1` or `os:2`.** These are Ballerina-only coverage in this comparison.
- **gosec is the closest match** to `bal scan`'s coverage, but it is also the noisiest: five of its 19 alerts have no Ballerina counterpart (G114, G115, G117, G705, G707).

## What the pull request showed

The pull request adds the same three findings in each language on changed lines: SSRF via a path segment (`http:3`), BCrypt work factor 4 (`crypto:2`), and command-line input to `tar` resolved through PATH (`os:1`, `os:4`).

### New alerts and inline review comments

`github-advanced-security[bot]` posted one review per tool and one inline comment per new alert, only on changed lines:

| Tool | New alerts on the changed lines | Missed |
|---|---|---|
| Ballerina | `http:3` ×2 (one per path segment), `crypto:2`, `os:1`, `os:4`, plus `ballerina:14` ×2 | — |
| CodeQL | `java/relative-path-command` | SSRF and BCrypt in all three languages; `tar` in Go and Python |
| gosec | G704 (SSRF), G702 + G204 (command) | BCrypt cost |
| Bandit | B603 + B607 (`tar`) | SSRF, BCrypt cost |

How each comment reads:

```text
## Ballerina Scan Tool / A password hashing function is configured with a work factor too low to resist brute-force attacks.
A password hashing function such as BCrypt or Argon2 is only as strong as its cost parameters. ... Use a BCrypt work factor of at least 10, or Argon2id with at least 19456 KiB of memory and 2 iterations.

## CodeQL / Executing a command with a relative path
Command with a relative path 'tar' is executed.

## gosec / SSRF via taint analysis
SSRF via taint analysis

## Bandit /
Starting a process with a partial executable path
```

The Ballerina comment is the most actionable of the four. It uses the rule's short description as the title and its full description as the body, so the remediation reaches the pull request. Bandit's title is empty because its SARIF rules carry no short description.

### Check conclusions

GitHub's default check-failure threshold is "high or higher" for security alerts and "errors" for other alerts. Only CodeQL alerts carry `security-severity`, so only CodeQL is judged on the security scale. Every other tool is judged by SARIF `level`:

- **Ballerina fails the check** because scan tool 0.12.0 emits `error` for high-impact rules. Under 0.11.0 nothing reached `error` and the check always passed (see [the archive](archive/results-scan-0.11.0.md)).
- **CodeQL passes** with a new medium-severity security alert, as configured.
- **gosec fails** because it emits `error` for almost everything.
- **Bandit passes** because its subprocess findings are `note`.

So a Ballerina finding can block a pull request today, but on the "errors" scale rather than the security-severity scale. Adding `security-severity` to the rules would move Ballerina alerts to the same scale as CodeQL, with severity filters and the security severity badge in the Security tab.

### The `scan-ballerina` gate and annotations

The workflow sets `fail-on-severity: high` with `max-findings: 10`, which is the baseline's high count. The pull request had 15 high findings, so the `bal scan` job failed with:

```text
Found 15 finding(s) at or above high severity; at most 10 are allowed.
```

The gate counts every finding in the scan, not the new ones. That works as a ratchet only as long as `max-findings` matches `main`, so someone has to update it whenever `main` changes.

`annotations: true` is not useful on a pull request in a repository that already has findings:

- It annotates every finding, on any line, not only the changed ones.
- GitHub keeps at most 10 annotations per level. The action annotated 22 of 30 findings and warned about the rest.
- One of the omitted findings was the new `http:3`. The code-scanning review comments did include it.

Leave `annotations` off when `github-code-scanning` is enabled. The review comments are diff-scoped and complete.

### Alert identity is weaker than it looks

Three alerts that already existed on `main` were reported as new on the pull request:

- Bandit B603 and B607 on `python/backup_job.py:15`. The line itself did not change, but code was added on the lines below it.
- gosec G710 at `go/internal/orders/orders.go:93`. It moved to line 105, and the lines after it also changed.

None of these tools emits `partialFingerprints`, so `upload-sarif` computes `primaryLocationLineHash`, which also covers the text after the flagged line. Any change just below a finding closes the old alert and opens a new one. `bal scan` does not emit fingerprints either, so it is exposed to the same churn; it was not hit here only because no Ballerina change landed directly below an existing finding. The [earlier result](archive/results-scan-0.11.0.md) that alert identity survives a line shift holds only when the surrounding text moves with the finding.

## Detection limits found while writing the samples

`bal scan` 0.12.0 only flags some shapes of each vulnerability, so the samples are written in those shapes:

| Rule | Fires on | Does not fire on |
|---|---|---|
| `http:3` | A user-controlled path segment in resource-access syntax: `client->/hooks/[target]` | A user-controlled base URL passed to `new http:Client(url)`, or a path passed to `client->get(path)` |
| `crypto:2` | `crypto:hashBcrypt` with a low work factor | `crypto:hashSha256` or `crypto:hashMd5` applied to a password |
| `io:1` | The read assigned through `check`: `byte[] b = check io:fileReadBytes(root + name)` | The read returned directly: `return io:fileReadBytes(root + name)` |
| `file:1` | A path built from `os:getEnv("TMP")` | `file:createTempDir`, `file:createTemp`, or a literal `/tmp` path |
| `os:1` | `args` or an element such as `args[0]` passed to `os:exec` | `args` passed through a spread (`[...args]`) or `args.slice(n)` |
| `os:1`, `os:2` | Command-line arguments to `main` | HTTP request input (see the [archive](archive/results-scan-0.11.0.md)) |

## Recommendations for the scan tool and the action

1. **Emit `security-severity` per rule.** This is the one change that puts Ballerina alerts on the same footing as CodeQL in the Security tab and in the default check threshold.
2. **Emit `rule.name`.** Alerts are titled by rule id today.
3. **Emit `partialFingerprints`** from the syntax tree rather than relying on the line-text hash, so unrelated edits nearby do not churn alerts.
4. **Widen the source and sink models** for `http:3`, `crypto:2`, `io:1`, `file:1` and `os:1` to the shapes above.
5. **`scan-ballerina`:** document that `annotations` is redundant alongside `github-code-scanning`. Consider a diff-scoped gate, or reading the code scanning check, instead of counting all findings.

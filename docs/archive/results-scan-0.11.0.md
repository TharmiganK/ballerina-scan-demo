# Verification results

What `bal scan` SARIF actually does once GitHub has it. Run on 3 September 2026 against this repository.

**Environment:** Ballerina 2201.13.5 · scan tool 0.11.0 · `github/codeql-action/upload-sarif@v3` · public repository · same-repo PR branch.

**Scan output:** 32 findings — 19 SARIF `warning` (all 15 security rules) and 13 `note` (language rules).

## Summary

| # | Question | Result |
|---|---|---|
| 1 | Does GitHub accept the SARIF? | **Yes.** 32 results, 19 rules ingested, tool shown as "Ballerina Scan Tool" |
| 2 | Do alerts appear? | **Yes.** All 32, one alert per finding, no collapsing |
| 3 | Are they security-classified? | **No.** `security_severity_level` is `null` for all 32 |
| 4 | Can they be filtered by CWE? | **No.** `rule.tags` is `[]` for all 32 |
| 5 | Do PR annotations appear? | **Yes.** On changed lines only, correctly diff-scoped |
| 6 | Does the code scanning check fail the PR? | **No.** `conclusion: success` with "2 new alerts" |
| 7 | Does alert identity survive a line shift? | **Yes — stable.** See below |

## The finding that overturned an assumption

We had documented that our SARIF omits `partialFingerprints`, and therefore that *"inserting a line above a finding closes the old alert and opens a new one"*.

**That is wrong for the GitHub Actions path.** The `upload-sarif` action generates fingerprints when they are absent. Retrieving the analysis as GitHub stored it:

```
GET /code-scanning/analyses/{id}   Accept: application/sarif+json

"partialFingerprints": { "primaryLocationLineHash": "7e3d7154e81af866:1" }
```

The action also injects `automationDetails` and `versionControlProvenance`, neither of which we emit.

Tested directly by inserting 12 blank lines above four findings and re-scanning:

| Alert | Rule | Line before | Line after | Number | `created_at` |
|---|---|---|---|---|---|
| #29 | `ballerina/http:1` | 6 | 18 | unchanged | unchanged |
| #30 | `ballerina/http:2` | 14 | 26 | unchanged | unchanged |
| #31 | `ballerina/http:3` | 27 | 39 | unchanged | unchanged |
| #32 | `ballerina/http:4` | 37 | 49 | unchanged | unchanged |

Alert count stayed at 32, all `open`. No churn.

**Caveat:** this holds for the `upload-sarif` action. The REST API does not generate fingerprints, so a pipeline that posts SARIF directly — Jenkins, Azure DevOps — may behave differently. Untested here.

## The gate: two different checks

A PR adding one new security finding produced two check runs:

| Check | Conclusion | Meaning |
|---|---|---|
| `Ballerina Scan Tool` (GitHub code scanning) | **success** — "2 new alerts" | GitHub's default threshold does not fail on `warning` |
| `scan` (this workflow) | **failure** | Our own gate step, counting `level == "warning"` |

This is the concrete evidence for the guidance that the gate belongs in the workflow rather than relying on GitHub's default. Nothing `bal scan` emits reaches `error`, so a check keyed on error severity never fires.

## Annotations

```
crypto_rules.bal:24  warning  Avoid using fast hashing algorithms
crypto_rules.bal:23  notice   Non isolated public function
```

Only the two findings on changed lines were annotated; the 30 pre-existing findings elsewhere in the package were not. SARIF `warning` maps to GitHub `warning`, `note` maps to `notice`.

## Other observations

- **`rule.name` is empty** in every alert, because the SARIF omits it. GitHub falls back to the rule id, so alert titles read `ballerina/http:4` rather than a readable name.
- **`--format=sarif` writes only the SARIF.** It does not also produce `scan_results.json`, so a workflow needing both must run `bal scan` twice. The gate step here parses the SARIF for that reason.
- **`bal scan` always exits 0**, including when it produces nothing. An empty result set uploads cleanly and GitHub reads it as "every alert fixed" — indistinguishable from a genuine regression. The workflow asserts a non-empty result set before uploading.
- **`$schema`** points at `schemastore.org` rather than the OASIS SARIF 2.1.0 URI. GitHub did not object.
- **The published noncompliant example for `ballerina/os:1` and `ballerina/os:2` does not trigger those rules.** The documented example feeds HTTP request input (`req.getQueryParamValue(...)`) into `os:exec` / `os:setEnv`. Neither that, nor a resource path parameter, nor a query parameter, nor `os:getEnv` output triggers them. Both rules fire only on **command-line arguments to `main`**. Five variants were tested before finding the working shape.

## GA preview: the same findings with the metadata the tool will emit

`scripts/enrich_sarif.py` adds to a copy of the report what the scan tool is expected to emit at GA — severity, `security-severity`, CWE and OWASP tags, rule names and remediation text — and the workflow uploads it under its own category. The scan is identical; only the SARIF metadata differs.

### What GitHub does with it

| | Raw | GA preview |
|---|---|---|
| Alerts | 32 | 32 |
| `security_severity_level: critical` | 0 | 1 |
| `security_severity_level: high` | 0 | 8 |
| `security_severity_level: medium` | 0 | 10 |
| No security severity | 32 | 13 (the maintainability rules) |
| Alerts carrying tags | 0 | 21 |
| `severity: error` | 0 | 9 |
| Rule name shown | *(empty — falls back to the rule id)* | e.g. "Command argument injection" |

### The consequence that matters

Both SARIFs were uploaded from the same workflow run on the same pull request commit. The two check runs:

| Check | Conclusion | Title |
|---|---|---|
| `Ballerina Scan Tool` | **success** | 2 new alerts |
| `Ballerina Scan Tool (GA preview)` | **failure** | 2 new alerts including 1 high severity security vulnerability |

Identical findings, identical code, identical GitHub settings. The only variable is SARIF metadata, and it is the difference between a pull request that passes and one that is blocked.

That is the whole argument for emitting severity and CWE metadata from the tool, in one line of evidence.

### Alerts cannot be compared side by side in one repository

Uploading the enriched SARIF under a different `category` **and** a different tool name did not create a second set of alerts. GitHub matched the enriched results to the existing alerts by rule id, location and fingerprint, and updated them in place: alerts #29–32 kept their numbers and their original `created_at`, but their tool became `Ballerina Scan Tool (GA preview)` and their category `bal-scan-ga-preview`.

Two things follow. A before/after comparison has to be sequential, captured from the API between uploads, rather than parallel. And alert identity survived a tool rename, a category change and a wholesale metadata rewrite — further evidence of how stable identity is once fingerprints exist.

## Untested

- Packages **not** at the repository root. SARIF `artifactLocation.uri` is relative to the *package* root, so a package in a subdirectory would emit URIs that do not resolve against the repo — which could break both annotations and fingerprint generation. This repository has the package at the root, the favourable case.
- The direct REST API upload path.
- Fork pull requests, which have restricted permissions for `security-events: write`.

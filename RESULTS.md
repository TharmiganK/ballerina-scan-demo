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

## Untested

- Packages **not** at the repository root. SARIF `artifactLocation.uri` is relative to the *package* root, so a package in a subdirectory would emit URIs that do not resolve against the repo — which could break both annotations and fingerprint generation. This repository has the package at the root, the favourable case.
- The direct REST API upload path.
- Fork pull requests, which have restricted permissions for `security-events: write`.

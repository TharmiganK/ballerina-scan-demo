#!/usr/bin/env python3
"""
Preview of the SARIF `bal scan` is expected to emit at GA.

The scan tool currently emits a minimal SARIF: no severity, no CWE, no OWASP
category, no rule name, no remediation text. This script adds that metadata to
an existing report so the GitHub experience at GA can be seen today.

It is a stand-in, not a proposal for how the tool should work. At GA this data
comes from the rule model itself (GA plan items 1.1 and 1.4) rather than from a
lookup table maintained alongside the tool.

Usage: enrich_sarif.py <input.sarif> <output.sarif>
"""
import json
import sys

# rule id -> (severity, [CWE], OWASP category, rule name)
#
# CWE and OWASP values are the published mapping from ballerina.io/learn/scan-rules.
# Severities are indicative, for preview purposes only.
RULES = {
    "ballerina/crypto:1": ("HIGH",   [327, 780], "A04", "Insecure cipher mode or padding scheme"),
    "ballerina/crypto:2": ("HIGH",   [916, 327], "A04", "Password hashed with a fast algorithm"),
    "ballerina/crypto:3": ("HIGH",   [329],      "A04", "Counter-mode initialization vector reused"),
    "ballerina/file:1":   ("MEDIUM", [377, 379], "A01", "File operation in a publicly writable directory"),
    "ballerina/file:2":   ("HIGH",   [22],       "A01", "Path injection in a file operation"),
    "ballerina/http:1":   ("MEDIUM", [352],      "A01", "Default resource accessor allows unsafe methods"),
    "ballerina/http:2":   ("MEDIUM", [942],      "A02", "Permissive Cross-Origin Resource Sharing"),
    "ballerina/http:3":   ("HIGH",   [918],      "A01", "Server-side request forgery"),
    "ballerina/http:4":   ("MEDIUM", [601],      "A01", "Open redirect through the Location header"),
    "ballerina/io:1":     ("HIGH",   [22],       "A01", "Path injection in an I/O operation"),
    "ballerina/log:1":    ("MEDIUM", [532],      "A09", "Sensitive configurable value written to the log"),
    "ballerina/os:1":     ("BLOCKER",[78, 88],   "A05", "Command argument injection"),
    "ballerina/os:2":     ("MEDIUM", [88, 454],  "A05", "Environment variable injection"),
    "ballerina/jwt:1":    ("HIGH",   [327, 347], "A04", "Weak algorithm signing a JWT"),
    "ballerina/email:1":  ("MEDIUM", [297, 295], "A07", "TLS hostname verification disabled"),
    # Language rules that map to A10 Mishandling of Exceptional Conditions
    "ballerina:1":        ("MEDIUM", [248, 636], "A10", "Avoid checkpanic"),
    "ballerina:7":        ("LOW",    [571],      "A10", "Operation always evaluates to true"),
    "ballerina:8":        ("LOW",    [570],      "A10", "Operation always evaluates to false"),
    "ballerina:9":        ("LOW",    [1023],     "A10", "Operation always evaluates to the same value"),
    "ballerina:10":       ("LOW",    [1164],     "A10", "Variable assigned to itself"),
    "ballerina:12":       ("LOW",    [606],      "A10", "Invalid range expression"),
}

# GitHub reads security-severity as CVSS-like: >9.0 critical, 7.0-8.9 high,
# 4.0-6.9 medium, 0.1-3.9 low. SARIF level drives the check conclusion.
SEVERITY = {
    "BLOCKER": ("9.3", "error"),
    "HIGH":    ("7.7", "error"),
    "MEDIUM":  ("5.5", "warning"),
    "LOW":     ("3.0", "note"),
}

OWASP = {
    "A01": "Broken Access Control",
    "A02": "Security Misconfiguration",
    "A04": "Cryptographic Failures",
    "A05": "Injection",
    "A07": "Authentication Failures",
    "A09": "Security Logging and Alerting Failures",
    "A10": "Mishandling of Exceptional Conditions",
}


def main(src, dst):
    with open(src) as f:
        sarif = json.load(f)

    run = sarif["runs"][0]
    run["tool"]["driver"]["name"] = "Ballerina Scan Tool (GA preview)"

    levels = {}
    enriched = 0

    for rule in run["tool"]["driver"].get("rules", []):
        meta = RULES.get(rule["id"])
        if not meta:
            continue
        severity, cwes, owasp, name = meta
        score, level = SEVERITY[severity]
        is_security = rule["id"].startswith("ballerina/")

        rule["name"] = name
        rule.setdefault("shortDescription", {})
        rule["fullDescription"] = {
            "text": "%s. %s (%s), %s." % (
                rule["shortDescription"]["text"],
                ", ".join("CWE-%d" % c for c in cwes),
                owasp + " " + OWASP[owasp],
                "severity " + severity.lower(),
            )
        }
        rule["help"] = {
            "text": "See %s" % rule.get("helpUri", ""),
            "markdown": "**%s**\n\n%s\n\n- Weakness: %s\n- OWASP Top 10:2025: %s %s\n- Severity: %s\n\n[Rule documentation](%s)" % (
                name,
                rule["shortDescription"]["text"],
                ", ".join("[CWE-%d](https://cwe.mitre.org/data/definitions/%d.html)" % (c, c) for c in cwes),
                owasp, OWASP[owasp], severity,
                rule.get("helpUri", ""),
            ),
        }

        tags = ["external/cwe/cwe-%d" % c for c in cwes]
        tags.append("external/owasp/%s-2025" % owasp.lower())
        props = rule.setdefault("properties", {})
        if is_security:
            tags.insert(0, "security")
            props["security-severity"] = score
        else:
            props["problem.severity"] = "warning" if level == "error" else "recommendation"
        props["tags"] = tags
        props["precision"] = "high"

        rule.setdefault("defaultConfiguration", {})["level"] = level
        levels[rule["id"]] = level
        enriched += 1

    for result in run.get("results", []):
        if result["ruleId"] in levels:
            result["level"] = levels[result["ruleId"]]

    with open(dst, "w") as f:
        json.dump(sarif, f, indent=2)

    print("enriched %d of %d rules; %d results relevelled"
          % (enriched, len(run["tool"]["driver"].get("rules", [])), len(run.get("results", []))))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])

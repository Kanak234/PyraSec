"""SARIF 2.1.0 output.

SARIF is what makes PyraSec a DevSecOps tool rather than a standalone one.
Upload the file with `github/codeql-action/upload-sarif` and every finding
appears as an annotation on the pull request diff, in the Security tab, and in
the branch-protection gate — no bespoke GitHub App required.

The ``partialFingerprints`` field is what stops a finding from being reported
as new every time a line moves; GitHub uses it to track a finding across
commits so a developer sees "1 new" instead of "47 findings" on every push.
"""

from __future__ import annotations

from ..core.models import SARIF_LEVEL, ScanResult, Severity
from ..rules.base import all_rules

SARIF_VERSION = "2.1.0"
SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spectool/main/schemas/sarif-schema-2.1.0.json"


def build_sarif(result: ScanResult, tool_version: str = "1.0.0") -> dict:
    fired = {f.rule_id for f in result.findings}
    rules = [r for r in all_rules() if r.id in fired]

    return {
        "$schema": SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "PyraSec",
                        "version": tool_version,
                        "organization": "CipherStack",
                        "informationUri": "https://github.com/Kanak234",
                        "semanticVersion": tool_version,
                        "rules": [_rule_descriptor(r) for r in rules],
                    }
                },
                "automationDetails": {"id": f"pyrasec/{result.profile}"},
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": result.started_at,
                        "workingDirectory": {"uri": _uri(result.root)},
                        "toolExecutionNotifications": [
                            {"level": "warning", "message": {"text": error}}
                            for error in result.stats.errors[:20]
                        ],
                    }
                ],
                "properties": {
                    "securityScore": result.score,
                    "grade": result.grade,
                    "filesScanned": result.stats.files_scanned,
                    "durationSeconds": result.stats.duration_seconds,
                },
                "results": [_result(f) for f in result.sorted_findings()],
            }
        ],
    }


def _rule_descriptor(rule) -> dict:
    tags = list(rule.tags)
    if rule.cwe:
        tags.append(rule.cwe.split()[0])
    if rule.owasp:
        tags.append(rule.owasp.split(":")[0])
    tags.append("security")

    descriptor = {
        "id": rule.id,
        "name": _pascal(rule.title),
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.description},
        "help": {
            "text": _help_text(rule),
            "markdown": _help_markdown(rule),
        },
        "defaultConfiguration": {"level": SARIF_LEVEL[rule.severity]},
        "properties": {
            "tags": sorted(set(tags)),
            "precision": _precision(rule.confidence),
            "problem.severity": _problem_severity(rule.severity),
            "security-severity": str(rule.cvss if rule.cvss is not None else rule.severity.cvss_base),
        },
    }
    if rule.remediation.references:
        descriptor["helpUri"] = rule.remediation.references[0]
    return descriptor


def _result(finding) -> dict:
    region: dict = {}
    if finding.line:
        region["startLine"] = finding.line
        if finding.column:
            region["startColumn"] = finding.column
    if finding.evidence:
        region["snippet"] = {"text": finding.evidence}

    location = {
        "physicalLocation": {
            "artifactLocation": {"uri": finding.path, "uriBaseId": "%SRCROOT%"},
        }
    }
    if region:
        location["physicalLocation"]["region"] = region

    return {
        "ruleId": finding.rule_id,
        "level": SARIF_LEVEL[finding.severity],
        "message": {"text": f"{finding.title}: {finding.description}"},
        "locations": [location],
        "partialFingerprints": {"pyrasec/v1": finding.fingerprint},
        "properties": {
            "severity": finding.severity.value,
            "confidence": finding.confidence,
            "cvss": finding.effective_cvss,
            "cwe": finding.cwe,
            "owasp": finding.owasp,
            "mitre": finding.mitre,
            "remediation": finding.remediation.summary,
        },
    }


def _help_text(rule) -> str:
    lines = [rule.description, "", rule.remediation.summary]
    lines.extend(f"- {step}" for step in rule.remediation.steps)
    return "\n".join(lines)


def _help_markdown(rule) -> str:
    parts = [f"## {rule.title}", "", rule.description, "", f"**Fix:** {rule.remediation.summary}", ""]
    if rule.remediation.steps:
        parts.extend(f"{i}. {step}" for i, step in enumerate(rule.remediation.steps, 1))
    if rule.remediation.example:
        parts += ["", "```", rule.remediation.example.rstrip(), "```"]
    if rule.cwe:
        parts += ["", f"**{rule.cwe}**"]
    if rule.owasp:
        parts += [f"**{rule.owasp}**"]
    return "\n".join(parts)


def _precision(confidence: float) -> str:
    if confidence >= 0.9:
        return "very-high"
    if confidence >= 0.7:
        return "high"
    if confidence >= 0.5:
        return "medium"
    return "low"


def _problem_severity(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "recommendation",
        Severity.INFO: "recommendation",
    }[severity]


def _pascal(text: str) -> str:
    return "".join(word.capitalize() for word in text.replace("-", " ").replace("/", " ").split())


def _uri(path: str) -> str:
    return f"file://{path}" if path.startswith("/") else path

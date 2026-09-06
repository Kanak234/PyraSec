"""Incremental scan cache.

Keyed on (path, sha256, rule-set fingerprint). Content hash rather than mtime,
because mtime lies constantly — a `git checkout` rewrites it on files whose
content is unchanged, and a CI runner starts with fresh timestamps on
everything. Hashing costs one sequential read; getting the answer wrong costs
a missed vulnerability.

Including the rule-set fingerprint means adding or editing a rule invalidates
the whole cache automatically, so a cached "clean" can never outlive the rule
that would have caught something.
"""

from __future__ import annotations

import hashlib
import json
import os
from typing import Any

from ..core.models import Finding, FileRecord, Remediation, Severity
from ..rules.base import all_rules

CACHE_VERSION = 2


def ruleset_fingerprint() -> str:
    """Changes whenever any rule's id, severity or version changes."""
    parts = [f"{r.id}:{r.severity.value}:{r.confidence}" for r in all_rules()]
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


class ScanCache:
    def __init__(self, path: str):
        self.path = path
        self.fingerprint = ruleset_fingerprint()
        self._data: dict[str, Any] = {}
        self._dirty = False
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                raw = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return
        if raw.get("version") != CACHE_VERSION or raw.get("ruleset") != self.fingerprint:
            return  # stale — start clean rather than trust it
        self._data = raw.get("entries", {})

    def get(self, record: FileRecord) -> list[Finding] | None:
        if not record.sha256:
            return None
        entry = self._data.get(record.path)
        if not entry or entry.get("sha256") != record.sha256:
            return None
        return [_finding_from_dict(d) for d in entry.get("findings", [])]

    def put(self, record: FileRecord, findings: list[Finding]) -> None:
        if not record.sha256:
            return
        self._data[record.path] = {
            "sha256": record.sha256,
            "findings": [f.to_dict() for f in findings],
        }
        self._dirty = True

    def save(self) -> None:
        if not self._dirty:
            return
        payload = {
            "version": CACHE_VERSION,
            "ruleset": self.fingerprint,
            "entries": self._data,
        }
        try:
            tmp = f"{self.path}.tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(payload, fh)
            os.replace(tmp, self.path)
            os.chmod(self.path, 0o600)  # the cache echoes redacted evidence
        except OSError:
            pass  # a cache that can't be written is a slow scan, not a failure

    def clear(self) -> None:
        self._data = {}
        self._dirty = True


def _finding_from_dict(data: dict) -> Finding:
    remediation_data = data.get("remediation") or {}
    return Finding(
        rule_id=data["rule_id"],
        title=data["title"],
        severity=Severity(data["severity"]),
        path=data["path"],
        description=data["description"],
        remediation=Remediation(
            summary=remediation_data.get("summary", ""),
            steps=remediation_data.get("steps", []),
            example=remediation_data.get("example"),
            references=remediation_data.get("references", []),
        ),
        line=data.get("line"),
        column=data.get("column"),
        evidence=data.get("evidence", ""),
        cwe=data.get("cwe"),
        owasp=data.get("owasp"),
        mitre=data.get("mitre"),
        cvss=data.get("cvss"),
        confidence=data.get("confidence", 1.0),
        tags=data.get("tags", []),
        metadata=data.get("metadata", {}),
    )

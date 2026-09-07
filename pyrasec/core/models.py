"""Core data model for PyraSec.

Everything the engine produces is one of these frozen-ish dataclasses, so the
scanner, the scorer, the visualiser and every report writer all speak the same
language. No AI, no heuristics that can't be explained: a Finding always knows
which rule produced it and why.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Ordered severity ladder. Weights drive the deterministic score."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> float:
        return _SEVERITY_WEIGHT[self]

    @property
    def rank(self) -> int:
        """0 = worst. Useful for ``min()`` when folding a folder's findings."""
        return _SEVERITY_RANK[self]

    @property
    def band(self) -> str:
        """Pyramid colour band from the pitch deck: critical / warning / secure."""
        if self in (Severity.CRITICAL, Severity.HIGH):
            return "critical"
        if self in (Severity.MEDIUM, Severity.LOW):
            return "warning"
        return "secure"

    @property
    def cvss_base(self) -> float:
        """Representative CVSS v3.1 base score for the band.

        This is a band midpoint, not a per-vulnerability vector calculation.
        Rules that know their real vector should set ``Finding.cvss`` directly.
        """
        return _SEVERITY_CVSS[self]

    @classmethod
    def worst(cls, severities: Iterable[Severity]) -> Severity:
        items = list(severities)
        if not items:
            return cls.INFO
        return min(items, key=lambda s: s.rank)


_SEVERITY_WEIGHT = {
    Severity.CRITICAL: 10.0,
    Severity.HIGH: 6.0,
    Severity.MEDIUM: 3.0,
    Severity.LOW: 1.0,
    Severity.INFO: 0.0,
}

_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

_SEVERITY_CVSS = {
    Severity.CRITICAL: 9.3,
    Severity.HIGH: 7.5,
    Severity.MEDIUM: 5.3,
    Severity.LOW: 3.1,
    Severity.INFO: 0.0,
}

# SARIF only understands four levels.
SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


@dataclass
class Remediation:
    """Deterministic fix guidance attached to a rule.

    ``summary`` is one line for the tooltip in the 3D view, ``steps`` is what a
    developer actually does, and ``example`` is a copy-pasteable snippet.
    """

    summary: str
    steps: list[str] = field(default_factory=list)
    example: str | None = None
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class Finding:
    """One rule firing on one location."""

    rule_id: str
    title: str
    severity: Severity
    path: str  # POSIX-style, relative to scan root
    description: str
    remediation: Remediation
    line: int | None = None
    column: int | None = None
    evidence: str = ""  # already redacted by the rule
    cwe: str | None = None
    owasp: str | None = None
    mitre: str | None = None
    cvss: float | None = None
    confidence: float = 1.0  # 0.0-1.0, multiplies the score penalty
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        """Stable ID across runs so a finding can be suppressed or diffed.

        Deliberately excludes the line number: adding an import above a
        hardcoded key should not resurrect a triaged finding.
        """
        raw = f"{self.rule_id}|{self.path}|{self.evidence}"
        return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]

    @property
    def penalty(self) -> float:
        return self.severity.weight * self.confidence

    @property
    def effective_cvss(self) -> float:
        return self.cvss if self.cvss is not None else self.severity.cvss_base

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        d["fingerprint"] = self.fingerprint
        d["cvss"] = self.effective_cvss
        d["band"] = self.severity.band
        return d


@dataclass
class FileRecord:
    """What the walker learned about one file, before any rule runs."""

    path: str  # relative, POSIX
    abs_path: str
    size: int
    mode: int  # st_mode & 0o777
    depth: int
    is_dir: bool = False
    is_symlink: bool = False
    is_binary: bool = False
    mtime: float = 0.0
    sha256: str = ""
    extension: str = ""
    owner_uid: int = -1

    @property
    def name(self) -> str:
        return self.path.rsplit("/", 1)[-1]

    @property
    def parent(self) -> str:
        return self.path.rsplit("/", 1)[0] if "/" in self.path else ""

    @property
    def mode_octal(self) -> str:
        return format(self.mode, "04o")


@dataclass
class ScanStats:
    files_scanned: int = 0
    files_skipped: int = 0
    dirs_scanned: int = 0
    bytes_read: int = 0
    rules_executed: int = 0
    cache_hits: int = 0
    duration_seconds: float = 0.0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """Everything one scan produced. This is the object every report renders."""

    root: str
    findings: list[Finding] = field(default_factory=list)
    files: list[FileRecord] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    started_at: str = ""
    scanner_version: str = ""
    profile: str = "default"

    # Filled in by engine.scoring so reports don't each recompute it.
    score: float = 100.0
    grade: str = "A+"

    def by_severity(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def by_rule(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.rule_id] = counts.get(f.rule_id, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))

    def findings_for(self, path: str) -> list[Finding]:
        return [f for f in self.findings if f.path == path]

    def sorted_findings(self) -> list[Finding]:
        """Deterministic order: worst first, then path, then line, then rule."""
        return sorted(
            self.findings,
            key=lambda f: (f.severity.rank, f.path, f.line or 0, f.rule_id),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema": "pyrasec.scan/1",
            "scanner_version": self.scanner_version,
            "root": self.root,
            "profile": self.profile,
            "started_at": self.started_at,
            "score": self.score,
            "grade": self.grade,
            "summary": {
                "total_findings": len(self.findings),
                "by_severity": self.by_severity(),
                "by_rule": self.by_rule(),
            },
            "stats": self.stats.to_dict(),
            "findings": [f.to_dict() for f in self.sorted_findings()],
        }


# --------------------------------------------------------------------------
# Redaction helpers — a security scanner must never be the thing that leaks
# the secret. Reports, logs and the 3D tooltip all get the masked form.
# --------------------------------------------------------------------------

_WS = re.compile(r"\s+")


def redact(secret: str, keep: int = 4) -> str:
    """Mask a secret, keeping a short prefix so a human can recognise it."""
    secret = secret.strip()
    if len(secret) <= keep:
        return "*" * len(secret)
    return f"{secret[:keep]}{'*' * min(len(secret) - keep, 24)}"


def snippet(line: str, limit: int = 160) -> str:
    """Collapse whitespace and truncate a source line for display."""
    text = _WS.sub(" ", line).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


# Central scrubbing. Applied by Rule.finding() to every piece of evidence and
# context before it reaches a report, so an individual rule cannot leak a
# credential by forgetting to redact. Defence in depth: the rules still redact
# at the point of detection, and this catches whatever they missed.

_SCRUB_ASSIGNMENT = re.compile(
    r"""(?ix)
    \b(?P<key>[A-Za-z0-9_.\-]*
        (?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|
           private[_-]?key|credential|passphrase|signing[_-]?key))
    (?P<sep>\s*[:=]{1,2}\s*)
    (?P<quote>['"]?)(?P<value>[^'"\s,;)}\]]{6,})(?P=quote)
    """
)

_SCRUB_TOKENS = [
    re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{10,}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"),
    re.compile(r"\bGOCSPX-[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\bSG\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    re.compile(r"\bnpm_[A-Za-z0-9]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{5,}\b"),
]

_SCRUB_URL_AUTH = re.compile(r"(?P<scheme>[a-z][a-z0-9+.\-]*://)(?P<user>[^:/\s'\"@]+):(?P<pw>[^@\s'\"]{2,})@")

_ALREADY_MASKED = re.compile(r"\*{4,}")


def scrub(text: str) -> str:
    """Remove credential-shaped substrings from any display string.

    Idempotent: values already masked with asterisks pass through unchanged.
    """
    if not text:
        return text

    def _mask_assignment(match: re.Match[str]) -> str:
        value = match.group("value")
        if _ALREADY_MASKED.search(value):
            return match.group(0)
        quote = match.group("quote")
        return f"{match.group('key')}{match.group('sep')}{quote}{redact(value)}{quote}"

    text = _SCRUB_ASSIGNMENT.sub(_mask_assignment, text)
    text = _SCRUB_URL_AUTH.sub(
        lambda m: f"{m.group('scheme')}{m.group('user')}:{'*' * 8}@", text
    )
    for pattern in _SCRUB_TOKENS:
        text = pattern.sub(lambda m: redact(m.group(0), keep=6), text)
    return text

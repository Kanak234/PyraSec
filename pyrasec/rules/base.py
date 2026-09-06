"""Rule framework.

Three kinds of rule, three different inputs:

* ``PathRule``    — sees only FileRecord metadata (name, extension, mode).
                    Cheap: runs on every file including binaries.
* ``ContentRule`` — sees the decoded text of a file. Runs once per text file;
                    the scanner reads each file exactly once and fans it out
                    to every interested ContentRule.
* ``ProjectRule`` — sees the whole file list at once. For things that are
                    defined by absence (no .gitignore) or by relationships
                    (a .env sitting inside a public/ folder).

A rule is a pure function of its input. Same tree in, same findings out,
every time — no model, no network call, no randomness. That property is the
whole reason findings can be cached, diffed and merge-blocked on.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable, Iterator, Sequence

from ..core.models import FileRecord, Finding, Remediation, Severity

# --------------------------------------------------------------------------
# Registry
# --------------------------------------------------------------------------

_REGISTRY: dict[str, "Rule"] = {}


def register(rule: "Rule") -> "Rule":
    if rule.id in _REGISTRY:
        raise ValueError(f"duplicate rule id: {rule.id}")
    _REGISTRY[rule.id] = rule
    return rule


def all_rules() -> list["Rule"]:
    return sorted(_REGISTRY.values(), key=lambda r: r.id)


def get_rule(rule_id: str) -> "Rule | None":
    return _REGISTRY.get(rule_id)


def rules_for_profile(
    profile: str = "default",
    enabled: Sequence[str] | None = None,
    disabled: Sequence[str] | None = None,
) -> list["Rule"]:
    """Filter the registry.

    Profiles let a pre-commit hook run the fast subset while the nightly scan
    runs everything. ``enabled``/``disabled`` are explicit rule-id overrides.
    """
    rules = all_rules()
    if enabled:
        wanted = set(enabled)
        rules = [r for r in rules if r.id in wanted]
    if disabled:
        unwanted = set(disabled)
        rules = [r for r in rules if r.id not in unwanted]
    if profile == "fast":
        rules = [r for r in rules if r.fast]
    elif profile == "secrets":
        rules = [r for r in rules if "secret" in r.tags]
    return rules


# --------------------------------------------------------------------------
# Rule types
# --------------------------------------------------------------------------


@dataclass
class Rule:
    """Metadata shared by every rule kind."""

    id: str
    title: str
    severity: Severity
    description: str
    remediation: Remediation
    cwe: str | None = None
    owasp: str | None = None
    mitre: str | None = None
    cvss: float | None = None
    tags: list[str] = field(default_factory=list)
    fast: bool = True  # included in the pre-commit / "fast" profile
    confidence: float = 1.0

    def finding(
        self,
        path: str,
        *,
        line: int | None = None,
        column: int | None = None,
        evidence: str = "",
        description: str | None = None,
        severity: Severity | None = None,
        confidence: float | None = None,
        metadata: dict | None = None,
    ) -> Finding:
        """Build a Finding from this rule's metadata plus a location.

        Evidence and any ``context`` in metadata are scrubbed here, centrally.
        Rules redact at the point of detection too — this is the backstop that
        makes a forgotten redaction a non-event rather than a data leak.
        """
        safe_metadata = dict(metadata or {})
        for key in ("context", "line", "snippet", "value", "raw"):
            if isinstance(safe_metadata.get(key), str):
                safe_metadata[key] = scrub(safe_metadata[key])

        return Finding(
            rule_id=self.id,
            title=self.title,
            severity=severity or self.severity,
            path=path,
            description=scrub(description or self.description),
            remediation=self.remediation,
            line=line,
            column=column,
            evidence=scrub(evidence),
            cwe=self.cwe,
            owasp=self.owasp,
            mitre=self.mitre,
            cvss=self.cvss,
            confidence=self.confidence if confidence is None else confidence,
            tags=list(self.tags),
            metadata=safe_metadata,
        )


@dataclass
class PathRule(Rule):
    """Fires on file metadata alone."""

    check: Callable[[FileRecord], Iterable[Finding]] | None = None

    def run(self, record: FileRecord) -> list[Finding]:
        if self.check is None:
            return []
        return list(self.check(record))


@dataclass
class ContentRule(Rule):
    """Fires on file text. ``applies_to`` keeps it off files it can't help with."""

    check: Callable[[FileRecord, str], Iterable[Finding]] | None = None
    extensions: set[str] = field(default_factory=set)  # empty = all text files
    filenames: set[str] = field(default_factory=set)
    max_size: int = 2 * 1024 * 1024

    def applies_to(self, record: FileRecord) -> bool:
        if record.is_dir or record.is_binary or record.size > self.max_size:
            return False
        if self.filenames and record.name.lower() in self.filenames:
            return True
        if self.extensions and record.extension in self.extensions:
            return True
        return not self.extensions and not self.filenames

    def run(self, record: FileRecord, text: str) -> list[Finding]:
        if self.check is None:
            return []
        return list(self.check(record, text))


@dataclass
class ProjectRule(Rule):
    """Fires on the whole file list — for absent files and cross-file relations."""

    check: Callable[[list[FileRecord]], Iterable[Finding]] | None = None

    def run(self, records: list[FileRecord]) -> list[Finding]:
        if self.check is None:
            return []
        return list(self.check(records))


# --------------------------------------------------------------------------
# Helpers used by the concrete rule modules
# --------------------------------------------------------------------------


def iter_lines(text: str) -> Iterator[tuple[int, str]]:
    """1-indexed line iteration, matching what an editor shows."""
    for index, line in enumerate(text.splitlines(), start=1):
        yield index, line


def is_comment(line: str) -> bool:
    stripped = line.lstrip()
    return stripped.startswith(("#", "//", "*", "/*", "--", ";"))


def in_test_path(path: str) -> bool:
    """Test fixtures legitimately contain fake credentials. Lower confidence."""
    lowered = path.lower()
    markers = ("test", "spec", "fixture", "mock", "sample", "example", "__tests__", "e2e")
    return any(m in lowered for m in markers)

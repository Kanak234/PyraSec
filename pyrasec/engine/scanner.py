"""Scan orchestration.

Reads every file exactly once and fans the text out to every interested
ContentRule. That single decision is most of the performance story — a naive
implementation that lets each rule open the file turns a 30-rule scan into
30 passes over the disk.

Parallelism uses threads, not processes: the workload is dominated by file I/O
and regex matching, both of which release or sidestep the GIL enough that
threads win without paying pickling costs. Findings are sorted at the end, so
output is byte-identical regardless of worker count — which is what makes the
results cacheable and diffable.
"""

from __future__ import annotations

import concurrent.futures
import re
import time
from datetime import datetime, timezone
from pathlib import Path

from ..core.models import FileRecord, Finding, ScanResult, ScanStats
from ..core.walker import WalkConfig, Walker, read_text
from ..rules import base as rulebase
from ..rules import (  # noqa: F401  (import registers the rules)
    containers, dependencies, filesystem, gitops, iac, secrets, webserver,
)
from .cache import ScanCache
from .scoring import compute_score

VERSION = "1.0.0"

# NOTE: the body of _parse_suppression was lost in recovery — only its call
# site survived. Reconstructed from the syntax documented in README.md and the
# contract of _apply_suppressions below. Behaviour is pinned by TestSuppression
# in tests/test_pyrasec.py.
_SUPPRESSION_RE = re.compile(
    r"pyrasec:ignore(?P<scope>-next-line|-file)?"
    r"(?P<ids>(?:[ \t,]+[A-Z][A-Z0-9]*[0-9]{3})+)"
)
_RULE_ID_RE = re.compile(r"[A-Z][A-Z0-9]*[0-9]{3}")
_SCOPE_KIND = {None: "line", "-next-line": "next", "-file": "file"}


def _parse_suppression(line: str) -> tuple[str, set[str]] | None:
    """Read one line for a ``pyrasec:ignore`` marker.

    Returns ``(kind, rule_ids)`` where kind is ``"line"``, ``"next"`` or
    ``"file"``, or ``None`` when the line carries no usable marker.

    A bare ``# pyrasec:ignore`` carrying no rule id returns None deliberately:
    a blanket suppression is how a scanner quietly stops working.
    """
    match = _SUPPRESSION_RE.search(line)
    if match is None:
        return None
    rule_ids = set(_RULE_ID_RE.findall(match.group("ids")))
    if not rule_ids:
        return None
    return _SCOPE_KIND[match.group("scope")], rule_ids


class Scanner:
    """Runs the full Scan → Detect pipeline over one directory tree."""

    def __init__(
        self,
        root: str,
        *,
        profile: str = "default",
        enabled_rules: list[str] | None = None,
        disabled_rules: list[str] | None = None,
        walk_config: WalkConfig | None = None,
        workers: int = 8,
        use_cache: bool = True,
        cache_path: str | None = None,
    ):
        self.root = str(Path(root).resolve())
        self.profile = profile
        self.walk_config = walk_config or WalkConfig()
        self.workers = max(1, workers)
        self.rules = rulebase.rules_for_profile(profile, enabled_rules, disabled_rules)
        self.cache = ScanCache(cache_path or f"{self.root}/.pyrasec-cache.json") if use_cache else None

        self._path_rules = [r for r in self.rules if isinstance(r, rulebase.PathRule) and r.check]
        self._content_rules = [r for r in self.rules if isinstance(r, rulebase.ContentRule) and r.check]
        self._project_rules = [r for r in self.rules if isinstance(r, rulebase.ProjectRule) and r.check]

    # -- public ------------------------------------------------------------

    def scan(self) -> ScanResult:
        started = time.perf_counter()
        stats = ScanStats()

        walker = Walker(self.root, self.walk_config)
        records = walker.walk()
        stats.errors.extend(walker.errors)
        stats.files_skipped = walker.skipped
        stats.dirs_scanned = sum(1 for r in records if r.is_dir)
        stats.files_scanned = sum(1 for r in records if not r.is_dir)

        findings: list[Finding] = []

        # 1. Path rules — cheap, run inline over every record.
        for record in records:
            for rule in self._path_rules:
                findings.extend(rule.run(record))
        stats.rules_executed += len(self._path_rules) * len(records)

        # 2. Content rules — one read per file, fanned out to interested rules.
        content_findings, read_bytes, hits = self._run_content_rules(records, stats)
        findings.extend(content_findings)
        stats.bytes_read = read_bytes
        stats.cache_hits = hits

        # 3. Project rules — need the whole picture.
        for rule in self._project_rules:
            try:
                findings.extend(rule.run(records))
            except Exception as exc:  # a broken rule must not kill the scan
                stats.errors.append(f"rule {rule.id}: {exc}")
        stats.rules_executed += len(self._project_rules)

        # 4. Cross-cutting checks that need both records and findings.
        findings.extend(self._check_lockfiles(records))

        # 5. Honour inline suppressions.
        findings, suppressed = self._apply_suppressions(findings, records)
        if suppressed:
            stats.errors.append(f"{suppressed} finding(s) suppressed by inline comments")

        if self.cache:
            self.cache.save()

        result = ScanResult(
            root=self.root,
            findings=self._dedupe(findings),
            files=records,
            stats=stats,
            started_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            scanner_version=VERSION,
            profile=self.profile,
        )
        stats.duration_seconds = round(time.perf_counter() - started, 3)

        breakdown = compute_score(result.findings, stats.files_scanned)
        result.score = breakdown.score
        result.grade = breakdown.grade
        return result

    # -- internals ---------------------------------------------------------

    def _run_content_rules(
        self, records: list[FileRecord], stats: ScanStats
    ) -> tuple[list[Finding], int, int]:
        targets = [
            r for r in records
            if not r.is_dir and not r.is_binary and not r.is_symlink
            and any(rule.applies_to(r) for rule in self._content_rules)
        ]
        if not targets:
            return [], 0, 0

        findings: list[Finding] = []
        total_bytes = 0
        cache_hits = 0

        def process(record: FileRecord) -> tuple[list[Finding], int, bool]:
            if self.cache:
                cached = self.cache.get(record)
                if cached is not None:
                    return cached, 0, True
            text = read_text(record, self.walk_config.max_file_size)
            if text is None:
                return [], 0, False
            local: list[Finding] = []
            for rule in self._content_rules:
                if not rule.applies_to(record):
                    continue
                try:
                    local.extend(rule.run(record, text))
                except Exception as exc:
                    stats.errors.append(f"rule {rule.id} on {record.path}: {exc}")
            if self.cache:
                self.cache.put(record, local)
            return local, len(text), False

        if self.workers == 1:
            results = [process(r) for r in targets]
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=self.workers) as pool:
                results = list(pool.map(process, targets))

        for local, size, hit in results:
            findings.extend(local)
            total_bytes += size
            cache_hits += int(hit)

        stats.rules_executed += len(self._content_rules) * len(targets)
        return findings, total_bytes, cache_hits

    def _check_lockfiles(self, records: list[FileRecord]) -> list[Finding]:
        """Manifest present + lockfile absent. Needs the whole file list."""
        names = {r.name for r in records if not r.is_dir}
        findings: list[Finding] = []
        for record in records:
            ecosystem = dependencies.MANIFESTS.get(record.name.lower())
            if not ecosystem:
                continue
            expected = dependencies.LOCKFILES.get(ecosystem)
            if not expected:
                continue
            if any(lock in names for lock in expected):
                continue
            findings.append(
                dependencies.MISSING_LOCKFILE_RULE.finding(
                    record.path,
                    evidence=f"no {' / '.join(expected)}",
                    description=(
                        f"`{record.name}` declares dependencies but none of "
                        f"{', '.join(expected)} is committed. Without a lockfile the transitive "
                        f"tree is resolved fresh on every install, so two builds from the same "
                        f"commit can contain different code."
                    ),
                    metadata={"ecosystem": ecosystem, "expected": list(expected)},
                )
            )
        return findings

    def _apply_suppressions(
        self, findings: list[Finding], records: list[FileRecord]
    ) -> tuple[list[Finding], int]:
        """Honour ``# pyrasec:ignore`` comments.

        Three forms, all deliberately explicit — a suppression should be
        readable in a code review, which is why there is no wildcard form:

            secret = "..."          # pyrasec:ignore SEC002 documented test key
            # pyrasec:ignore-next-line SEC001
            # pyrasec:ignore-file SEC004

        A bare ``pyrasec:ignore`` with no rule id is rejected. Blanket
        suppressions are how a scanner quietly stops working.
        """
        paths_with_findings = {f.path for f in findings if f.line}
        if not paths_with_findings:
            return findings, 0

        by_path = {r.path: r for r in records}
        line_suppressions: dict[tuple[str, int], set[str]] = {}
        file_suppressions: dict[str, set[str]] = {}

        for path in paths_with_findings:
            record = by_path.get(path)
            if record is None or record.is_binary:
                continue
            text = read_text(record, self.walk_config.max_file_size)
            if text is None:
                continue
            for index, line in enumerate(text.splitlines(), start=1):
                marker = _parse_suppression(line)
                if marker is None:
                    continue
                kind, rule_ids = marker
                if kind == "file":
                    file_suppressions.setdefault(path, set()).update(rule_ids)
                elif kind == "next":
                    line_suppressions.setdefault((path, index + 1), set()).update(rule_ids)
                else:
                    line_suppressions.setdefault((path, index), set()).update(rule_ids)

        kept: list[Finding] = []
        removed = 0
        for finding in findings:
            file_rules = file_suppressions.get(finding.path, set())
            line_rules = line_suppressions.get((finding.path, finding.line or -1), set())
            if finding.rule_id in file_rules or finding.rule_id in line_rules:
                removed += 1
                continue
            kept.append(finding)
        return kept, removed

    @staticmethod
    def _dedupe(findings: list[Finding]) -> list[Finding]:
        seen: set[tuple[str, str, int | None]] = set()
        unique: list[Finding] = []
        for finding in findings:
            key = (finding.rule_id, finding.path, finding.line)
            if key in seen:
                continue
            seen.add(key)
            unique.append(finding)
        return unique


def scan(root: str, **kwargs) -> ScanResult:
    """Convenience wrapper: ``pyrasec.scan("./myproject")``."""
    return Scanner(root, **kwargs).scan()


def collect_sbom(result: ScanResult) -> dict:
    """Build a CycloneDX 1.5 SBOM from the manifests found during the scan."""
    components: list[dependencies.Component] = []
    for record in result.files:
        if record.is_dir or record.name.lower() not in dependencies.MANIFESTS:
            continue
        text = read_text(record)
        if text:
            components.extend(dependencies.extract_components(record, text))

    unique: dict[str, dependencies.Component] = {}
    for component in components:
        unique.setdefault(component.purl, component)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": result.started_at,
            "tools": [{"vendor": "CipherStack", "name": "PyraSec", "version": VERSION}],
            "component": {"type": "application", "name": Path(result.root).name},
        },
        "components": [c.to_dict() for c in sorted(unique.values(), key=lambda c: c.purl)],
    }

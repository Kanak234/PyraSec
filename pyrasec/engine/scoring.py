"""The security score.

A single 0-100 number that judges, dashboards and the 3D pyramid all read from.
It has to satisfy four properties, and the model below is chosen to guarantee
each one rather than to look impressive:

1. **Bounded.** Always in [0, 100]. A subtractive model goes negative on a
   messy repo and then "0" means nothing.
2. **Monotonic.** Fixing a finding can never lower the score. Adding one can
   never raise it.
3. **Size-fair.** Ten findings in a 20-file project is a worse posture than
   ten findings in a 5,000-file monorepo. Penalty is normalised by tree size.
4. **Explainable.** Every input is printable. `pyrasec score --explain` shows
   the arithmetic, because a score nobody can reconstruct is a score nobody
   trusts.

    penalty  = Σ (severity_weight × confidence)
    density  = penalty / (1 + log₁₀(files))
    score    = 100 × e^(−density / K)

Exponential decay gives steep early feedback (fixing the first critical moves
the number a lot) with a long tail (a repo with 200 issues doesn't sit at
exactly the same 0 as one with 400).
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from ..core.models import Finding, Severity

DECAY_CONSTANT = 12.0

GRADE_BANDS = [
    (95.0, "A+"), (90.0, "A"), (85.0, "A-"),
    (80.0, "B+"), (75.0, "B"), (70.0, "B-"),
    (65.0, "C+"), (60.0, "C"), (55.0, "C-"),
    (50.0, "D+"), (40.0, "D"), (0.0, "F"),
]


@dataclass
class ScoreBreakdown:
    """Every intermediate value, so the number can be audited."""

    score: float
    grade: str
    total_penalty: float
    density: float
    file_count: int
    penalty_by_severity: dict[str, float] = field(default_factory=dict)
    count_by_severity: dict[str, int] = field(default_factory=dict)
    top_contributors: list[tuple[str, float]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "grade": self.grade,
            "total_penalty": round(self.total_penalty, 3),
            "density": round(self.density, 4),
            "file_count": self.file_count,
            "penalty_by_severity": {k: round(v, 2) for k, v in self.penalty_by_severity.items()},
            "count_by_severity": self.count_by_severity,
            "top_contributors": [
                {"rule_id": r, "penalty": round(p, 2)} for r, p in self.top_contributors
            ],
            "formula": "100 * exp(-(total_penalty / (1 + log10(files))) / 12)",
        }

    def explain(self) -> str:
        lines = [
            f"Files scanned          : {self.file_count}",
            f"Total penalty          : {self.total_penalty:.2f}",
            f"Size normaliser        : 1 + log10({self.file_count}) = {1 + math.log10(max(self.file_count, 1)):.3f}",
            f"Penalty density        : {self.density:.4f}",
            f"Score = 100 * e^(-{self.density:.4f}/{DECAY_CONSTANT}) = {self.score:.1f}  [{self.grade}]",
            "",
            "Penalty by severity:",
        ]
        for severity, penalty in self.penalty_by_severity.items():
            count = self.count_by_severity.get(severity, 0)
            if count:
                lines.append(f"  {severity:<9} {count:>4} finding(s)  →  {penalty:6.2f}")
        if self.top_contributors:
            lines.append("")
            lines.append("Largest contributors:")
            for rule_id, penalty in self.top_contributors:
                lines.append(f"  {rule_id:<10} {penalty:6.2f}")
        return "\n".join(lines)


def compute_score(findings: list[Finding], file_count: int) -> ScoreBreakdown:
    penalty_by_severity: dict[str, float] = {s.value: 0.0 for s in Severity}
    count_by_severity: dict[str, int] = {s.value: 0 for s in Severity}
    penalty_by_rule: dict[str, float] = {}

    total = 0.0
    for finding in findings:
        penalty = finding.penalty
        total += penalty
        penalty_by_severity[finding.severity.value] += penalty
        count_by_severity[finding.severity.value] += 1
        penalty_by_rule[finding.rule_id] = penalty_by_rule.get(finding.rule_id, 0.0) + penalty

    normaliser = 1.0 + math.log10(max(file_count, 1))
    density = total / normaliser
    score = 100.0 * math.exp(-density / DECAY_CONSTANT)
    score = round(max(0.0, min(100.0, score)), 1)

    top = sorted(penalty_by_rule.items(), key=lambda kv: -kv[1])[:5]

    return ScoreBreakdown(
        score=score,
        grade=grade_for(score),
        total_penalty=total,
        density=density,
        file_count=file_count,
        penalty_by_severity=penalty_by_severity,
        count_by_severity=count_by_severity,
        top_contributors=top,
    )


def grade_for(score: float) -> str:
    for threshold, grade in GRADE_BANDS:
        if score >= threshold:
            return grade
    return "F"


def risk_reduction(findings: list[Finding], fixed: list[Finding], file_count: int) -> dict:
    """What fixing a specific set of findings would do to the score.

    This is what powers "fix this one thing first": the engine can rank every
    finding by how much the score moves when it alone is resolved, which is a
    genuinely different ordering from raw severity once confidence and
    clustering are taken into account.
    """
    before = compute_score(findings, file_count)
    fixed_ids = {f.fingerprint for f in fixed}
    remaining = [f for f in findings if f.fingerprint not in fixed_ids]
    after = compute_score(remaining, file_count)
    return {
        "score_before": before.score,
        "score_after": after.score,
        "gain": round(after.score - before.score, 1),
        "findings_resolved": len(fixed),
    }


def prioritise(findings: list[Finding], file_count: int, limit: int = 10) -> list[dict]:
    """The 'fix this first' list, ranked by penalty removed per action.

    Findings are grouped into **fix actions** — one (rule, file) pair is one
    thing a developer does. Six SEC002 hits in `settings.py` are one action
    ("move that file's config to env vars"), not six. Ranking ungrouped
    findings produces a list where the top ten entries are all the same file,
    which is a worse experience than no list at all.

    Ranking is by penalty removed rather than by realised score gain: on a
    badly-scoring project the exponential curve is flat near zero, so every
    individual fix would show a gain of +0.00 and the list would carry no
    signal. Penalty is the quantity that actually differs between actions;
    ``score_gain`` is reported alongside it as context.
    """
    baseline = compute_score(findings, file_count).score

    groups: dict[tuple[str, str], list[Finding]] = {}
    for finding in findings:
        groups.setdefault((finding.rule_id, finding.path), []).append(finding)

    ranked: list[dict] = []
    for (rule_id, path), group in groups.items():
        penalty = sum(f.penalty for f in group)
        remaining = [f for f in findings if (f.rule_id, f.path) != (rule_id, path)]
        gain = compute_score(remaining, file_count).score - baseline
        worst = min(group, key=lambda f: f.severity.rank)
        lines = sorted(f.line for f in group if f.line)
        ranked.append(
            {
                "rule_id": rule_id,
                "title": worst.title,
                "path": path,
                "line": lines[0] if lines else None,
                "lines": lines,
                "severity": worst.severity.value,
                "occurrences": len(group),
                "penalty_removed": round(penalty, 2),
                "score_gain": round(gain, 2),
                "remediation": worst.remediation.summary,
                "fingerprints": [f.fingerprint for f in group],
            }
        )

    ranked.sort(key=lambda item: (-item["penalty_removed"], item["path"], item["rule_id"]))
    return ranked[:limit]

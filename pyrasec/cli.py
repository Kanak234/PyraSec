"""PyraSec command line interface.

Design rule: the CLI is the product boundary. The FastAPI service, the
pre-commit hook and the CI job all call the same ``Scanner`` this does — none
of them re-implement logic. If it can't be done from the CLI, it isn't a
feature yet.

Exit codes are the CI contract:
    0  clean, or findings below the --fail-on threshold
    1  findings at or above the threshold  (fail the build)
    2  scan could not run (bad path, unreadable root)
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
from pathlib import Path

from .core.models import Severity
from .core.walker import WalkConfig
from .engine.scanner import Scanner, collect_sbom, VERSION
from .engine.scoring import compute_score, prioritise
from .report.html import render_html
from .report.sarif import build_sarif
from .rules.base import all_rules

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

C = {
    "reset": "\033[0m", "bold": "\033[1m", "dim": "\033[2m",
    "red": "\033[91m", "orange": "\033[38;5;208m", "yellow": "\033[93m",
    "green": "\033[92m", "cyan": "\033[96m", "grey": "\033[90m",
}

SEVERITY_COLOR = {
    "critical": C["red"], "high": C["orange"], "medium": C["yellow"],
    "low": C["cyan"], "info": C["grey"],
}


def _supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


def paint(text: str, *styles: str) -> str:
    if not _supports_color():
        return text
    return "".join(C[s] for s in styles) + text + C["reset"]


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------


def cmd_scan(args: argparse.Namespace) -> int:
    walk_config = WalkConfig(
        max_file_size=args.max_file_size,
        exclude_globs=args.exclude or [],
        respect_gitignore=not args.no_gitignore,
    )
    try:
        scanner = Scanner(
            args.path,
            profile=args.profile,
            enabled_rules=args.rule,
            disabled_rules=args.disable,
            walk_config=walk_config,
            workers=args.workers,
            use_cache=not args.no_cache,
        )
        result = scanner.scan()
    except (FileNotFoundError, NotADirectoryError) as exc:
        print(paint(f"error: {exc}", "red"), file=sys.stderr)
        return 2

    breakdown = compute_score(result.findings, result.stats.files_scanned)
    result.score, result.grade = breakdown.score, breakdown.grade

    fmt = args.format
    if fmt == "json":
        payload = result.to_dict()
        payload["score_breakdown"] = breakdown.to_dict()
        output = json.dumps(payload, indent=2)
    elif fmt == "sarif":
        output = json.dumps(build_sarif(result, VERSION), indent=2)
    elif fmt == "html":
        output = render_html(result, breakdown)
    elif fmt == "csv":
        output = _csv(result)
    else:
        output = _table(result, breakdown, args.verbose)

    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(paint(f"→ {args.output}", "green"))
        if fmt == "table":
            print(output)
    else:
        print(output)

    return _exit_code(result, args.fail_on)


def cmd_score(args: argparse.Namespace) -> int:
    result = Scanner(args.path, profile=args.profile, use_cache=not args.no_cache).scan()
    breakdown = compute_score(result.findings, result.stats.files_scanned)
    if args.explain:
        print(paint("PyraSec score breakdown", "bold"))
        print(paint("─" * 60, "grey"))
        print(breakdown.explain())
    else:
        print(f"{breakdown.score:g} {breakdown.grade}")
    return 0


def cmd_fix(args: argparse.Namespace) -> int:
    result = Scanner(args.path, profile=args.profile).scan()
    ranked = prioritise(result.findings, result.stats.files_scanned, limit=args.limit)
    if not ranked:
        print(paint("Nothing to fix — no findings.", "green"))
        return 0

    print(paint(
        "\nFix these first — {} actions cover {} findings (score now: {:g}/100 {})\n".format(
            len(ranked), sum(i["occurrences"] for i in ranked), result.score, result.grade
        ), "bold"))
    for index, item in enumerate(ranked, 1):
        severity = paint("{:<8}".format(item["severity"].upper()), "bold")
        location = item["path"]
        if item["lines"]:
            shown = ",".join(str(n) for n in item["lines"][:4])
            more = "…" if len(item["lines"]) > 4 else ""
            location += ":" + shown + more
        count = " ×{}".format(item["occurrences"]) if item["occurrences"] > 1 else ""
        impact = paint("-{:.0f} penalty".format(item["penalty_removed"]), "green")
        if item["score_gain"] >= 0.05:
            impact += paint("  (+{:.1f} score)".format(item["score_gain"]), "grey")
        print("{:>2}. {} {}{}  {}".format(
            index, severity, paint(item["rule_id"], "grey"), count, item["title"]))
        print("    {}".format(paint(location, "cyan")))
        print("    {}  {}".format(impact, item["remediation"]))
        print()
    return 0


def cmd_sbom(args: argparse.Namespace) -> int:
    result = Scanner(args.path, profile="default", use_cache=False).scan()
    sbom = collect_sbom(result)
    output = json.dumps(sbom, indent=2)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(paint(f"→ {args.output}  ({len(sbom['components'])} components)", "green"))
    else:
        print(output)
    return 0


def cmd_pyramid(args: argparse.Namespace) -> int:
    from .viz.pyramid import build_attack_surface, build_folder_tree, build_pyramid, build_risk_heatmap

    result = Scanner(args.path, profile=args.profile).scan()
    payload = {
        "pyramid": build_pyramid(result),
        "tree": build_folder_tree(result),
        "heatmap": build_risk_heatmap(result),
        "attack_surface": build_attack_surface(result),
    }
    output = json.dumps(payload, indent=2)
    if args.output:
        Path(args.output).write_text(output, encoding="utf-8")
        print(paint(f"→ {args.output}", "green"))
    else:
        print(output)
    return 0


def cmd_rules(args: argparse.Namespace) -> int:
    rules = all_rules()
    if args.json:
        print(json.dumps([
            {
                "id": r.id, "title": r.title, "severity": r.severity.value,
                "cwe": r.cwe, "owasp": r.owasp, "mitre": r.mitre,
                "cvss": r.cvss, "tags": r.tags, "fast": r.fast,
                "description": r.description,
                "remediation": r.remediation.to_dict(),
            } for r in rules
        ], indent=2))
        return 0

    print(paint(f"\n{len(rules)} rules registered\n", "bold"))
    current_tag = None
    for rule in rules:
        tag = rule.tags[0] if rule.tags else "general"
        if tag != current_tag:
            print(paint(f"  {tag.upper()}", "grey"))
            current_tag = tag
        severity = paint("{:<9}".format(rule.severity.value.upper()), "bold")
        print("  {:<16} {} {}".format(rule.id, severity, rule.title))
    print()
    return 0


def cmd_hook(args: argparse.Namespace) -> int:
    """Install a git pre-commit hook that runs the fast profile."""
    repo = Path(args.path).resolve()
    hooks = repo / ".git" / "hooks"
    if not hooks.is_dir():
        print(paint(f"error: {repo} is not a git repository", "red"), file=sys.stderr)
        return 2

    hook = hooks / "pre-commit"
    script = f"""#!/bin/sh
# Installed by PyraSec. Blocks a commit that introduces high or critical findings.
# Bypass deliberately (and rarely) with: git commit --no-verify
exec python3 -m pyrasec scan . --profile fast --fail-on high --format table
"""
    if hook.exists() and not args.force:
        print(paint(f"{hook} already exists — pass --force to overwrite", "yellow"))
        return 1
    hook.write_text(script, encoding="utf-8")
    hook.chmod(0o755)
    print(paint(f"→ installed {hook}", "green"))
    print(paint("  runs the fast profile on every commit; blocks on high/critical", "grey"))
    return 0


# --------------------------------------------------------------------------
# Output formats
# --------------------------------------------------------------------------


def _table(result, breakdown, verbose: bool) -> str:
    lines: list[str] = []
    counts = result.by_severity()

    lines.append("")
    lines.append(paint("  PyraSec", "bold", "cyan") + paint("  Visualize. Detect. Secure.", "grey"))
    lines.append(paint("  " + "─" * 68, "grey"))
    lines.append(f"  {paint('root', 'grey')}     {result.root}")
    lines.append(
        f"  {paint('scanned', 'grey')}  {result.stats.files_scanned} files, "
        f"{result.stats.dirs_scanned} folders in {result.stats.duration_seconds}s"
        + (f"  ({result.stats.cache_hits} cached)" if result.stats.cache_hits else "")
    )

    score_style = "green" if result.score >= 85 else "yellow" if result.score >= 60 else "red"
    lines.append(
        f"  {paint('score', 'grey')}    "
        + paint(f"{result.score:g}/100  {result.grade}", "bold", score_style)
    )
    lines.append("")

    summary = "  ".join(
        paint(f"{counts[s]} {s}", "bold") if counts[s] else paint(f"0 {s}", "grey")
        for s in SEVERITY_ORDER if counts[s] or s in ("critical", "high")
    )
    lines.append(f"  {summary}")
    lines.append("")

    if not result.findings:
        lines.append(paint("  ✓ No findings.", "green"))
        lines.append("")
        return "\n".join(lines)

    for finding in result.sorted_findings():
        color = SEVERITY_COLOR[finding.severity.value]
        location = f"{finding.path}:{finding.line}" if finding.line else finding.path
        badge = paint(f" {finding.severity.value.upper():<8} ", "bold")
        lines.append(f"  {badge} {paint(finding.rule_id, 'grey')}  {finding.title}")
        lines.append(f"     {paint(location, 'cyan')}")
        if finding.evidence:
            lines.append(f"     {paint('evidence:', 'grey')} {finding.evidence}")
        if verbose:
            lines.append(f"     {paint(finding.description, 'grey')}")
            lines.append(f"     {paint('fix:', 'green')} {finding.remediation.summary}")
            for step in finding.remediation.steps[:3]:
                lines.append(f"       • {paint(step, 'grey')}")
        lines.append("")

    lines.append(paint("  " + "─" * 68, "grey"))
    top = ", ".join(f"{rid} ({p:.0f})" for rid, p in breakdown.top_contributors[:3])
    lines.append(f"  {paint('biggest contributors:', 'grey')} {top}")
    lines.append(f"  {paint('run', 'grey')} pyrasec fix {result.root} "
                 f"{paint('for the ranked fix list', 'grey')}")
    lines.append("")
    return "\n".join(lines)


def _csv(result) -> str:
    import io

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow([
        "rule_id", "severity", "cvss", "confidence", "path", "line",
        "title", "cwe", "owasp", "mitre", "evidence", "remediation", "fingerprint",
    ])
    for f in result.sorted_findings():
        writer.writerow([
            f.rule_id, f.severity.value, f.effective_cvss, f.confidence, f.path,
            f.line or "", f.title, f.cwe or "", f.owasp or "", f.mitre or "",
            f.evidence, f.remediation.summary, f.fingerprint,
        ])
    return buffer.getvalue()


def _exit_code(result, fail_on: str) -> int:
    if fail_on == "none":
        return 0
    threshold = Severity(fail_on).rank
    if any(f.severity.rank <= threshold for f in result.findings):
        return 1
    return 0


# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pyrasec",
        description="PyraSec — deterministic project security scanner with 3D visualisation.",
        epilog="Scan → Detect → Visualize → Fix.  No AI, no ML, no LLM in the detection path.",
    )
    parser.add_argument("--version", action="version", version=f"PyraSec {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p):
        p.add_argument("path", nargs="?", default=".", help="project directory (default: .)")
        p.add_argument("--profile", default="default",
                       choices=["default", "fast", "secrets"],
                       help="rule subset: fast = pre-commit speed, secrets = credentials only")
        p.add_argument("--no-cache", action="store_true", help="ignore the incremental cache")

    scan = sub.add_parser("scan", help="scan a project and report findings")
    add_common(scan)
    scan.add_argument("-f", "--format", default="table",
                      choices=["table", "json", "sarif", "html", "csv"])
    scan.add_argument("-o", "--output", help="write the report to a file")
    scan.add_argument("--fail-on", default="none",
                      choices=["none", "critical", "high", "medium", "low"],
                      help="exit 1 when a finding at or above this severity exists")
    scan.add_argument("--rule", action="append", help="run only this rule id (repeatable)")
    scan.add_argument("--disable", action="append", help="skip this rule id (repeatable)")
    scan.add_argument("--exclude", action="append", help="glob to exclude (repeatable)")
    scan.add_argument("--no-gitignore", action="store_true", help="do not honour .gitignore")
    scan.add_argument("--workers", type=int, default=8, help="parallel file readers")
    scan.add_argument("--max-file-size", type=int, default=5 * 1024 * 1024)
    scan.add_argument("-v", "--verbose", action="store_true", help="include fix guidance inline")
    scan.set_defaults(func=cmd_scan)

    score = sub.add_parser("score", help="print the security score")
    add_common(score)
    score.add_argument("--explain", action="store_true", help="show the full arithmetic")
    score.set_defaults(func=cmd_score)

    fix = sub.add_parser("fix", help="ranked list of what to fix first")
    add_common(fix)
    fix.add_argument("--limit", type=int, default=10)
    fix.set_defaults(func=cmd_fix)

    sbom = sub.add_parser("sbom", help="generate a CycloneDX SBOM")
    add_common(sbom)
    sbom.add_argument("-o", "--output")
    sbom.set_defaults(func=cmd_sbom)

    pyramid = sub.add_parser("pyramid", help="emit visualisation JSON for the frontend")
    add_common(pyramid)
    pyramid.add_argument("-o", "--output")
    pyramid.set_defaults(func=cmd_pyramid)

    rules = sub.add_parser("rules", help="list every registered rule")
    rules.add_argument("--json", action="store_true")
    rules.set_defaults(func=cmd_rules)

    hook = sub.add_parser("hook", help="install the git pre-commit hook")
    hook.add_argument("path", nargs="?", default=".")
    hook.add_argument("--force", action="store_true")
    hook.set_defaults(func=cmd_hook)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print(paint("\ninterrupted", "yellow"), file=sys.stderr)
        return 130
    except BrokenPipeError:
        # Piping into `head` or `less` closes stdout early. Redirect the fd to
        # devnull so the interpreter's shutdown flush doesn't raise again.
        devnull = os.open(os.devnull, os.O_WRONLY)
        os.dup2(devnull, sys.stdout.fileno())
        return 0


if __name__ == "__main__":
    raise SystemExit(main())

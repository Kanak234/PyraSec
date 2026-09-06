"""Git exposure rules.

Two failure modes, both common enough to have their own scanner tooling in the
wild: shipping the `.git` directory to production (which hands over full source
history), and having no `.gitignore` protection for the files that matter (which
means the next `git add .` commits the secret).
"""

from __future__ import annotations

import fnmatch
import os

from ..core.models import FileRecord, Remediation, Severity
from .base import ProjectRule, register

# Patterns a project should be ignoring. Each entry: (label, candidate patterns
# that would satisfy it, severity if missing).
REQUIRED_IGNORES: list[tuple[str, tuple[str, ...], Severity]] = [
    ("environment files", (".env", ".env*", "*.env", ".env.*"), Severity.CRITICAL),
    ("private keys", ("*.pem", "*.key", "id_rsa*", "*.p12", "*.pfx"), Severity.HIGH),
    ("dependency directories", ("node_modules", "node_modules/", "/node_modules"), Severity.LOW),
    ("virtual environments", ("venv", "venv/", ".venv", ".venv/", "env/"), Severity.LOW),
    ("build output", ("dist", "dist/", "build", "build/", "target/"), Severity.LOW),
    ("logs", ("*.log", "logs/", "log/"), Severity.LOW),
    ("backups and dumps", ("*.bak", "*.sql", "*.dump", "*.sqlite3"), Severity.MEDIUM),
    ("IDE and OS files", (".vscode/", ".idea/", ".DS_Store", "Thumbs.db"), Severity.INFO),
]


def _read_ignore_patterns(root: str) -> list[str]:
    path = os.path.join(root, ".gitignore")
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return [
                line.strip()
                for line in fh
                if line.strip() and not line.strip().startswith("#")
            ]
    except OSError:
        return []


def _check_git_directory(records: list[FileRecord]):
    """A committed/deployed .git directory leaks the entire history."""
    for record in records:
        parts = record.path.split("/")
        if ".git" not in parts:
            continue
        # Only report the directory itself, not everything under it.
        if record.is_dir and record.name == ".git":
            depth_note = "project root" if record.depth == 0 else f"`{record.parent or '.'}`"
            yield GIT_DIR_RULE.finding(
                record.path,
                evidence=record.path,
                description=(
                    f"A `.git` directory exists at {depth_note}. This is normal during development, "
                    f"but if this tree is copied to a web root or baked into a container image with "
                    f"`COPY . .`, then `/.git/config`, `/.git/HEAD` and the packfiles become fetchable — "
                    f"and the full source history, including any secret ever committed and later "
                    f"'removed', can be reconstructed."
                ),
                severity=Severity.MEDIUM if record.depth == 0 else Severity.HIGH,
                confidence=0.6 if record.depth == 0 else 1.0,
                metadata={"depth": record.depth},
            )


GIT_DIR_RULE = register(
    ProjectRule(
        id="GIT001",
        title="Git metadata directory present",
        severity=Severity.MEDIUM,
        description="A .git directory was found; verify it never reaches a served path or image.",
        remediation=Remediation(
            summary="Keep .git out of images and web roots; block it at the server.",
            steps=[
                "Add `.git` and `.gitignore` to `.dockerignore` so `COPY . .` cannot include them.",
                "In a multi-stage build, copy only build artefacts into the final stage.",
                "Block the path at the web server as defence in depth.",
                "Verify from outside: `curl -I https://yoursite/.git/HEAD` should return 404, not 200.",
            ],
            example=(
                "# .dockerignore\n.git\n.gitignore\n.env\n*.md\n\n"
                "# nginx\nlocation ~ /\\.git { deny all; return 404; }\n"
            ),
            references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
        ),
        cwe="CWE-527 Exposure of Version-Control Repository to an Unauthorized Control Sphere",
        owasp="A05:2021 Security Misconfiguration",
        mitre="T1213 Data from Information Repositories",
        cvss=5.3,
        tags=["git", "exposure"],
        check=_check_git_directory,
    )
)


def _check_missing_gitignore(records: list[FileRecord]):
    has_git = any(r.name == ".git" and r.is_dir for r in records)
    has_gitignore = any(r.path == ".gitignore" for r in records)
    if has_git and not has_gitignore:
        yield NO_GITIGNORE_RULE.finding(
            ".gitignore",
            evidence="file not present",
            description=(
                "This is a git repository with no .gitignore. Every `git add .` sweeps in "
                "whatever is in the working tree — .env files, keys, dumps, node_modules. "
                "The first accidental commit of a credential is usually this."
            ),
        )


NO_GITIGNORE_RULE = register(
    ProjectRule(
        id="GIT002",
        title="Repository has no .gitignore",
        severity=Severity.HIGH,
        description="A git repository without a .gitignore will commit secrets by default.",
        remediation=Remediation(
            summary="Create a .gitignore before the next commit.",
            steps=[
                "Run `pyrasec fix gitignore` to write a starter file based on what this scan actually found.",
                "Start from a language template: https://github.com/github/gitignore",
                "Verify with `git status --ignored` that the right paths are excluded.",
                "Remember .gitignore only affects untracked files — already-tracked files need `git rm --cached <path>`.",
            ],
            example=(
                ".env\n.env.*\n!.env.example\n*.pem\n*.key\nnode_modules/\n"
                "__pycache__/\n.venv/\ndist/\nbuild/\n*.log\n*.sql\n*.bak\n.DS_Store\n"
            ),
        ),
        cwe="CWE-1230 Exposure of Sensitive Information Through Metadata",
        owasp="A05:2021 Security Misconfiguration",
        cvss=7.5,
        tags=["git", "hygiene"],
        check=_check_missing_gitignore,
    )
)


def _check_ignore_coverage(records: list[FileRecord]):
    root = _scan_root(records)
    if root is None:
        return
    if not any(r.path == ".gitignore" for r in records):
        return  # GIT002 already covers this
    patterns = _read_ignore_patterns(root)
    if not patterns:
        return

    # Only complain about a missing pattern when a matching file actually exists.
    existing_names = {r.name.lower() for r in records if not r.is_dir}
    existing_dirs = {r.name for r in records if r.is_dir}

    for label, candidates, severity in REQUIRED_IGNORES:
        if any(_pattern_present(patterns, c) for c in candidates):
            continue
        if not _relevant(label, candidates, existing_names, existing_dirs):
            continue
        yield IGNORE_COVERAGE_RULE.finding(
            ".gitignore",
            evidence=f"no rule covering {label}",
            severity=severity,
            description=(
                f".gitignore does not cover {label}, and files of that kind exist in the tree. "
                f"Suggested pattern: `{candidates[0]}`."
            ),
            metadata={"category": label, "suggested_pattern": candidates[0]},
        )


def _pattern_present(patterns: list[str], candidate: str) -> bool:
    candidate = candidate.rstrip("/").lstrip("/")
    for pattern in patterns:
        normalised = pattern.rstrip("/").lstrip("/")
        if normalised == candidate:
            return True
        if fnmatch.fnmatch(candidate, normalised):
            return True
    return False


def _relevant(label: str, candidates: tuple[str, ...], names: set[str], dirs: set[str]) -> bool:
    for candidate in candidates:
        cleaned = candidate.rstrip("/").lstrip("/")
        if cleaned in dirs:
            return True
        if any(fnmatch.fnmatch(name, cleaned.lower()) for name in names):
            return True
    return False


def _scan_root(records: list[FileRecord]) -> str | None:
    """Recover the absolute scan root from any record (path is relative)."""
    for record in records:
        if record.path and record.abs_path.endswith(record.path):
            return record.abs_path[: -len(record.path)].rstrip(os.sep) or os.sep
    return None


IGNORE_COVERAGE_RULE = register(
    ProjectRule(
        id="GIT003",
        title=".gitignore missing coverage for sensitive files",
        severity=Severity.MEDIUM,
        description="Files exist that .gitignore does not exclude.",
        remediation=Remediation(
            summary="Extend .gitignore to cover the categories present in this tree.",
            steps=[
                "Append the suggested patterns (each finding names one).",
                "Run `git status --ignored` to confirm they take effect.",
                "For files already tracked, `git rm --cached <path>` then commit — ignoring alone will not untrack them.",
            ],
        ),
        cwe="CWE-1230 Exposure of Sensitive Information Through Metadata",
        owasp="A05:2021 Security Misconfiguration",
        cvss=5.3,
        fast=False,
        tags=["git", "hygiene"],
        check=_check_ignore_coverage,
    )
)


def _check_env_committed(records: list[FileRecord]):
    """A .env in a repo whose .gitignore does not exclude it is one `git add` away."""
    root = _scan_root(records)
    patterns = _read_ignore_patterns(root) if root else []
    has_git = any(r.name == ".git" and r.is_dir for r in records)
    if not has_git:
        return
    for record in records:
        if record.is_dir or not record.name.lower().startswith(".env"):
            continue
        if record.name.lower() in (".env.example", ".env.sample", ".env.template", ".env.dist"):
            continue
        if any(_pattern_present(patterns, record.name) or fnmatch.fnmatch(record.name, p.strip("/")) for p in patterns):
            continue
        yield ENV_UNIGNORED_RULE.finding(
            record.path,
            evidence=record.name,
            description=(
                f"`{record.path}` is a real environment file in a git repository and no .gitignore "
                f"pattern excludes it. The next `git add .` commits it, and once pushed the values "
                f"must be treated as public."
            ),
        )


ENV_UNIGNORED_RULE = register(
    ProjectRule(
        id="GIT004",
        title="Environment file is not git-ignored",
        severity=Severity.CRITICAL,
        description="A .env file exists in a repo and is not excluded by .gitignore.",
        remediation=Remediation(
            summary="Ignore it now, and commit a .env.example instead.",
            steps=[
                "Add `.env` and `.env.*` to .gitignore, with `!.env.example` to keep the template tracked.",
                "Check whether it is already tracked: `git ls-files --error-unmatch .env`. If it is, `git rm --cached .env` and rotate every value in it.",
                "Create `.env.example` with the same keys and empty values so new developers know what to set.",
            ],
            example=(
                "# .gitignore\n.env\n.env.*\n!.env.example\n\n"
                "# .env.example\nDATABASE_URL=\nSTRIPE_KEY=\nJWT_SECRET=\n"
            ),
        ),
        cwe="CWE-538 Insertion of Sensitive Information into Externally-Accessible File",
        owasp="A05:2021 Security Misconfiguration",
        mitre="T1552.001 Credentials In Files",
        cvss=9.1,
        tags=["git", "secret", "exposure"],
        check=_check_env_committed,
    )
)

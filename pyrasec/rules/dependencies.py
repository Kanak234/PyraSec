"""Dependency and supply-chain rules, plus SBOM extraction.

Honest scoping note, because this is where security tools most often overclaim:

PyraSec parses manifests and produces a real CycloneDX SBOM. What it does *not*
do offline is tell you a package has a CVE — that requires a vulnerability
database, and shipping a stale copy of one is worse than shipping none.
``pyrasec db import <osv-dump>`` loads an OSV export into a local SQLite index;
until you do that, the CVE rule stays quiet rather than inventing results.

Everything else here is fully offline and fully deterministic: unpinned
versions, missing lockfiles, insecure registry URLs, and direct-from-git
dependencies are all decidable from the manifest text alone.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from ..core.models import FileRecord, Remediation, Severity
from .base import ContentRule, iter_lines, register

MANIFESTS = {
    "requirements.txt": "pypi",
    "requirements-dev.txt": "pypi",
    "pyproject.toml": "pypi",
    "pipfile": "pypi",
    "setup.py": "pypi",
    "package.json": "npm",
    "composer.json": "packagist",
    "gemfile": "rubygems",
    "go.mod": "go",
    "cargo.toml": "crates",
    "pom.xml": "maven",
    "build.gradle": "maven",
}

LOCKFILES = {
    "npm": ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"),
    "pypi": ("poetry.lock", "requirements.lock", "Pipfile.lock", "uv.lock"),
    "rubygems": ("Gemfile.lock",),
    "crates": ("Cargo.lock",),
    "packagist": ("composer.lock",),
}


@dataclass
class Component:
    """One SBOM component."""

    name: str
    version: str
    ecosystem: str
    source_file: str
    pinned: bool = True
    direct: bool = True
    scope: str = "required"

    @property
    def purl(self) -> str:
        """Package URL — the identifier CycloneDX and OSV both key on."""
        eco = {"pypi": "pypi", "npm": "npm", "go": "golang", "crates": "cargo"}.get(
            self.ecosystem, self.ecosystem
        )
        version = f"@{self.version}" if self.version and self.version != "*" else ""
        return f"pkg:{eco}/{self.name}{version}"

    def to_dict(self) -> dict:
        return {
            "type": "library",
            "name": self.name,
            "version": self.version or "unspecified",
            "purl": self.purl,
            "scope": self.scope,
            "properties": [
                {"name": "pyrasec:source", "value": self.source_file},
                {"name": "pyrasec:pinned", "value": str(self.pinned).lower()},
                {"name": "pyrasec:direct", "value": str(self.direct).lower()},
            ],
        }


# --------------------------------------------------------------------------
# Manifest parsers — each returns a list of Components
# --------------------------------------------------------------------------

PY_REQ = re.compile(
    r"^\s*(?P<name>[A-Za-z0-9._-]+)\s*(?P<op>==|>=|<=|~=|!=|>|<)?\s*(?P<version>[A-Za-z0-9._*+-]+)?"
)


def parse_requirements(text: str, source: str) -> list[Component]:
    components: list[Component] = []
    for _, raw in iter_lines(text):
        line = raw.split("#")[0].strip()
        if not line or line.startswith("-"):
            continue
        if line.startswith(("git+", "http://", "https://")):
            components.append(Component(line[:60], "", "pypi", source, pinned=False))
            continue
        match = PY_REQ.match(line)
        if not match:
            continue
        name = match.group("name")
        op = match.group("op")
        version = match.group("version") or ""
        components.append(
            Component(name, version, "pypi", source, pinned=(op == "=="))
        )
    return components


def parse_package_json(text: str, source: str) -> list[Component]:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return []
    components: list[Component] = []
    for section, scope in (("dependencies", "required"), ("devDependencies", "optional")):
        for name, spec in (data.get(section) or {}).items():
            spec = str(spec)
            pinned = bool(re.fullmatch(r"\d+\.\d+\.\d+", spec))
            components.append(
                Component(name, spec, "npm", source, pinned=pinned, scope=scope)
            )
    return components


def parse_go_mod(text: str, source: str) -> list[Component]:
    components: list[Component] = []
    in_block = False
    for _, raw in iter_lines(text):
        line = raw.strip()
        if line.startswith("require ("):
            in_block = True
            continue
        if in_block and line == ")":
            in_block = False
            continue
        target = line[len("require "):] if line.startswith("require ") else (line if in_block else "")
        parts = target.split()
        if len(parts) >= 2 and "/" in parts[0]:
            components.append(Component(parts[0], parts[1], "go", source))
    return components


def extract_components(record: FileRecord, text: str) -> list[Component]:
    name = record.name.lower()
    if name.startswith("requirements") and name.endswith(".txt"):
        return parse_requirements(text, record.path)
    if name == "package.json":
        return parse_package_json(text, record.path)
    if name == "go.mod":
        return parse_go_mod(text, record.path)
    return []


# --------------------------------------------------------------------------
# Rules
# --------------------------------------------------------------------------

PIN_REMEDIATION = Remediation(
    summary="Pin exact versions and commit a lockfile.",
    steps=[
        "Pin direct dependencies to exact versions (`==1.2.3` / `1.2.3`, not `>=` or `^`).",
        "Commit the lockfile — it pins the full transitive tree with hashes, which is the part that actually protects you.",
        "Install from the lockfile in CI and production: `npm ci`, `pip install -r requirements.txt --require-hashes`, `poetry install --sync`.",
        "Use Dependabot or Renovate so pinning does not mean never updating.",
        "Unpinned ranges mean a compromised or typosquatted release can enter your build without a single line of your code changing — this is the shape of most recent supply-chain incidents.",
    ],
    example=(
        "# requirements.txt — pinned with hashes\n"
        "fastapi==0.115.0 \\\n"
        "    --hash=sha256:0f1c...\n\n"
        "# generate with: pip-compile --generate-hashes requirements.in\n"
    ),
    references=["https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"],
)


def _check_manifest(record: FileRecord, text: str):
    components = extract_components(record, text)
    if not components:
        return

    unpinned = [c for c in components if not c.pinned and c.scope == "required"]
    if unpinned:
        sample = ", ".join(c.name for c in unpinned[:5])
        more = f" (+{len(unpinned) - 5} more)" if len(unpinned) > 5 else ""
        yield UNPINNED_RULE.finding(
            record.path,
            evidence=f"{len(unpinned)} unpinned: {sample}{more}",
            description=(
                f"{len(unpinned)} of {len(components)} runtime dependencies are not pinned to an "
                f"exact version. The build is not reproducible, and a malicious release published "
                f"upstream would be pulled in on the next install."
            ),
            severity=Severity.HIGH if len(unpinned) > len(components) / 2 else Severity.MEDIUM,
            metadata={
                "unpinned": [c.name for c in unpinned],
                "total": len(components),
            },
        )

    for line_no, raw in iter_lines(text):
        if re.search(r"http://[a-z0-9.-]+/(?:simple|registry|packages)", raw, re.I):
            yield INSECURE_REGISTRY_RULE.finding(
                record.path, line=line_no, evidence=raw.strip()[:120]
            )
        if re.search(r"(?:git\+|github\.com[:/])[^\s\"']+(?<!\.git#)$", raw) and "#" not in raw:
            if raw.strip().startswith(("git+", '"git+', "'git+")):
                yield GIT_DEP_RULE.finding(
                    record.path, line=line_no, evidence=raw.strip()[:120]
                )


UNPINNED_RULE = register(
    ContentRule(
        id="DEP001",
        title="Unpinned dependency versions",
        severity=Severity.MEDIUM,
        description="Runtime dependencies use ranges instead of exact versions.",
        remediation=PIN_REMEDIATION,
        cwe="CWE-1104 Use of Unmaintained Third Party Components",
        owasp="A06:2021 Vulnerable and Outdated Components",
        mitre="T1195.001 Compromise Software Dependencies and Development Tools",
        cvss=6.5,
        filenames=set(MANIFESTS),
        tags=["dependency", "supply-chain"],
        check=_check_manifest,
    )
)

INSECURE_REGISTRY_RULE = register(
    ContentRule(
        id="DEP002",
        title="Package registry accessed over plain HTTP",
        severity=Severity.HIGH,
        description="A dependency source uses http://, allowing package substitution in transit.",
        remediation=Remediation(
            summary="Switch the index URL to HTTPS.",
            steps=[
                "Change the index/registry URL to https://.",
                "For an internal mirror, install its CA rather than falling back to plain HTTP.",
                "Over HTTP, anyone on the path can replace the package you asked for with one they wrote.",
            ],
            example="pip config set global.index-url https://pypi.internal/simple\nnpm config set registry https://registry.npmjs.org/\n",
        ),
        cwe="CWE-319 Cleartext Transmission of Sensitive Information",
        owasp="A08:2021 Software and Data Integrity Failures",
        mitre="T1195.002 Compromise Software Supply Chain",
        cvss=8.1,
        filenames=set(MANIFESTS) | {".npmrc", "pip.conf", ".pypirc"},
        tags=["dependency", "supply-chain"],
    )
)

GIT_DEP_RULE = register(
    ContentRule(
        id="DEP003",
        title="Dependency installed directly from a git branch",
        severity=Severity.MEDIUM,
        description="A dependency points at a git ref that can move.",
        remediation=Remediation(
            summary="Pin the git dependency to a commit SHA.",
            steps=[
                "Append a full commit SHA so the ref cannot move: `git+https://github.com/org/repo@<40-char-sha>`.",
                "Better: publish an internal package to a private registry and depend on a version.",
                "A branch reference means whoever controls that branch controls what runs in your build.",
            ],
            example="git+https://github.com/org/lib@8d3f2c1a9b4e5f6d7c8b9a0e1f2d3c4b5a6d7e8f\n",
        ),
        cwe="CWE-494 Download of Code Without Integrity Check",
        owasp="A08:2021 Software and Data Integrity Failures",
        cvss=5.9,
        filenames=set(MANIFESTS),
        tags=["dependency", "supply-chain"],
    )
)


def _check_lockfile_presence(record: FileRecord, text: str):
    """Reported by the ProjectRule wrapper in engine.scanner via SBOM collection."""
    return []


MISSING_LOCKFILE_RULE = register(
    ContentRule(
        id="DEP004",
        title="Manifest without a committed lockfile",
        severity=Severity.MEDIUM,
        description="A dependency manifest exists but no lockfile pins the transitive tree.",
        remediation=PIN_REMEDIATION,
        cwe="CWE-1104 Use of Unmaintained Third Party Components",
        owasp="A06:2021 Vulnerable and Outdated Components",
        cvss=5.3,
        filenames=set(MANIFESTS),
        tags=["dependency", "supply-chain"],
    )
)

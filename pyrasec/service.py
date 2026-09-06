"""FastAPI service.

Thin HTTP layer over the same ``Scanner`` the CLI uses — no detection logic
lives here. That is deliberate: the moment the API and the CLI can disagree
about what a finding is, you have two products to keep in sync and one of them
is always wrong.

    pip install "fastapi[standard]"
    uvicorn pyrasec.service:app --reload

The React + Three.js frontend consumes ``POST /api/v1/scan`` and renders
``response.pyramid`` directly — that payload is exactly what
``pyrasec pyramid`` writes to disk, so the CLI output and the live app are the
same bytes.

Security notes for anyone deploying this beyond a demo, because a scanner that
takes a path from a request is a directory-traversal engine if you let it:

* ``ALLOWED_ROOTS`` confines every scan to configured directories. It is not
  optional — resolve-then-verify, before any filesystem access.
* Add authentication before this is reachable by anyone but you. There is no
  auth here; wiring OAuth/RBAC is the next milestone, not a solved problem.
* Long scans belong on a task queue (Celery + Redis), not in the request
  thread. ``/scan`` is synchronous by design for the hackathon build; the
  ``202 + job id`` shape is sketched in ``ROADMAP`` in the README.
"""

from __future__ import annotations

import os
from pathlib import Path

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import HTMLResponse, JSONResponse
    from pydantic import BaseModel, Field
except ImportError as exc:  # pragma: no cover
    raise SystemExit(
        "The API needs FastAPI. Install it with:  pip install 'fastapi[standard]'\n"
        "The scanner core and CLI have no dependencies and work without it."
    ) from exc

from .core.walker import WalkConfig
from .engine.scanner import Scanner, collect_sbom, VERSION
from .engine.scoring import compute_score, prioritise
from .report.html import render_html
from .report.sarif import build_sarif
from .rules.base import all_rules
from .viz.pyramid import (
    build_attack_surface, build_folder_tree, build_pyramid, build_risk_heatmap,
)

# Every scan target must resolve inside one of these. Override with
# PYRASEC_ALLOWED_ROOTS="/srv/repos:/var/checkouts".
ALLOWED_ROOTS = [
    Path(p).resolve()
    for p in os.environ.get("PYRASEC_ALLOWED_ROOTS", str(Path.cwd())).split(os.pathsep)
    if p
]

app = FastAPI(
    title="PyraSec API",
    version=VERSION,
    description="Deterministic project security analysis. Scan → Detect → Visualize → Fix.",
)


class ScanRequest(BaseModel):
    path: str = Field(..., description="Directory to scan (must be under an allowed root)")
    profile: str = Field("default", pattern="^(default|fast|secrets)$")
    workers: int = Field(8, ge=1, le=32)
    include_pyramid: bool = True
    include_tree: bool = False
    use_cache: bool = True


def _resolve(raw: str) -> Path:
    """Resolve a requested path and confirm it is inside an allowed root."""
    try:
        target = Path(raw).expanduser().resolve(strict=True)
    except (OSError, RuntimeError):
        raise HTTPException(status_code=404, detail="path not found")
    if not target.is_dir():
        raise HTTPException(status_code=400, detail="path is not a directory")
    for allowed in ALLOWED_ROOTS:
        if target == allowed or allowed in target.parents:
            return target
    raise HTTPException(status_code=403, detail="path is outside the allowed roots")


def _run(request: ScanRequest):
    root = _resolve(request.path)
    scanner = Scanner(
        str(root),
        profile=request.profile,
        workers=request.workers,
        use_cache=request.use_cache,
        walk_config=WalkConfig(),
    )
    result = scanner.scan()
    breakdown = compute_score(result.findings, result.stats.files_scanned)
    result.score, result.grade = breakdown.score, breakdown.grade
    return result, breakdown


@app.get("/health")
def health() -> dict:
    return {
        "status": "ok",
        "version": VERSION,
        "rules_loaded": len(all_rules()),
        "allowed_roots": [str(p) for p in ALLOWED_ROOTS],
    }


@app.post("/api/v1/scan")
def scan_endpoint(request: ScanRequest) -> dict:
    """Full scan. This is what the frontend calls on 'Scan project'."""
    result, breakdown = _run(request)
    payload = result.to_dict()
    payload["score_breakdown"] = breakdown.to_dict()
    payload["priority_fixes"] = prioritise(result.findings, result.stats.files_scanned)
    if request.include_pyramid:
        payload["pyramid"] = build_pyramid(result)
        payload["heatmap"] = build_risk_heatmap(result)
        payload["attack_surface"] = build_attack_surface(result)
    if request.include_tree:
        payload["tree"] = build_folder_tree(result)
    return payload


@app.post("/api/v1/score")
def score_endpoint(request: ScanRequest) -> dict:
    """Just the number and its arithmetic — cheap enough for a status badge."""
    _result, breakdown = _run(request)
    return breakdown.to_dict()


@app.post("/api/v1/pyramid")
def pyramid_endpoint(request: ScanRequest) -> dict:
    """Visualisation payloads only. Same bytes as `pyrasec pyramid -o`."""
    result, _ = _run(request)
    return {
        "pyramid": build_pyramid(result),
        "tree": build_folder_tree(result),
        "heatmap": build_risk_heatmap(result),
        "attack_surface": build_attack_surface(result),
    }


@app.post("/api/v1/sbom")
def sbom_endpoint(request: ScanRequest) -> dict:
    """CycloneDX 1.5 software bill of materials."""
    result, _ = _run(request)
    return collect_sbom(result)


@app.post("/api/v1/sarif")
def sarif_endpoint(request: ScanRequest) -> JSONResponse:
    """SARIF 2.1.0 — upload straight to GitHub code scanning."""
    result, _ = _run(request)
    return JSONResponse(build_sarif(result, VERSION))


@app.post("/api/v1/report", response_class=HTMLResponse)
def report_endpoint(request: ScanRequest) -> HTMLResponse:
    """Self-contained HTML report. No external requests, safe to email."""
    result, breakdown = _run(request)
    return HTMLResponse(render_html(result, breakdown))


@app.get("/api/v1/rules")
def rules_endpoint(tag: str | None = None, severity: str | None = None) -> dict:
    """The rule catalogue. Powers the 'what does this catch?' page."""
    rules = all_rules()
    if tag:
        rules = [r for r in rules if tag in r.tags]
    if severity:
        rules = [r for r in rules if r.severity.value == severity]
    return {
        "count": len(rules),
        "rules": [
            {
                "id": r.id,
                "title": r.title,
                "severity": r.severity.value,
                "description": r.description,
                "cwe": r.cwe,
                "owasp": r.owasp,
                "mitre": r.mitre,
                "cvss": r.cvss if r.cvss is not None else r.severity.cvss_base,
                "tags": r.tags,
                "in_fast_profile": r.fast,
                "remediation": r.remediation.to_dict(),
            }
            for r in rules
        ],
    }

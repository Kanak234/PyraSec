# PyraSec

[![CI](https://github.com/Kanak234/PyraSec/actions/workflows/ci.yml/badge.svg)](https://github.com/Kanak234/PyraSec/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Kanak234/PyraSec/actions/workflows/codeql.yml/badge.svg)](https://github.com/Kanak234/PyraSec/actions/workflows/codeql.yml)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

**Visualize. Detect. Secure.**


A project security scanner that walks your file architecture, applies deterministic rules, renders the result as a 3D pyramid, and tells you exactly what to fix — in that order.

Built by **Team CipherStack** for **HackLabify V1.0**, Security Track, Master's Union, Gurugram, 1–2 August 2026.

```
Scan  →  Detect  →  Visualize  →  Fix
```

---

## The one design constraint

**No AI. No ML. No LLM. No chatbot anywhere in the detection path.**

Every finding comes from a rule you can open and read. That is not a limitation being worked around — it is the property that makes the rest of the tool possible:

| Property | Why it needs determinism |
|---|---|
| **Cacheable** | A cached result is only safe if re-running would produce the same answer. |
| **Diffable** | "3 new findings since last commit" requires runs to be comparable. |
| **Merge-blockable** | You cannot gate a merge on a check that might answer differently on retry. |
| **Auditable** | A compliance auditor can read the rule that produced the finding. |
| **Air-gapped** | No API key, no token spend, no network egress from your source tree. |

A scanner that phones a model to decide whether `AKIA...` is a credential is slower, costs money per scan, leaks your source to a third party, and can answer differently on Tuesday. `SEC001` is a regex plus an entropy floor plus a placeholder filter, and it is right every time.

---

## Quick start

Python 3.10+. No dependencies to install for the scanner, CLI or reports.

```bash
python3 -m pyrasec scan /path/to/project          # human-readable table
python3 -m pyrasec scan . -f html -o report.html  # self-contained report
python3 -m pyrasec fix .                          # ranked fix list
python3 -m pyrasec score . --explain              # the arithmetic behind the number
python3 -m pyrasec rules                          # all 65 rules
```

Try it against the deliberately-broken sample project:

```bash
python3 tests/make_fixture.py /tmp/vulnerable-app
python3 -m pyrasec scan /tmp/vulnerable-app
# 71 findings across 21 files in 0.018s — score 0/100 (F)
```

---

## Architecture

```
pyrasec/
├── core/
│   ├── models.py       Finding, Severity, FileRecord, ScanResult, central scrubbing
│   └── walker.py       iterative FS walk, .gitignore, binary detection, hashing
├── rules/
│   ├── base.py         PathRule / ContentRule / ProjectRule + registry
│   ├── secrets.py      SEC001-006   provider tokens, entropy, private keys, PANs
│   ├── filesystem.py   FS001-020    permissions, leftovers, risky placement
│   ├── gitops.py       GIT001-004   .git exposure, .gitignore coverage
│   ├── containers.py   DOC001-014   Dockerfile + Compose
│   ├── iac.py          K8S/TF       Kubernetes manifests + Terraform
│   ├── webserver.py    WEB001-024   nginx + Apache
│   └── dependencies.py DEP001-004   manifests, lockfiles, SBOM extraction
├── engine/
│   ├── scanner.py      orchestration, threading, suppressions
│   ├── scoring.py      the 0-100 model and fix prioritisation
│   └── cache.py        incremental cache keyed on content hash
├── viz/pyramid.py      pyramid, folder tree, heatmap, attack surface
├── report/
│   ├── sarif.py        SARIF 2.1.0 for GitHub code scanning
│   └── html.py         self-contained HTML with offline SVG pyramid
├── cli.py              scan / score / fix / sbom / pyramid / rules / hook
└── service.py          FastAPI wrapper (optional dependency)
```

Three rule kinds, because three different things need three different inputs:

- **`PathRule`** — sees file metadata only (name, mode, size). Runs on everything, including binaries. Cheap.
- **`ContentRule`** — sees decoded text. The scanner reads each file **once** and fans it out to every interested rule; a naive design where each rule opens the file turns a 30-rule scan into 30 passes over the disk.
- **`ProjectRule`** — sees the whole file list. For things defined by *absence* (no `.gitignore`) or by *relationship* (a `.env` inside `public/`).

Adding a detection means adding a module to `rules/` and importing it in `rules/__init__.py`. Nothing else changes.

---

## The score

```
penalty  = Σ (severity_weight × confidence)
density  = penalty / (1 + log₁₀(files))
score    = 100 × e^(−density / 12)
```

Four properties this guarantees, each chosen over a simpler model that fails one of them:

1. **Bounded** — always in [0, 100]. A subtractive model goes negative on a messy repo, and then "0" stops meaning anything.
2. **Monotonic** — fixing a finding can never lower the score; adding one can never raise it.
3. **Size-fair** — ten findings in a 20-file project is a worse posture than ten in a 5,000-file monorepo.
4. **Explainable** — `pyrasec score --explain` prints every intermediate value. A score nobody can reconstruct is a score nobody trusts.

Exponential decay gives steep early feedback (the first critical fix moves the number a lot) with a long tail (200 issues and 400 issues are not both exactly zero).

`pyrasec fix` groups findings into **fix actions** — one `(rule, file)` pair is one thing a developer does. Six `SEC002` hits in `settings.py` are one action, not six. Ranking ungrouped findings gives you a top-ten list that is all the same file.

---

## False positives are the real problem

A scanner that flags `password = "your-password-here"` gets muted, and a muted scanner catches nothing. Three filter layers, all deterministic:

- **Placeholder detection** — `changeme`, `${VAR}`, `<your-key>`, `process.env.X`, repeated characters.
- **Entropy floor** — Shannon entropy per character, tuned separately for hex, base64 and mixed charsets. Reproducible with a calculator.
- **Test-path discount** — fixtures legitimately contain fake credentials, so `tests/` and `fixtures/` hits drop to MEDIUM at reduced confidence rather than screaming CRITICAL.

Where a filter is wrong, suppress explicitly:

```python
API_KEY = "documented-test-key-here"   # pyrasec:ignore SEC002
# pyrasec:ignore-next-line SEC001
# pyrasec:ignore-file SEC004
```

A bare `# pyrasec:ignore` with no rule id **does not work**, deliberately. Blanket suppressions are how a scanner quietly stops working.

---

## The scanner does not leak the thing it found

Evidence is masked at detection *and* scrubbed centrally in `Rule.finding()` before it reaches any report. The regression test scans a tree of known secrets and greps the JSON, SARIF and HTML output for the plaintext.

This test caught a real bug during development: `SEC001` masked its `evidence` field correctly but passed the raw source line through `metadata["context"]`. Every format leaked the key. The central scrub is the fix, and the belt-and-braces design is why a single forgotten redaction is now a non-event.

---

## DevSecOps

**Pre-commit** — blocks a commit that introduces high or critical findings:

```bash
python3 -m pyrasec hook install .
```

**GitHub Actions** — `.github/workflows/pyrasec.yml` ships with three jobs: a fast PR gate that fails on high/critical, a full scan that uploads SARIF so findings annotate the diff inline, and the test suite.

**Exit codes** are the CI contract: `0` clean, `1` findings at or above `--fail-on`, `2` the scan could not run.

**SARIF** carries `partialFingerprints`, so GitHub tracks a finding across commits and a developer sees "1 new" instead of "47 findings" on every push.

---

## API

```bash
pip install "fastapi[standard]"
uvicorn pyrasec.service:app --reload
```

| Endpoint | Returns |
|---|---|
| `POST /api/v1/scan` | findings + score + pyramid + heatmap + attack surface |
| `POST /api/v1/score` | the number and its full breakdown |
| `POST /api/v1/pyramid` | visualisation payloads for the Three.js frontend |
| `POST /api/v1/sbom` | CycloneDX 1.5 |
| `POST /api/v1/sarif` | SARIF 2.1.0 |
| `POST /api/v1/report` | self-contained HTML |
| `GET /api/v1/rules` | the rule catalogue |

The API contains **no detection logic** — it calls the same `Scanner` the CLI does. The moment those two can disagree about what a finding is, you have two products to keep in sync and one of them is always wrong.

`PYRASEC_ALLOWED_ROOTS` confines scans to configured directories. It is not optional: an endpoint that takes a path from a request is a directory-traversal engine if you let it. **There is no authentication yet** — do not expose this beyond localhost.

---

## The pyramid

`viz/pyramid.py` emits pure data — coordinates, colours, counts. No WebGL, no browser assumptions. The Three.js frontend and the offline HTML report consume the same payload, so they always agree.

- **Folders become layers, files become blocks**, as in the pitch deck.
- **Altitude is inverted directory depth** — the project root is the apex, and each level of nesting widens the layer below it. That is what makes the shape come out as a pyramid instead of a top-heavy mushroom: real trees have a handful of files at the root and more in every level beneath.
- **Colour is the worst finding on that file** — red / amber / green, straight from the deck's palette.
- **Block volume is log-scaled file size**, so one vendored bundle doesn't dwarf every source file.
- Blocks sit on a ring per layer so every one stays clickable from outside; a solid grid buries the interior.

The same structure projects into the folder tree, treemap, sunburst and risk heatmap, which is why a folder's colour is consistent across all of them.

---

## What this does not do yet

Being straight about this matters more than a longer feature list — the fastest way to lose a security demo is to claim something a judge can disprove in one question.

- **No CVE lookup.** Manifests are parsed and a real CycloneDX SBOM is produced, but nothing here tells you a package has a known vulnerability. That needs a vulnerability database, and shipping a stale copy of one is worse than shipping none. The `purl` identifiers in the SBOM are the exact keys OSV takes — `pyrasec db import <osv-dump>` is the next milestone.
- **No dataflow analysis.** These are pattern, metadata and structure rules. Real taint tracking (source → sink across function boundaries) needs an AST and a call graph. That is what Semgrep and CodeQL do, and it is a different tool.
- **No authentication.** OAuth, passkeys, WebAuthn, TOTP, RBAC, org accounts — none of it exists. `service.py` has a path allowlist and nothing else.
- **No persistence, no scheduler, no multi-tenancy.** No PostgreSQL, no Redis, no Celery. Scans are stateless and synchronous.
- **No PDF or Excel reports.** JSON, SARIF, HTML and CSV work today.
- **Compliance mapping is partial.** Every rule carries CWE, OWASP Top 10 and (mostly) MITRE ATT&CK identifiers. NIST, ISO 27001, SOC 2, PCI DSS, HIPAA and GDPR control mappings are not built — the finding metadata is the right shape to carry them, which is the groundwork, not the feature.

Roughly: this repo is the **Scan → Detect → Visualize → Fix** loop, working end to end and tested. The enterprise platform around it is a roadmap.

---

## Tests

```bash
python3 tests/test_pyrasec.py      # 45 tests
```

The tests that matter most for a scanner are the negative ones: no false positive on a placeholder, no crash on malformed YAML or truncated JSON, identical results at 1 worker and 8 workers, and no secret surviving into any output format.

---

## Rules

65 registered. `python3 -m pyrasec rules` lists them; `--json` gives the full catalogue with remediation.

| Prefix | Area | Count |
|---|---|---|
| `SEC` | Hardcoded secrets, private keys, entropy, payment card data | 6 |
| `FS` | Permissions, setuid, leftovers, dumps, risky placement | 8 |
| `GIT` | `.git` exposure, `.gitignore` coverage, unignored `.env` | 4 |
| `DOC` | Dockerfile and Compose | 14 |
| `K8S` | Kubernetes pod security | 10 |
| `TF` | Terraform / cloud misconfiguration | 8 |
| `WEB` | nginx and Apache | 11 |
| `DEP` | Dependency pinning, lockfiles, registry transport | 4 |

Every rule carries a CWE, an OWASP Top 10 category, a CVSS band, and remediation with concrete steps and a working example — enforced by a test, so an incomplete rule fails CI.

---

MIT. Team CipherStack · [github.com/Kanak234](https://github.com/Kanak234)

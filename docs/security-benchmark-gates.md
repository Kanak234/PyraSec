# PyraSec vs Shipys: reproducible security benchmark (draft)

Status: SPECIFICATION ONLY. No scanner executions or pass claims.

## Scope and ground truth
Use a synthetic, isolated repository with **no real credentials**, no running vulnerable service, and no external network by default. Pin both scanner versions, OS, CPU, dependency databases and timestamps. Keep the benchmark fixture independent from both scanners.

Create `benchmark/cases.json` with one record per vulnerability instance: unique ID, file path, line span, category, CWE, severity, expected detector outcome, and notes. The prior comparison's "17 vulnerabilities" is a historical label, **not a validated count**. Reconcile actual cases and expected positives before publishing any denominator.

Required positive families:
- AWS, Stripe, Supabase and OpenAI synthetic credentials
- Missing .gitignore / exposed .env
- SQL injection, command injection, unsafe eval
- CORS wildcard with credentials
- React dangerouslySetInnerHTML with untrusted input
- Firebase allow read/write if true
- Supabase USING (true) policy and disabled RLS
- Docker root and floating latest tag
- Known vulnerable dependency version, with a pinned advisory snapshot

Required negative controls:
- Parameterized SQL, safely escaped output, strict CORS allowlist
- Environment-based credentials and documented placeholders
- Secure Firebase and Supabase policies, enabled RLS
- Non-root Docker image with digest pinning
- Dependency version outside advisory range
- Comments, strings, fixtures and intentionally suppressed findings

## Execution protocol
1. Record scanner version/commit and SHA256 of every executable; verify downloaded binaries before running. Do not run remote install scripts blindly.
2. Run both scanners against the exact same fixture commit and identical file tree. Record each enabled engine and whether network-dependent checks actually ran.
3. Run online and offline trials separately. Record missing tools, timeouts, parse failures and skipped files as **incomplete**, not as a clean scan or a false negative.
4. Save raw JSON/SARIF/terminal output, exit status, wall-clock duration, and environment manifest.
5. Normalize findings to (case ID, file, location, CWE/category). Manually adjudicate uncertain mappings without changing the ground truth post hoc.
6. Repeat timed trials five times after a warmup; report median and spread. Do not compare runs on different machines as equivalent.

## Metrics
- Recall = TP / (TP + FN), over executable positive cases.
- Precision = TP / (TP + FP); report undefined if no findings.
- F1 = 2 * precision * recall / (precision + recall), if defined.
- False-positive count on negative controls.
- Engine availability / coverage and skipped-case count.
- Median scan time; CPU and memory if measured.
- Secret redaction: no raw synthetic token may appear in any output.

Do not declare an overall winner from a single metric or a run with missing engines.

## Release gates (proposed, not passed)
- G1: every ground-truth case has a stable ID and independent expected result.
- G2: every new detection has positive, negative, and adversarial tests.
- G3: all known critical benchmark cases are detected; no blanket claim about unknown vulnerabilities.
- G4: no plaintext credential leaks through JSON, SARIF, HTML, logs, or errors.
- G5: unavailable engines produce an explicit incomplete state and non-success CI outcome when required.
- G6: findings are deterministic across repeated runs and worker counts.
- G7: JSON/SARIF/CLI represent the same normalized findings.
- G8: tests, security review, and CI checks must pass before release.

## Implementation order
1. Freeze fixture and baseline current PyraSec output.
2. Add narrowly scoped injection/XSS/CORS/Firebase/Supabase rules with negative tests.
3. Add OSV-backed dependency scanning with explicit advisory freshness and offline behavior.
4. Evaluate AST/data-flow analysis separately; do not promise that regex-only rules prove exploitability.
5. Compare the released Shipys binary in a sandbox and publish reproducible raw results.

No production repository files should be overwritten, no default-branch push, and no automatic merge.

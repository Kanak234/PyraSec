"""Create an isolated 17-case synthetic benchmark and run PyraSec against it.

No real credentials, network requests, or vulnerable services are used.
Run: python3 tests/security_benchmark.py
Optional: python3 tests/security_benchmark.py --keep-fixture /tmp/pyrasec-benchmark
Exit code 0 means the harness ran, NOT that the scanner detected all cases.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Each case has a unique file or explicit location. This is synthetic ground truth,
# not an assertion that a scanner can establish exploitability.
CASES = [
    ("AWS", "src/aws.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'),
    ("STRIPE", "src/stripe.py", 'STRIPE_KEY = "sk_live_51H8xQ2KpZ9mNvBcXwErTyUiOpAsDfGhJ"\n'),
    ("SUPABASE_KEY", "src/supabase_key.py", 'SUPABASE_SERVICE_ROLE_KEY = "eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"\n'),
    ("OPENAI_KEY", "src/openai.py", 'OPENAI_API_KEY = "sk-proj-A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0U1v2W3x4Y5z6"\n'),
    ("MISSING_GITIGNORE", "README.md", "# Synthetic benchmark: deliberately no .gitignore\n"),
    ("EXPOSED_ENV", "public/.env", "PUBLIC_SECRET=synthetic-only-not-a-real-secret\n"),
    ("SQL_INJECTION", "src/sql.py", 'def lookup(db, user):\n    return db.execute("SELECT * FROM users WHERE id = " + user)\n'),
    ("SHELL_INJECTION", "src/shell.py", 'import os\ndef run(user):\n    os.system("echo " + user)\n'),
    ("EVAL", "src/eval.py", 'def run(user):\n    return eval(user)\n'),
    ("CORS", "src/cors.js", 'app.use(cors({origin: "*", credentials: true}));\n'),
    ("XSS", "src/xss.jsx", 'export default function View({input}) { return <div dangerouslySetInnerHTML={{__html: input}} />; }\n'),
    ("FIREBASE_OPEN", "firebase.rules", 'service cloud.firestore { match /databases/{database}/documents { match /{document=**} { allow read, write: if true; } } }\n'),
    ("SUPABASE_POLICY", "supabase/policy.sql", 'CREATE POLICY "open" ON public.todos FOR ALL USING (true);\n'),
    ("SUPABASE_RLS", "supabase/rls.sql", 'ALTER TABLE public.todos DISABLE ROW LEVEL SECURITY;\n'),
    ("DOCKER_ROOT", "Dockerfile", 'FROM node:latest\nUSER root\nCMD ["node", "index.js"]\n'),
    ("DOCKER_LATEST", "Dockerfile", 'FROM node:latest\nUSER root\nCMD ["node", "index.js"]\n'),
    ("VULNERABLE_LODASH", "package.json", '{"name":"synthetic-security-benchmark","version":"1.0.0","dependencies":{"lodash":"4.17.11"}}\n'),
]

# Category-level matching is deliberately deferred to adjudication: a finding
# somewhere in a file does not prove it detected the intended vulnerability.
def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--keep-fixture", type=Path, help="Use an empty existing directory or a new path")
    args = parser.parse_args()
    if len(CASES) != 17 or len({c[0] for c in CASES}) != 17:
        raise RuntimeError("Ground truth must contain exactly 17 unique cases")
    if args.keep_fixture:
        target = args.keep_fixture.resolve()
        if target.exists() and any(target.iterdir()):
            parser.error("--keep-fixture must be an empty directory; refusing overwrite")
        target.mkdir(parents=True, exist_ok=True)
        cleanup = None
    else:
        cleanup = tempfile.TemporaryDirectory(prefix="pyrasec-benchmark-")
        target = Path(cleanup.name)
    try:
        for _, rel, data in CASES:
            dest = target / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            if dest.exists():
                if dest.read_text(encoding="utf-8") != data:
                    raise RuntimeError(f"Conflicting fixture contents: {rel}")
                continue
            dest.write_text(data, encoding="utf-8")
        cmd = [sys.executable, "-m", "pyrasec", "scan", str(target), "--no-cache", "-f", "json"]
        proc = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, timeout=90)
        output = {"schema": 1, "fixture_cases": [{"id": ident, "path": path, "status": "not_adjudicated"} for ident, path, _ in CASES],
                  "scanner": "PyraSec", "exit_code": proc.returncode, "complete": False}
        try:
            report = json.loads(proc.stdout)
            output["finding_count"] = len(report.get("findings", []))
            output["rule_ids"] = sorted({f.get("rule_id", "") for f in report.get("findings", [])})
            output["complete"] = proc.returncode in (0, 1)
        except (ValueError, TypeError, AttributeError):
            output["error"] = "Scanner did not return valid JSON"
            output["stderr_tail"] = proc.stderr[-1000:]
        print(json.dumps(output, indent=2))
        return 0 if output["complete"] else 2
    finally:
        if cleanup:
            cleanup.cleanup()


if __name__ == "__main__":
    raise SystemExit(main())

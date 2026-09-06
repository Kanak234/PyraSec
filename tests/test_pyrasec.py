"""PyraSec test suite.

Run with: python3 -m pytest tests/ -q   (or `python3 tests/test_pyrasec.py`)

The tests that matter most for a security scanner are the ones asserting what
it does *not* do: no false positive on a placeholder, no crash on a malformed
file, no non-determinism between runs. A missed detection is a bug; a noisy
detection is a bug that gets the whole tool switched off.
"""

from __future__ import annotations

import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pyrasec import Severity, build_folder_tree, build_pyramid, scan  # noqa: E402
from pyrasec.engine.scanner import Scanner, collect_sbom  # noqa: E402
from pyrasec.engine.scoring import compute_score, grade_for, prioritise  # noqa: E402
from pyrasec.report.html import render_html  # noqa: E402
from pyrasec.report.sarif import build_sarif  # noqa: E402
from pyrasec.rules.base import all_rules  # noqa: E402
from pyrasec.rules.secrets import (  # noqa: E402
    is_high_entropy, looks_like_placeholder, luhn_valid, shannon_entropy,
)


class TempProject:
    """Context manager that builds a throwaway tree from a dict."""

    def __init__(self, files: dict[str, str], modes: dict[str, int] | None = None):
        self.files = files
        self.modes = modes or {}
        self.root = ""

    def __enter__(self) -> str:
        self.root = tempfile.mkdtemp(prefix="pyrasec-test-")
        for rel, content in self.files.items():
            path = Path(self.root) / rel
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        for rel, mode in self.modes.items():
            os.chmod(Path(self.root) / rel, mode)
        return self.root

    def __exit__(self, *exc) -> None:
        shutil.rmtree(self.root, ignore_errors=True)


def rule_ids(result) -> set[str]:
    return {f.rule_id for f in result.findings}


# --------------------------------------------------------------------------


class TestFilters(unittest.TestCase):
    """The false-positive suppression layer. Tested first because it is what
    keeps every other rule usable."""

    def test_placeholders_are_rejected(self):
        for value in [
            "changeme", "your_api_key", "${DB_PASSWORD}", "<your-key-here>",
            "xxxxxxxxxxxx", "process.env.SECRET", "$STRIPE_KEY", "aaaaaaaaaaaa",
            "{{ vault_password }}", "%APPDATA%",
        ]:
            self.assertTrue(looks_like_placeholder(value), f"should reject: {value}")

    def test_real_looking_secrets_are_not_rejected(self):
        for value in [
            "sk_live_51H8xQ2KpZ9mNvBcXwErTyUiOp",
            "P@ssw0rd-Pr0duct10n-2024",
            "8f3d9a1c7b2e5f4a6d8c0b3e7f1a9d2c",
        ]:
            self.assertFalse(looks_like_placeholder(value), f"should keep: {value}")

    def test_entropy_ordering(self):
        self.assertGreater(
            shannon_entropy("kJ8#mQ2$vN9@pL4&xT7"),
            shannon_entropy("aaaaaaaaaaaaaaaaaaa"),
        )

    def test_entropy_floor(self):
        self.assertFalse(is_high_entropy("short"))
        self.assertFalse(is_high_entropy("aaaaaaaaaaaaaaaaaaaaaaaa"))
        self.assertTrue(is_high_entropy("kJ8mQ2vN9pL4xT7bR3wZ6yH1"))

    def test_luhn(self):
        self.assertTrue(luhn_valid("4111111111111111"))
        self.assertFalse(luhn_valid("4111111111111112"))


class TestSecretRules(unittest.TestCase):
    def test_detects_aws_key(self):
        with TempProject({"config.py": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'}) as root:
            result = scan(root, use_cache=False)
            self.assertIn("SEC001", rule_ids(result))

    def test_detects_private_key(self):
        content = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----\n"
        with TempProject({"certs/server.pem": content}) as root:
            result = scan(root, use_cache=False)
            self.assertIn("SEC003", rule_ids(result))

    def test_ignores_env_var_reads(self):
        clean = (
            "import os\n"
            'API_KEY = os.environ["API_KEY"]\n'
            'DB_PASSWORD = os.getenv("DB_PASSWORD", "")\n'
            'SECRET_KEY = "${SECRET_KEY}"\n'
        )
        with TempProject({"settings.py": clean}) as root:
            result = scan(root, use_cache=False)
            secret_findings = [f for f in result.findings if f.rule_id.startswith("SEC")]
            self.assertEqual(secret_findings, [], f"false positives: {secret_findings}")

    def test_evidence_is_redacted(self):
        secret = "sk_live_51H8xQ2KpZ9mNvBcXwErTyUiOpAsDfGhJ"
        with TempProject({"pay.py": f'STRIPE = "{secret}"\n'}) as root:
            result = scan(root, use_cache=False)
            self.assertTrue(result.findings)
            for finding in result.findings:
                self.assertNotIn(secret, finding.evidence)
                self.assertNotIn(secret, json.dumps(finding.to_dict()))

    def test_no_secret_survives_into_any_report(self):
        """End-to-end: scan a tree of known secrets, then grep every output
        format for the plaintext. This is the regression test for the class of
        bug where a rule redacts `evidence` but leaks through `metadata`."""
        secrets = {
            "conf.tf": 'password = "TerraformPlaintextPassword99"\n',
            "app.py": 'DB_PASSWORD = "P@ssw0rd-Pr0duct10n-2024"\n',
            "pay.js": 'const k = "sk_live_51H8xQ2KpZ9mNvBcXwErTyUiOpAsDfGhJ";\n',
            "deploy.sh": 'TOKEN="ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"\n',
            ".env": "DATABASE_URL=postgres://u:hunter2wasnevergood@db:5432/prod\n",
        }
        plaintext = [
            "TerraformPlaintextPassword99", "P@ssw0rd-Pr0duct10n-2024",
            "sk_live_51H8xQ2KpZ9mNvBcXwErTyUiOpAsDfGhJ",
            "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", "hunter2wasnevergood",
        ]
        with TempProject(secrets) as root:
            result = scan(root, use_cache=False)
            outputs = {
                "json": json.dumps(result.to_dict()),
                "sarif": json.dumps(build_sarif(result)),
                "html": render_html(result),
            }
        self.assertTrue(result.findings, "fixture should produce findings")
        for name, blob in outputs.items():
            for secret in plaintext:
                self.assertNotIn(secret, blob, f"{name} report leaked {secret[:10]}…")

    def test_test_paths_get_lower_severity(self):
        payload = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        with TempProject({"src/config.py": payload}) as root:
            prod = scan(root, use_cache=False)
        with TempProject({"tests/test_config.py": payload}) as root:
            test = scan(root, use_cache=False)
        prod_worst = min(f.severity.rank for f in prod.findings)
        test_worst = min(f.severity.rank for f in test.findings)
        self.assertLess(prod_worst, test_worst, "test fixtures should score lower")


class TestFilesystemRules(unittest.TestCase):
    def test_world_writable(self):
        with TempProject({"data.txt": "x\n"}, {"data.txt": 0o666}) as root:
            result = scan(root, use_cache=False)
            self.assertIn("FS001", rule_ids(result))

    def test_backup_file(self):
        with TempProject({"config.php.bak": "<?php $db='x';\n"}) as root:
            result = scan(root, use_cache=False)
            self.assertIn("FS010", rule_ids(result))

    def test_sensitive_file_in_public_dir(self):
        with TempProject({"public/.env": "KEY=value123456\n"}) as root:
            result = scan(root, use_cache=False)
            self.assertIn("FS020", rule_ids(result))
            finding = next(f for f in result.findings if f.rule_id == "FS020")
            self.assertEqual(finding.severity, Severity.CRITICAL)

    def test_clean_project_has_no_filesystem_findings(self):
        with TempProject({
            "src/main.py": "def main():\n    print('hello')\n",
            "README.md": "# Project\n",
        }, {"src/main.py": 0o644}) as root:
            result = scan(root, use_cache=False)
            self.assertEqual(rule_ids(result) & {"FS001", "FS002", "FS010", "FS020"}, set())


class TestInfraRules(unittest.TestCase):
    def test_dockerfile_root_and_latest(self):
        content = "FROM node:latest\nCOPY . .\nCMD [\"node\", \"s.js\"]\n"
        with TempProject({"Dockerfile": content}) as root:
            found = rule_ids(scan(root, use_cache=False))
            self.assertIn("DOC001", found)
            self.assertIn("DOC002", found)

    def test_dockerfile_with_nonroot_user_passes(self):
        content = (
            "FROM node:20-slim@sha256:abc123\n"
            "RUN adduser --system app\n"
            "USER app\n"
            'CMD ["node", "s.js"]\n'
        )
        with TempProject({"Dockerfile": content}) as root:
            found = rule_ids(scan(root, use_cache=False))
            self.assertNotIn("DOC001", found)
            self.assertNotIn("DOC002", found)

    def test_compose_privileged(self):
        content = "services:\n  app:\n    privileged: true\n"
        with TempProject({"docker-compose.yml": content}) as root:
            self.assertIn("DOC010", rule_ids(scan(root, use_cache=False)))

    def test_kubernetes_privileged_pod(self):
        content = (
            "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n"
            "    - name: app\n      securityContext:\n        privileged: true\n"
        )
        with TempProject({"pod.yaml": content}) as root:
            self.assertIn("K8S001", rule_ids(scan(root, use_cache=False)))

    def test_non_k8s_yaml_is_not_flagged(self):
        with TempProject({"ci.yml": "steps:\n  - run: echo hi\n"}) as root:
            self.assertNotIn("K8S001", rule_ids(scan(root, use_cache=False)))

    def test_terraform_open_security_group(self):
        content = 'resource "aws_security_group" "x" {\n  cidr_blocks = ["0.0.0.0/0"]\n}\n'
        with TempProject({"main.tf": content}) as root:
            self.assertIn("TF001", rule_ids(scan(root, use_cache=False)))


class TestScoring(unittest.TestCase):
    def test_bounds(self):
        with TempProject({"a.py": "x = 1\n"}) as root:
            clean = scan(root, use_cache=False)
        self.assertGreaterEqual(clean.score, 0.0)
        self.assertLessEqual(clean.score, 100.0)

    def test_monotonic_more_findings_never_scores_higher(self):
        one = 'AWS = "AKIAIOSFODNN7EXAMPLE"\n'
        with TempProject({"a.py": one}) as root:
            single = scan(root, use_cache=False)
        with TempProject({"a.py": one, "b.py": one, "c.py": one}) as root:
            triple = scan(root, use_cache=False)
        self.assertLessEqual(triple.score, single.score)

    def test_clean_project_scores_high(self):
        with TempProject({
            "src/app.py": "import os\nKEY = os.environ['KEY']\n",
            "README.md": "# hello\n",
            ".gitignore": ".env\n*.pem\n",
        }) as root:
            result = scan(root, use_cache=False)
        self.assertGreaterEqual(result.score, 90.0, f"findings: {rule_ids(result)}")

    def test_grades_are_ordered(self):
        self.assertEqual(grade_for(100), "A+")
        self.assertEqual(grade_for(0), "F")
        self.assertEqual(grade_for(77), "B")

    def test_size_fairness(self):
        """Same finding count is worse in a small project than a large one."""
        secret = 'AWS = "AKIAIOSFODNN7EXAMPLE"\n'
        small = {"a.py": secret}
        large = {"a.py": secret}
        large.update({f"pkg/mod{i}.py": "x = 1\n" for i in range(60)})
        with TempProject(small) as root:
            small_score = scan(root, use_cache=False).score
        with TempProject(large) as root:
            large_score = scan(root, use_cache=False).score
        self.assertGreater(large_score, small_score)

    def test_prioritise_groups_by_action(self):
        content = (
            'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
            'GH = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"\n'
        )
        with TempProject({"settings.py": content}) as root:
            result = scan(root, use_cache=False)
            ranked = prioritise(result.findings, result.stats.files_scanned)
        self.assertTrue(ranked)
        self.assertTrue(all("occurrences" in item for item in ranked))
        penalties = [item["penalty_removed"] for item in ranked]
        self.assertEqual(penalties, sorted(penalties, reverse=True))


class TestDeterminism(unittest.TestCase):
    def test_identical_across_runs(self):
        files = {
            "app/settings.py": 'KEY = "AKIAIOSFODNN7EXAMPLE"\n',
            "Dockerfile": "FROM python:latest\nCOPY . .\n",
            "public/.env": "SECRET=abcdef123456\n",
        }
        with TempProject(files) as root:
            first = scan(root, use_cache=False)
            second = scan(root, use_cache=False)
        self.assertEqual(
            [f.fingerprint for f in first.sorted_findings()],
            [f.fingerprint for f in second.sorted_findings()],
        )
        self.assertEqual(first.score, second.score)

    def test_worker_count_does_not_change_results(self):
        files = {f"mod{i}.py": f'KEY{i} = "AKIAIOSFODNN7EXAMPL{i}"\n' for i in range(12)}
        with TempProject(files) as root:
            serial = Scanner(root, workers=1, use_cache=False).scan()
            parallel = Scanner(root, workers=8, use_cache=False).scan()
        self.assertEqual(
            [f.fingerprint for f in serial.sorted_findings()],
            [f.fingerprint for f in parallel.sorted_findings()],
        )


class TestSuppression(unittest.TestCase):
    def test_inline_suppression(self):
        content = 'AWS = "AKIAIOSFODNN7EXAMPLE"  # pyrasec:ignore SEC001,SEC002\n'
        with TempProject({"a.py": content}) as root:
            found = rule_ids(scan(root, use_cache=False))
        self.assertNotIn("SEC001", found)

    def test_bare_ignore_is_not_honoured(self):
        content = 'AWS = "AKIAIOSFODNN7EXAMPLE"  # pyrasec:ignore\n'
        with TempProject({"a.py": content}) as root:
            found = rule_ids(scan(root, use_cache=False))
        self.assertIn("SEC001", found, "a wildcard suppression must not work")


class TestRobustness(unittest.TestCase):
    def test_empty_directory(self):
        root = tempfile.mkdtemp(prefix="pyrasec-empty-")
        try:
            result = scan(root, use_cache=False)
            self.assertEqual(result.findings, [])
            self.assertEqual(result.score, 100.0)
            build_pyramid(result)  # must not raise
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_malformed_files_do_not_crash(self):
        files = {
            "package.json": "{ this is not valid json",
            "broken.yaml": "apiVersion: v1\nkind: [[[unclosed\n",
            "weird.tf": 'resource "x" {{{{ \n',
            "empty.py": "",
        }
        with TempProject(files) as root:
            result = scan(root, use_cache=False)
        self.assertIsNotNone(result)

    def test_binary_files_are_skipped(self):
        root = tempfile.mkdtemp(prefix="pyrasec-bin-")
        try:
            Path(root, "blob.bin").write_bytes(b"\x00\x01\x02" * 5000)
            result = scan(root, use_cache=False)
            self.assertFalse([f for f in result.findings if f.path == "blob.bin" and f.line])
        finally:
            shutil.rmtree(root, ignore_errors=True)

    def test_missing_root_raises(self):
        with self.assertRaises(FileNotFoundError):
            scan("/nonexistent/path/definitely-not-here", use_cache=False)


class TestReports(unittest.TestCase):
    FILES = {
        "app/settings.py": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
        "Dockerfile": "FROM node:latest\nCOPY . .\n",
        "requirements.txt": "requests\nfastapi>=0.100\n",
    }

    def test_sarif_shape(self):
        with TempProject(self.FILES) as root:
            result = scan(root, use_cache=False)
            sarif = build_sarif(result)
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "PyraSec")
        self.assertEqual(len(run["results"]), len(result.findings))
        for entry in run["results"]:
            self.assertIn(entry["level"], {"error", "warning", "note", "none"})
            self.assertIn("partialFingerprints", entry)
        reported = {r["id"] for r in run["tool"]["driver"]["rules"]}
        self.assertEqual(reported, {f.rule_id for f in result.findings})

    def test_json_is_serialisable(self):
        with TempProject(self.FILES) as root:
            result = scan(root, use_cache=False)
        json.dumps(result.to_dict())  # must not raise

    def test_html_is_self_contained(self):
        with TempProject(self.FILES) as root:
            result = scan(root, use_cache=False)
            page = render_html(result, compute_score(result.findings, result.stats.files_scanned))
        self.assertIn("<svg class=\"pyramid\"", page)
        for external in ("http://", "https://cdn", "<script src"):
            self.assertNotIn(external, page, f"report must not reference {external}")

    def test_sbom_shape(self):
        with TempProject(self.FILES) as root:
            result = scan(root, use_cache=False)
            sbom = collect_sbom(result)
        self.assertEqual(sbom["bomFormat"], "CycloneDX")
        self.assertTrue(sbom["components"])
        for component in sbom["components"]:
            self.assertTrue(component["purl"].startswith("pkg:"))


class TestVisualisation(unittest.TestCase):
    def test_pyramid_tapers_upward(self):
        files = {"root.py": "x=1\n"}
        files.update({f"a/f{i}.py": "x=1\n" for i in range(4)})
        files.update({f"a/b/f{i}.py": "x=1\n" for i in range(9)})
        with TempProject(files) as root:
            pyramid = build_pyramid(scan(root, use_cache=False))
        widths = [layer["width"] for layer in pyramid["layers"]]
        self.assertEqual(widths, sorted(widths, reverse=True), "base must be widest")
        self.assertEqual(pyramid["layers"][0]["depth"], 2, "deepest nesting at the base")
        self.assertEqual(pyramid["layers"][-1]["depth"], 0, "project root at the apex")

    def test_block_colour_matches_worst_finding(self):
        with TempProject({"public/.env": "SECRET=abcdef1234567\n"}) as root:
            result = scan(root, use_cache=False)
            pyramid = build_pyramid(result)
        block = next(b for b in pyramid["blocks"] if b["path"] == "public/.env")
        self.assertEqual(block["band"], "critical")

    def test_folder_tree_rolls_up_findings(self):
        with TempProject({"deep/nested/config.py": 'KEY = "AKIAIOSFODNN7EXAMPLE"\n'}) as root:
            tree = build_folder_tree(scan(root, use_cache=False))
        self.assertGreater(tree["findings"], 0, "root must aggregate nested findings")


class TestRuleQuality(unittest.TestCase):
    """Every rule must be usable, not just registered."""

    def test_every_rule_has_complete_metadata(self):
        for rule in all_rules():
            with self.subTest(rule=rule.id):
                self.assertTrue(rule.title.strip())
                self.assertTrue(rule.description.strip())
                self.assertTrue(rule.remediation.summary.strip())
                self.assertTrue(rule.remediation.steps, "needs actionable steps")
                self.assertIsNotNone(rule.owasp, "needs an OWASP mapping")
                self.assertTrue(0.0 < rule.confidence <= 1.0)

    def test_rule_ids_are_unique(self):
        ids = [rule.id for rule in all_rules()]
        self.assertEqual(len(ids), len(set(ids)))

    def test_fast_profile_is_a_subset(self):
        from pyrasec.rules.base import rules_for_profile
        fast = {r.id for r in rules_for_profile("fast")}
        every = {r.id for r in all_rules()}
        self.assertTrue(fast <= every)
        self.assertTrue(fast, "fast profile must not be empty")


if __name__ == "__main__":
    unittest.main(verbosity=2)

import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pyrasec import cli


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()

        # Create basic sample files
        (self.root / "app.py").write_text("import os\nprint('hello')\n", encoding="utf-8")
        (self.root / "config.json").write_text('{"debug": true}\n', encoding="utf-8")

    def tearDown(self):
        self.temp_dir.cleanup()

    def run_cli(self, *args):
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        with patch("sys.stdout", stdout_capture), patch("sys.stderr", stderr_capture):
            code = cli.main(list(args))
        return code, stdout_capture.getvalue(), stderr_capture.getvalue()

    def test_health(self):
        code, out, err = self.run_cli("health")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["engine"], "pyrasec")

        code, out, _ = self.run_cli("health", "--json")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["status"], "healthy")

    def test_scan_table(self):
        code, out, err = self.run_cli("scan", str(self.root))
        self.assertEqual(code, 0)
        self.assertIn("PyraSec", out)

    def test_scan_json(self):
        code, out, _ = self.run_cli("scan", str(self.root), "-f", "json")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertIn("findings", data)
        self.assertIn("score", data)

    def test_scan_sarif(self):
        code, out, _ = self.run_cli("scan", str(self.root), "-f", "sarif")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertIn("$schema", data)

    def test_scan_html(self):
        code, out, _ = self.run_cli("scan", str(self.root), "-f", "html")
        self.assertEqual(code, 0)
        self.assertIn("<!DOCTYPE html>", out)

    def test_scan_csv(self):
        code, out, _ = self.run_cli("scan", str(self.root), "-f", "csv")
        self.assertEqual(code, 0)
        self.assertIn("rule_id", out)

    def test_scan_output_file(self):
        out_file = self.root / "report.json"
        code, out, _ = self.run_cli("scan", str(self.root), "-f", "json", "-o", str(out_file))
        self.assertEqual(code, 0)
        self.assertTrue(out_file.exists())
        data = json.loads(out_file.read_text(encoding="utf-8"))
        self.assertIn("findings", data)

    def test_scan_not_found(self):
        code, _, err = self.run_cli("scan", str(self.root / "nonexistent"))
        self.assertEqual(code, 2)
        self.assertIn("error", err)

    def test_scan_fail_on_threshold(self):
        (self.root / "docker-compose.yml").write_text("services:\n  app:\n    privileged: true\n", encoding="utf-8")
        code, _, _ = self.run_cli("scan", str(self.root), "--fail-on", "high")
        self.assertEqual(code, 1)


    def test_scan_options(self):
        code, out, _ = self.run_cli(
            "scan", str(self.root),
            "--verbose",
            "--exclude", "*.json",
            "--rule", "SEC-001",
            "--disable", "DOCK-001",
            "--no-gitignore",
            "--workers", "2",
        )
        self.assertEqual(code, 0)

    def test_score(self):
        code, out, _ = self.run_cli("score", str(self.root))
        self.assertEqual(code, 0)
        self.assertTrue(len(out.strip()) > 0)

        code, out, _ = self.run_cli("score", str(self.root), "--explain")
        self.assertEqual(code, 0)
        self.assertIn("breakdown", out.lower())

    def test_fix(self):
        code, out, _ = self.run_cli("fix", str(self.root))
        self.assertEqual(code, 0)

    def test_sbom(self):
        code, out, _ = self.run_cli("sbom", str(self.root))
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["bomFormat"], "CycloneDX")

        sbom_file = self.root / "sbom.json"
        code, _, _ = self.run_cli("sbom", str(self.root), "-o", str(sbom_file))
        self.assertEqual(code, 0)
        self.assertTrue(sbom_file.exists())

    def test_pyramid(self):
        code, out, _ = self.run_cli("pyramid", str(self.root))
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertIn("pyramid", data)

        pyr_file = self.root / "pyr.json"
        code, _, _ = self.run_cli("pyramid", str(self.root), "-o", str(pyr_file))
        self.assertEqual(code, 0)
        self.assertTrue(pyr_file.exists())

    def test_rules(self):
        code, out, _ = self.run_cli("rules")
        self.assertEqual(code, 0)
        self.assertIn("rules registered", out)

        code, out, _ = self.run_cli("rules", "--json")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0)

    def test_hook_non_git(self):
        code, _, err = self.run_cli("hook", str(self.root))
        self.assertEqual(code, 2)
        self.assertIn("not a git repository", err)

    def test_hook_git(self):
        git_hooks = self.root / ".git" / "hooks"
        git_hooks.mkdir(parents=True, exist_ok=True)

        code, out, _ = self.run_cli("hook", str(self.root))
        self.assertEqual(code, 0)
        self.assertTrue((git_hooks / "pre-commit").exists())

        # Calling again without force returns 1
        code, out, _ = self.run_cli("hook", str(self.root))
        self.assertEqual(code, 1)

        # Calling with force returns 0
        code, out, _ = self.run_cli("hook", str(self.root), "--force")
        self.assertEqual(code, 0)

    def test_main_keyboard_interrupt(self):
        with patch("pyrasec.cli.cmd_health", side_effect=KeyboardInterrupt):
            code, _, err = self.run_cli("health")
            self.assertEqual(code, 130)
            self.assertIn("interrupted", err)

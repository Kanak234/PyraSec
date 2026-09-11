import tempfile
import unittest
from pathlib import Path

from starlette.testclient import TestClient

from pyrasec.service import app, ALLOWED_ROOTS


class TestService(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)
        self.temp_dir = tempfile.TemporaryDirectory()
        self.dir_path = Path(self.temp_dir.name).resolve()
        ALLOWED_ROOTS.append(self.dir_path)

        # Create a sample project structure
        (self.dir_path / "main.py").write_text("print('hello world')\n", encoding="utf-8")
        (self.dir_path / "app.env").write_text("SECRET_KEY=12345\n", encoding="utf-8")

    def tearDown(self):
        if self.dir_path in ALLOWED_ROOTS:
            ALLOWED_ROOTS.remove(self.dir_path)
        self.temp_dir.cleanup()

    def test_health(self):
        resp = self.client.get("/health")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["status"], "ok")
        self.assertIn("version", data)
        self.assertGreater(data["rules_loaded"], 0)

    def test_rules_catalog(self):
        resp = self.client.get("/api/v1/rules")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertGreater(data["count"], 0)

        # Filter by severity
        resp_crit = self.client.get("/api/v1/rules?severity=critical")
        self.assertEqual(resp_crit.status_code, 200)
        self.assertTrue(all(r["severity"] == "critical" for r in resp_crit.json()["rules"]))

        # Filter by tag
        resp_tag = self.client.get("/api/v1/rules?tag=secrets")
        self.assertEqual(resp_tag.status_code, 200)
        self.assertTrue(all("secrets" in r["tags"] for r in resp_tag.json()["rules"]))

    def test_scan_endpoint(self):
        payload = {
            "path": str(self.dir_path),
            "profile": "default",
            "workers": 2,
            "include_pyramid": True,
            "include_tree": True,
            "use_cache": False,
        }
        resp = self.client.post("/api/v1/scan", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("findings", data)
        self.assertIn("score", data)
        self.assertIn("score_breakdown", data)
        self.assertIn("pyramid", data)
        self.assertIn("tree", data)

    def test_score_endpoint(self):
        payload = {"path": str(self.dir_path), "profile": "default"}
        resp = self.client.post("/api/v1/score", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("score", data)
        self.assertIn("grade", data)

    def test_pyramid_endpoint(self):
        payload = {"path": str(self.dir_path), "profile": "default"}
        resp = self.client.post("/api/v1/pyramid", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("pyramid", data)
        self.assertIn("tree", data)
        self.assertIn("heatmap", data)
        self.assertIn("attack_surface", data)

    def test_sbom_endpoint(self):
        payload = {"path": str(self.dir_path), "profile": "default"}
        resp = self.client.post("/api/v1/sbom", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("bomFormat", data)
        self.assertEqual(data["bomFormat"], "CycloneDX")

    def test_sarif_endpoint(self):
        payload = {"path": str(self.dir_path), "profile": "default"}
        resp = self.client.post("/api/v1/sarif", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn("$schema", data)
        self.assertIn("runs", data)

    def test_report_endpoint(self):
        payload = {"path": str(self.dir_path), "profile": "default"}
        resp = self.client.post("/api/v1/report", json=payload)
        self.assertEqual(resp.status_code, 200)
        self.assertIn("text/html", resp.headers["content-type"])
        self.assertIn("PyraSec", resp.text)

    def test_resolve_not_found(self):
        payload = {"path": str(self.dir_path / "nonexistent_dir")}
        resp = self.client.post("/api/v1/scan", json=payload)
        self.assertEqual(resp.status_code, 404)

    def test_resolve_not_a_directory(self):
        payload = {"path": str(self.dir_path / "main.py")}
        resp = self.client.post("/api/v1/scan", json=payload)
        self.assertEqual(resp.status_code, 400)

    def test_resolve_outside_allowed(self):
        outside = tempfile.mkdtemp()
        try:
            payload = {"path": outside}
            resp = self.client.post("/api/v1/scan", json=payload)
            self.assertEqual(resp.status_code, 403)
        finally:
            Path(outside).rmdir()

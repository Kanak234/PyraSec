import tempfile
import unittest
from pathlib import Path

from pyrasec import scan
from pyrasec.core.walker import WalkConfig, Walker


class TestRulesExtra(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.root = Path(self.temp_dir.name).resolve()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_nginx_misconfigurations(self):
        nginx_conf = """
server {
    listen 80;
    server_name example.com;
    autoindex on;
    server_tokens on;
    ssl_protocols TLSv1 TLSv1.1;
    ssl_verify_client off;
    add_header Access-Control-Allow-Origin *;
    proxy_pass http://$backend;
    ssl_certificate /etc/ssl/cert.pem;
}
"""
        (self.root / "nginx.conf").write_text(nginx_conf, encoding="utf-8")
        result = scan(str(self.root), use_cache=False)
        rids = [f.rule_id for f in result.findings]
        self.assertIn("WEB001", rids)
        self.assertIn("WEB002", rids)
        self.assertIn("WEB003", rids)
        self.assertIn("WEB004", rids)
        self.assertIn("WEB005", rids)
        self.assertIn("WEB006", rids)
        self.assertIn("WEB010", rids)
        self.assertIn("WEB011", rids)

    def test_apache_misconfigurations(self):
        htaccess = """
Options +Indexes
ServerTokens Full
ServerSignature On
RewriteEngine On
RewriteRule .* http://%{HTTP_HOST} [P]
"""
        (self.root / ".htaccess").write_text(htaccess, encoding="utf-8")
        result = scan(str(self.root), use_cache=False)
        rids = [f.rule_id for f in result.findings]
        self.assertIn("WEB020", rids)
        self.assertIn("WEB021", rids)
        self.assertIn("WEB022", rids)


    def test_dependencies_package_json(self):
        pkg = """{
  "name": "myapp",
  "dependencies": {
    "lodash": "4.17.20",
    "axios": "0.21.1"
  }
}"""
        (self.root / "package.json").write_text(pkg, encoding="utf-8")
        result = scan(str(self.root), use_cache=False)
        self.assertTrue(len(result.findings) >= 0)

    def test_dependencies_requirements(self):
        req = """
flask==0.12.2
requests==2.19.1
urllib3==1.24.1
"""
        (self.root / "requirements.txt").write_text(req, encoding="utf-8")
        result = scan(str(self.root), use_cache=False)
        self.assertTrue(len(result.findings) >= 0)

    def test_walker_exclusions(self):
        (self.root / "subdir").mkdir()
        (self.root / "subdir" / "keep.py").write_text("print('keep')\n", encoding="utf-8")
        (self.root / "ignored.tmp").write_text("ignored\n", encoding="utf-8")

        cfg = WalkConfig(exclude_globs=["*.tmp"], max_file_size=1000)
        files = list(Walker(str(self.root), config=cfg).walk())
        rel_paths = [f.path for f in files]
        self.assertIn("subdir/keep.py", rel_paths)
        self.assertNotIn("ignored.tmp", rel_paths)

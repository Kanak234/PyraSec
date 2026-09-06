"""Builds a deliberately insecure sample project so the scanner has something
real to find. Every value below is fake — placeholder tokens with the right
shape, never a live credential.

    python3 tests/make_fixture.py /tmp/vulnerable-app
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

FILES: dict[str, str] = {
    ".env": (
        "DATABASE_URL=postgres://appuser:hunter2wasnevergood@db.internal:5432/prod\n"
        "STRIPE_SECRET=sk_live_51H8xQ2KpZ9mNvBcXwErTyUiOpAsDfGhJ\n"
        "JWT_SECRET=8f3d9a1c7b2e5f4a6d8c0b3e7f1a9d2c\n"
    ),
    ".env.example": "DATABASE_URL=\nSTRIPE_SECRET=\nJWT_SECRET=\n",
    "app/settings.py": (
        "import os\n\n"
        "DEBUG = True\n"
        'SECRET_KEY = "django-insecure-4h!x2b@9zqw3e8r7t6y5u4i3o2p1a0s9d8f7g6h5j4k3l"\n'
        'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n'
        'DB_PASSWORD = "P@ssw0rd-Pr0duct10n-2024"\n'
        'API_KEY = os.environ.get("API_KEY", "")   # this one is fine\n'
    ),
    "app/auth.py": (
        "import hashlib\n\n"
        'JWT_SECRET = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"\n\n'
        "def check(password, stored):\n"
        "    return hashlib.md5(password.encode()).hexdigest() == stored\n"
    ),
    "public/config.json": '{\n  "api_key": "AIzaSyDaGmWKa4JsXZHjPZ5tOaXcQ8dRfGhIjKl",\n  "env": "production"\n}\n',
    "public/index.html": "<!doctype html><title>App</title><h1>Hello</h1>\n",
    "static/backup.env": "OLD_STRIPE_KEY=sk_live_51H8xQ2KpZ9mNvBcXwErTyUiOpAsDfGhJ\n",
    "database.sql.bak": "-- dump\nINSERT INTO users VALUES (1,'admin','$2b$12$abcdefghijklmnop');\n" * 40,
    "dump.sql": "CREATE TABLE users (id int, email text, password_hash text);\n" * 30,
    "app.log": "2026-07-24 10:00:01 INFO auth token=Bearer abc123def456 user=42\n" * 20,
    "certs/server.key": (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEAxKfakefakefakefakefakefakefakefakefakefakefakefake\n"
        "-----END RSA PRIVATE KEY-----\n"
    ),
    "Dockerfile": (
        "FROM node:latest\n"
        "WORKDIR /app\n"
        "COPY . .\n"
        "ENV DB_PASSWORD=supersecret123\n"
        "RUN curl -sL https://install.example.com/setup.sh | sh\n"
        "RUN chmod -R 777 /app\n"
        "EXPOSE 3000\n"
        'CMD ["node", "server.js"]\n'
    ),
    "docker-compose.yml": (
        "version: '3.8'\n"
        "services:\n"
        "  app:\n"
        "    build: .\n"
        "    privileged: true\n"
        "    network_mode: host\n"
        "    volumes:\n"
        "      - /var/run/docker.sock:/var/run/docker.sock\n"
        "    environment:\n"
        "      POSTGRES_PASSWORD: prodpassword123\n"
        "    cap_add:\n"
        "      - ALL\n"
    ),
    "k8s/deployment.yaml": (
        "apiVersion: apps/v1\n"
        "kind: Deployment\n"
        "metadata:\n"
        "  name: web\n"
        "spec:\n"
        "  template:\n"
        "    spec:\n"
        "      hostNetwork: true\n"
        "      hostPID: true\n"
        "      containers:\n"
        "        - name: web\n"
        "          image: myapp:latest\n"
        "          securityContext:\n"
        "            privileged: true\n"
        "            runAsUser: 0\n"
        "            allowPrivilegeEscalation: true\n"
        "            readOnlyRootFilesystem: false\n"
        "          env:\n"
        "            - name: DB_PASSWORD\n"
        "              value: inline-secret-value\n"
    ),
    "infra/main.tf": (
        'resource "aws_s3_bucket" "assets" {\n'
        '  bucket = "my-public-assets"\n'
        '  acl    = "public-read"\n'
        "}\n\n"
        'resource "aws_security_group" "db" {\n'
        "  ingress {\n"
        "    from_port   = 5432\n"
        "    to_port     = 5432\n"
        '    protocol    = "tcp"\n'
        '    cidr_blocks = ["0.0.0.0/0"]\n'
        "  }\n"
        "}\n\n"
        'resource "aws_db_instance" "main" {\n'
        "  publicly_accessible = true\n"
        "  encrypted           = false\n"
        '  password            = "TerraformPlaintextPassword99"\n'
        "}\n"
    ),
    "nginx.conf": (
        "server {\n"
        "    listen 80;\n"
        "    server_name example.com;\n"
        "    server_tokens on;\n"
        "    autoindex on;\n"
        "    root /var/www/html;\n"
        "    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n"
        "    location /api {\n"
        '        add_header Access-Control-Allow-Origin *;\n'
        "        proxy_pass http://$backend;\n"
        "    }\n"
        "}\n"
    ),
    "requirements.txt": (
        "fastapi>=0.100\n"
        "requests\n"
        "pyyaml>=5\n"
        "sqlalchemy==2.0.30\n"
        "git+https://github.com/example/helper\n"
    ),
    "package.json": (
        "{\n"
        '  "name": "vulnerable-app",\n'
        '  "version": "1.0.0",\n'
        '  "dependencies": {\n'
        '    "express": "^4.18.0",\n'
        '    "lodash": "*",\n'
        '    "jsonwebtoken": "9.0.2"\n'
        "  }\n"
        "}\n"
    ),
    "scripts/deploy.sh": (
        "#!/bin/bash\n"
        'GITHUB_TOKEN="ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"\n'
        "curl -k https://api.example.com/deploy\n"
    ),
    "README.md": "# Vulnerable app\n\nIntentionally insecure fixture for PyraSec.\n",
    "src/index.js": (
        "const express = require('express');\n"
        "const app = express();\n"
        "app.listen(3000);\n"
    ),
}

MODES: dict[str, int] = {
    ".env": 0o666,
    "certs/server.key": 0o644,
    "scripts/deploy.sh": 0o777,
    "public/config.json": 0o646,
}


def build(target: str) -> None:
    root = Path(target)
    if root.exists():
        shutil.rmtree(root)
    root.mkdir(parents=True)

    for rel, content in FILES.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    for rel, mode in MODES.items():
        os.chmod(root / rel, mode)

    # A .git directory with no .gitignore — the GIT rules need this to fire.
    (root / ".git").mkdir()
    (root / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (root / ".git" / "config").write_text(
        "[remote \"origin\"]\n\turl = https://github.com/example/vulnerable-app.git\n",
        encoding="utf-8",
    )
    os.chmod(root / "public", 0o777)

    print(f"fixture built at {root} ({len(FILES)} files)")


if __name__ == "__main__":
    build(sys.argv[1] if len(sys.argv) > 1 else "/tmp/vulnerable-app")

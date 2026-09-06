"""Container configuration rules — Dockerfile and Compose.

Container misconfiguration is where a contained web-app bug turns into host
compromise. Every rule here is a line-level check on the build file, so the
finding points at the exact instruction to change.
"""

from __future__ import annotations

import re

from ..core.models import FileRecord, Remediation, Severity
from .base import ContentRule, iter_lines, register

DOCKERFILE_NAMES = {"dockerfile", "dockerfile.dev", "dockerfile.prod", "containerfile"}
COMPOSE_NAMES = {
    "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml",
    "docker-compose.prod.yml", "docker-compose.override.yml",
}

SECRET_ENV_KEYS = re.compile(
    r"(?i)\b(?:ENV|ARG)\s+([A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIAL)[A-Z0-9_]*)\s*[= ]\s*(\S+)"
)


def _check_dockerfile(record: FileRecord, text: str):
    has_user = False
    last_user_root = False
    from_lines: list[tuple[int, str]] = []

    for line_no, raw in iter_lines(text):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        upper = line.upper()

        # --- base image tag -------------------------------------------------
        if upper.startswith("FROM "):
            from_lines.append((line_no, line))
            image = line.split(None, 1)[1].split(" AS ")[0].split(" as ")[0].strip()
            if "@sha256:" not in image:
                if image.endswith(":latest") or ":" not in image.rsplit("/", 1)[-1]:
                    yield LATEST_TAG_RULE.finding(
                        record.path,
                        line=line_no,
                        evidence=image,
                        description=(
                            f"Base image `{image}` is unpinned. `latest` (or no tag) means the image "
                            f"you tested is not the image you deploy — a rebuild silently pulls new "
                            f"code, and a compromised upstream tag propagates straight into production."
                        ),
                        metadata={"image": image},
                    )

        # --- USER -----------------------------------------------------------
        if upper.startswith("USER "):
            has_user = True
            user = line.split(None, 1)[1].strip()
            last_user_root = user in ("root", "0", "0:0")

        # --- secrets in build args / env -------------------------------------
        match = SECRET_ENV_KEYS.search(line)
        if match:
            key, value = match.group(1), match.group(2)
            if value not in ("", '""', "''") and not value.startswith("$"):
                yield DOCKER_SECRET_RULE.finding(
                    record.path,
                    line=line_no,
                    evidence=f"{key}=***",
                    description=(
                        f"`{key}` is baked into the image at build time. Every ENV and ARG value "
                        f"is readable with `docker history` and `docker inspect` by anyone who can "
                        f"pull the image — build-time secrets are not secret."
                    ),
                    metadata={"key": key},
                )

        # --- privileged / risky instructions ---------------------------------
        if re.search(r"(?i)\bcurl\b[^|]*\|\s*(?:ba)?sh", line) or re.search(r"(?i)\bwget\b[^|]*\|\s*(?:ba)?sh", line):
            yield CURL_PIPE_SH_RULE.finding(
                record.path,
                line=line_no,
                evidence=line[:120],
            )

        if re.search(r"(?i)\bchmod\s+(?:-R\s+)?777\b", line):
            yield DOCKER_CHMOD_RULE.finding(record.path, line=line_no, evidence=line[:120])

        if upper.startswith("ADD ") and ("http://" in line or "https://" in line):
            yield ADD_REMOTE_RULE.finding(record.path, line=line_no, evidence=line[:120])

        if re.search(r"(?i)--no-check-certificate|--insecure\b|(?<!\w)-k\s", line):
            yield TLS_BYPASS_RULE.finding(record.path, line=line_no, evidence=line[:120])

    if from_lines and (not has_user or last_user_root):
        yield ROOT_USER_RULE.finding(
            record.path,
            line=from_lines[-1][0],
            evidence="no non-root USER instruction" if not has_user else "USER root",
            description=(
                "The final stage of this image runs as root. Any remote code execution in the "
                "application then starts as uid 0 inside the container, which makes kernel and "
                "runtime escapes far easier and defeats most read-only-filesystem hardening."
            ),
        )


LATEST_TAG_RULE = register(
    ContentRule(
        id="DOC001",
        title="Unpinned container base image",
        severity=Severity.MEDIUM,
        description="FROM uses :latest or no tag, so builds are not reproducible.",
        remediation=Remediation(
            summary="Pin the base image by digest.",
            steps=[
                "Pin to an immutable digest: `FROM python:3.12-slim@sha256:<digest>`.",
                "Get the digest with `docker inspect --format='{{index .RepoDigests 0}}' python:3.12-slim`.",
                "Automate bumps with Renovate or Dependabot so pinning does not mean going stale.",
            ],
            example="FROM python:3.12-slim@sha256:1e6f2f2b7...  # pinned, reproducible\n",
        ),
        cwe="CWE-1104 Use of Unmaintained Third Party Components",
        owasp="A08:2021 Software and Data Integrity Failures",
        cvss=5.3,
        filenames=DOCKERFILE_NAMES,
        tags=["container", "supply-chain"],
        check=_check_dockerfile,
    )
)

ROOT_USER_RULE = register(
    ContentRule(
        id="DOC002",
        title="Container runs as root",
        severity=Severity.HIGH,
        description="No non-root USER instruction in the final build stage.",
        remediation=Remediation(
            summary="Create and switch to an unprivileged user.",
            steps=[
                "Add a dedicated user and switch to it before CMD/ENTRYPOINT.",
                "Chown only what the app must write; keep the rest read-only.",
                "Run with `--read-only --cap-drop=ALL --security-opt=no-new-privileges`.",
                "In Kubernetes, set `runAsNonRoot: true` so the cluster refuses a root image.",
            ],
            example=(
                "RUN addgroup --system app && adduser --system --ingroup app app\n"
                "COPY --chown=app:app . /app\n"
                "USER app\n"
                'CMD ["python", "-m", "app"]\n'
            ),
            references=["https://cwe.mitre.org/data/definitions/250.html"],
        ),
        cwe="CWE-250 Execution with Unnecessary Privileges",
        owasp="A05:2021 Security Misconfiguration",
        mitre="T1610 Deploy Container",
        cvss=7.8,
        filenames=DOCKERFILE_NAMES,
        tags=["container", "privesc"],
    )
)

DOCKER_SECRET_RULE = register(
    ContentRule(
        id="DOC003",
        title="Secret baked into image layer",
        severity=Severity.CRITICAL,
        description="ENV/ARG assigns a credential value at build time.",
        remediation=Remediation(
            summary="Use BuildKit secret mounts or runtime injection.",
            steps=[
                "Remove the value; pass it at runtime with `-e` / a secret volume / the orchestrator's secret store.",
                "If it is genuinely needed during build, use a BuildKit secret mount — it never lands in a layer.",
                "Rotate the credential: it is already in every pulled copy of the image.",
                "Audit existing images with `docker history --no-trunc <image>`.",
            ],
            example=(
                "# syntax=docker/dockerfile:1.7\n"
                "RUN --mount=type=secret,id=pip_token \\\n"
                "    pip install --index-url https://$(cat /run/secrets/pip_token)@pypi.internal/simple -r req.txt\n\n"
                "# build with: docker build --secret id=pip_token,src=./token .\n"
            ),
        ),
        cwe="CWE-798 Use of Hard-coded Credentials",
        owasp="A05:2021 Security Misconfiguration",
        mitre="T1552.001 Credentials In Files",
        cvss=8.6,
        filenames=DOCKERFILE_NAMES,
        tags=["container", "secret"],
    )
)

CURL_PIPE_SH_RULE = register(
    ContentRule(
        id="DOC004",
        title="Remote script piped to a shell",
        severity=Severity.HIGH,
        description="`curl ... | sh` executes unverified remote code at build time.",
        remediation=Remediation(
            summary="Download, verify the checksum, then execute.",
            steps=[
                "Split the step: download to a file, verify a pinned SHA-256, then run it.",
                "Prefer the distro package manager or an official release artefact with a signature.",
                "If the upstream host is ever compromised, a piped install runs their code inside your build with full network access.",
            ],
            example=(
                "ADD https://example.com/install.sh /tmp/install.sh\n"
                'RUN echo "a1b2c3...  /tmp/install.sh" | sha256sum -c - && sh /tmp/install.sh\n'
            ),
        ),
        cwe="CWE-494 Download of Code Without Integrity Check",
        owasp="A08:2021 Software and Data Integrity Failures",
        mitre="T1195.002 Compromise Software Supply Chain",
        cvss=8.1,
        filenames=DOCKERFILE_NAMES,
        tags=["container", "supply-chain"],
    )
)

DOCKER_CHMOD_RULE = register(
    ContentRule(
        id="DOC005",
        title="chmod 777 in image build",
        severity=Severity.MEDIUM,
        description="World-writable permissions applied during the build.",
        remediation=Remediation(
            summary="Grant the narrowest mode that works.",
            steps=[
                "Replace with `chmod 755` for executables, `644` for data, `750`/`640` when a group needs access.",
                "Use `COPY --chown=app:app` instead of a broad chmod after the fact.",
            ],
            example="COPY --chown=app:app ./app /app\nRUN chmod -R go-w /app\n",
        ),
        cwe="CWE-732 Incorrect Permission Assignment for Critical Resource",
        owasp="A05:2021 Security Misconfiguration",
        cvss=5.5,
        filenames=DOCKERFILE_NAMES,
        tags=["container", "permissions"],
    )
)

ADD_REMOTE_RULE = register(
    ContentRule(
        id="DOC006",
        title="ADD from a remote URL",
        severity=Severity.MEDIUM,
        description="ADD fetches a remote resource without integrity verification.",
        remediation=Remediation(
            summary="Use COPY for local files; verify checksums for remote ones.",
            steps=[
                "Use COPY for anything already in the build context — ADD's extra behaviour (auto-extract, remote fetch) is rarely what you want.",
                "For remote artefacts, download and verify a pinned checksum before use.",
            ],
            example='ADD --checksum=sha256:a1b2c3... https://example.com/app.tar.gz /tmp/\n',
        ),
        cwe="CWE-494 Download of Code Without Integrity Check",
        owasp="A08:2021 Software and Data Integrity Failures",
        cvss=5.3,
        filenames=DOCKERFILE_NAMES,
        tags=["container", "supply-chain"],
    )
)

TLS_BYPASS_RULE = register(
    ContentRule(
        id="DOC007",
        title="TLS verification disabled",
        severity=Severity.HIGH,
        description="A build step disables certificate validation.",
        remediation=Remediation(
            summary="Fix the trust store instead of skipping verification.",
            steps=[
                "Remove `--insecure` / `-k` / `--no-check-certificate`.",
                "If a corporate proxy is the reason, install its CA into the image: `COPY corp-ca.crt /usr/local/share/ca-certificates/ && update-ca-certificates`.",
                "Skipping verification makes every build step trivially machine-in-the-middle-able.",
            ],
            example="COPY corp-ca.crt /usr/local/share/ca-certificates/corp-ca.crt\nRUN update-ca-certificates\n",
        ),
        cwe="CWE-295 Improper Certificate Validation",
        owasp="A02:2021 Cryptographic Failures",
        cvss=7.4,
        filenames=DOCKERFILE_NAMES,
        tags=["container", "crypto"],
    )
)


# --------------------------------------------------------------------------
# docker-compose
# --------------------------------------------------------------------------

PRIVILEGED = re.compile(r"(?i)^\s*privileged\s*:\s*true")
HOST_NETWORK = re.compile(r"(?i)^\s*network_mode\s*:\s*[\"']?host")
DOCKER_SOCK = re.compile(r"/var/run/docker\.sock")
ROOT_MOUNT = re.compile(r"^\s*-\s*[\"']?/(?::|/)?\s*:")
CAP_ADD_ALL = re.compile(r"(?i)^\s*-\s*(ALL|SYS_ADMIN|SYS_PTRACE|NET_ADMIN)\s*$")
COMPOSE_SECRET = re.compile(
    r"(?i)^\s*-?\s*([A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_?KEY)[A-Z0-9_]*)\s*[:=]\s*(\S+)"
)


def _check_compose(record: FileRecord, text: str):
    in_cap_add = False
    for line_no, raw in iter_lines(text):
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        if PRIVILEGED.match(line):
            yield COMPOSE_PRIVILEGED_RULE.finding(record.path, line=line_no, evidence=stripped)
        if HOST_NETWORK.match(line):
            yield COMPOSE_HOST_NET_RULE.finding(record.path, line=line_no, evidence=stripped)
        if DOCKER_SOCK.search(line):
            yield DOCKER_SOCK_RULE.finding(record.path, line=line_no, evidence=stripped)

        if re.match(r"(?i)^\s*cap_add\s*:", line):
            in_cap_add = True
            continue
        if in_cap_add:
            if CAP_ADD_ALL.match(stripped):
                yield COMPOSE_CAPS_RULE.finding(record.path, line=line_no, evidence=stripped)
            elif not stripped.startswith("-"):
                in_cap_add = False

        match = COMPOSE_SECRET.match(line)
        if match:
            value = match.group(2).strip("\"'")
            if value and not value.startswith("$") and not value.startswith("{"):
                yield COMPOSE_SECRET_RULE.finding(
                    record.path,
                    line=line_no,
                    evidence=f"{match.group(1)}=***",
                    metadata={"key": match.group(1)},
                )


COMPOSE_PRIVILEGED_RULE = register(
    ContentRule(
        id="DOC010",
        title="Privileged container",
        severity=Severity.CRITICAL,
        description="`privileged: true` removes essentially all container isolation.",
        remediation=Remediation(
            summary="Drop privileged mode; add only the specific capabilities needed.",
            steps=[
                "Remove `privileged: true`.",
                "Identify what actually required it and grant that one capability: `cap_add: [NET_ADMIN]`.",
                "Add `security_opt: [no-new-privileges:true]` and `cap_drop: [ALL]` as the baseline.",
                "A privileged container can access every host device and is generally considered equivalent to root on the host.",
            ],
            example=(
                "services:\n  app:\n    cap_drop: [ALL]\n    cap_add: [NET_BIND_SERVICE]\n"
                "    security_opt:\n      - no-new-privileges:true\n    read_only: true\n"
            ),
        ),
        cwe="CWE-250 Execution with Unnecessary Privileges",
        owasp="A05:2021 Security Misconfiguration",
        mitre="T1611 Escape to Host",
        cvss=9.9,
        filenames=COMPOSE_NAMES,
        tags=["container", "privesc"],
        check=_check_compose,
    )
)

COMPOSE_HOST_NET_RULE = register(
    ContentRule(
        id="DOC011",
        title="Host network mode",
        severity=Severity.HIGH,
        description="`network_mode: host` removes network namespace isolation.",
        remediation=Remediation(
            summary="Use a bridge network and publish only the ports you need.",
            steps=[
                "Remove `network_mode: host` and publish explicit ports instead.",
                "Bind to localhost where the port is only for other local services: `127.0.0.1:5432:5432`.",
                "With host networking the container can reach every service bound to the host, including ones that assumed they were internal-only.",
            ],
            example="services:\n  db:\n    ports:\n      - \"127.0.0.1:5432:5432\"\n",
        ),
        cwe="CWE-668 Exposure of Resource to Wrong Sphere",
        owasp="A05:2021 Security Misconfiguration",
        cvss=7.5,
        filenames=COMPOSE_NAMES,
        tags=["container", "network"],
    )
)

DOCKER_SOCK_RULE = register(
    ContentRule(
        id="DOC012",
        title="Docker socket mounted into container",
        severity=Severity.CRITICAL,
        description="/var/run/docker.sock grants full control of the Docker daemon.",
        remediation=Remediation(
            summary="Do not mount the socket; use a proxy or rootless alternative.",
            steps=[
                "Remove the bind mount. Access to the socket is equivalent to root on the host — a container can start a new privileged container mounting `/`.",
                "If the workload genuinely needs Docker API access, put a filtering proxy (e.g. docker-socket-proxy) in front and expose only the needed endpoints, read-only.",
                "For CI runners, prefer rootless buildkit or kaniko.",
            ],
        ),
        cwe="CWE-269 Improper Privilege Management",
        owasp="A01:2021 Broken Access Control",
        mitre="T1610 Deploy Container",
        cvss=9.9,
        filenames=COMPOSE_NAMES,
        tags=["container", "privesc"],
    )
)

COMPOSE_CAPS_RULE = register(
    ContentRule(
        id="DOC013",
        title="Dangerous Linux capability granted",
        severity=Severity.HIGH,
        description="cap_add includes ALL or a capability that enables container escape.",
        remediation=Remediation(
            summary="Drop all capabilities, then add back the minimum.",
            steps=[
                "Replace with `cap_drop: [ALL]` plus the single capability you can justify.",
                "SYS_ADMIN in particular is close to full root; SYS_PTRACE allows reading other processes' memory.",
            ],
            example="cap_drop: [ALL]\ncap_add: [NET_BIND_SERVICE]\n",
        ),
        cwe="CWE-250 Execution with Unnecessary Privileges",
        owasp="A05:2021 Security Misconfiguration",
        mitre="T1611 Escape to Host",
        cvss=8.2,
        filenames=COMPOSE_NAMES,
        tags=["container", "privesc"],
    )
)

COMPOSE_SECRET_RULE = register(
    ContentRule(
        id="DOC014",
        title="Credential hardcoded in compose file",
        severity=Severity.HIGH,
        description="An environment value in the compose file holds a literal secret.",
        remediation=Remediation(
            summary="Reference an env var or a Docker secret instead.",
            steps=[
                "Replace the literal with `${VAR}` and keep the value in a git-ignored `.env` beside the compose file.",
                "For production use `secrets:` with a file or external secret, mounted at /run/secrets.",
                "Rotate the value — compose files are almost always committed.",
            ],
            example=(
                "services:\n  db:\n    environment:\n      POSTGRES_PASSWORD_FILE: /run/secrets/db_password\n"
                "secrets:\n  db_password:\n    external: true\n"
            ),
        ),
        cwe="CWE-798 Use of Hard-coded Credentials",
        owasp="A07:2021 Identification and Authentication Failures",
        cvss=7.5,
        filenames=COMPOSE_NAMES,
        tags=["container", "secret"],
    )
)

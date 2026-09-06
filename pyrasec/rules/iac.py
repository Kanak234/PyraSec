"""Infrastructure-as-code rules — Kubernetes manifests and Terraform.

Parsed line-by-line rather than with a YAML/HCL object model on purpose: IaC
files in the wild are full of Helm template braces and heredocs that break
strict parsers, and a scanner that crashes on one file is worse than one that
reads it as text. The trade-off is that these rules report a line, not a
resource path — which is what a developer wants to jump to anyway.
"""

from __future__ import annotations

import re

from ..core.models import FileRecord, Remediation, Severity
from .base import ContentRule, register

YAML_EXT = {".yaml", ".yml"}
TF_EXT = {".tf", ".tfvars"}

K8S_MARKERS = re.compile(r"(?m)^\s*(?:apiVersion|kind)\s*:")


def _is_k8s(text: str) -> bool:
    return bool(K8S_MARKERS.search(text)) and "kind:" in text


# --------------------------------------------------------------------------
# Kubernetes
# --------------------------------------------------------------------------

K8S_PATTERNS: list[tuple[str, re.Pattern[str], Severity, str, str]] = [
    ("K8S001", re.compile(r"(?i)^\s*privileged\s*:\s*true"), Severity.CRITICAL,
     "Privileged pod",
     "A privileged container disables namespace and cgroup restrictions; it is effectively root on the node."),
    ("K8S002", re.compile(r"(?i)^\s*hostNetwork\s*:\s*true"), Severity.HIGH,
     "hostNetwork enabled",
     "The pod shares the node's network namespace and can reach every service bound to the node, including the kubelet."),
    ("K8S003", re.compile(r"(?i)^\s*hostPID\s*:\s*true"), Severity.HIGH,
     "hostPID enabled",
     "The pod can see and signal every process on the node, which enables credential theft from other workloads."),
    ("K8S004", re.compile(r"(?i)^\s*allowPrivilegeEscalation\s*:\s*true"), Severity.HIGH,
     "Privilege escalation allowed",
     "setuid binaries inside the container can gain privileges the pod spec did not grant."),
    ("K8S005", re.compile(r"(?i)^\s*runAsUser\s*:\s*0\s*$"), Severity.HIGH,
     "Container runs as UID 0",
     "Running as root inside the pod removes a major barrier between an application bug and a node compromise."),
    ("K8S006", re.compile(r"(?i)^\s*readOnlyRootFilesystem\s*:\s*false"), Severity.MEDIUM,
     "Writable root filesystem",
     "A writable root filesystem lets an attacker drop tooling and persist inside the container."),
    ("K8S007", re.compile(r"(?i)^\s*-?\s*(?:name\s*:\s*)?hostPath\s*:"), Severity.HIGH,
     "hostPath volume",
     "hostPath mounts node storage into the pod; mounting / or /var/run leads directly to node takeover."),
    ("K8S008", re.compile(r"(?i)^\s*type\s*:\s*LoadBalancer"), Severity.MEDIUM,
     "Service exposed via LoadBalancer",
     "A LoadBalancer service gets a public IP. Confirm this is intended and that an ingress policy restricts source ranges."),
    ("K8S009", re.compile(r"(?i)^\s*automountServiceAccountToken\s*:\s*true"), Severity.MEDIUM,
     "Service account token auto-mounted",
     "The pod receives an API token it may not need; anything that reads the filesystem can then talk to the API server."),
]

K8S_SECRET_LITERAL = re.compile(
    r"(?i)^\s*(?:-\s*)?(?:name\s*:\s*)?([A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|API_?KEY)[A-Z0-9_]*)\s*:\s*(\S+)"
)

K8S_REMEDIATION = Remediation(
    summary="Apply a restricted Pod Security Standard baseline to the spec.",
    steps=[
        "Set the securityContext explicitly on every container — the defaults are permissive.",
        "Enforce it cluster-wide: label the namespace with `pod-security.kubernetes.io/enforce: restricted` so a bad manifest is rejected at admission, not discovered later.",
        "Add a policy engine (Kyverno or OPA Gatekeeper) so the rule is checked on every apply, not just in this repo.",
        "Scan manifests in CI so the pipeline fails before `kubectl apply` ever runs.",
    ],
    example=(
        "securityContext:\n"
        "  runAsNonRoot: true\n"
        "  runAsUser: 10001\n"
        "  allowPrivilegeEscalation: false\n"
        "  readOnlyRootFilesystem: true\n"
        "  capabilities:\n"
        "    drop: [ALL]\n"
        "  seccompProfile:\n"
        "    type: RuntimeDefault\n"
    ),
    references=["https://kubernetes.io/docs/concepts/security/pod-security-standards/"],
)

_K8S_RULES: dict[str, ContentRule] = {}


def _check_k8s(record: FileRecord, text: str):
    if not _is_k8s(text):
        return
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for rule_id, pattern, _sev, _title, _desc in K8S_PATTERNS:
            if pattern.match(line):
                yield _K8S_RULES[rule_id].finding(
                    record.path, line=line_no, evidence=stripped[:120]
                )
        match = K8S_SECRET_LITERAL.match(line)
        if match:
            value = match.group(2).strip("\"'")
            if value and not value.startswith(("$", "{", "valueFrom", "secretKeyRef")):
                yield _K8S_RULES["K8S020"].finding(
                    record.path,
                    line=line_no,
                    evidence=f"{match.group(1)}=***",
                    metadata={"key": match.group(1)},
                )


for _id, _pat, _sev, _title, _desc in K8S_PATTERNS:
    _K8S_RULES[_id] = register(
        ContentRule(
            id=_id,
            title=_title,
            severity=_sev,
            description=_desc,
            remediation=K8S_REMEDIATION,
            cwe="CWE-250 Execution with Unnecessary Privileges",
            owasp="A05:2021 Security Misconfiguration",
            mitre="T1611 Escape to Host",
            cvss=_sev.cvss_base,
            extensions=set(YAML_EXT),
            tags=["kubernetes", "iac"],
            check=_check_k8s if _id == "K8S001" else None,
        )
    )

_K8S_RULES["K8S020"] = register(
    ContentRule(
        id="K8S020",
        title="Literal secret in Kubernetes manifest",
        severity=Severity.HIGH,
        description="A credential is written directly into a manifest instead of referenced from a Secret.",
        remediation=Remediation(
            summary="Reference a Secret; do not inline the value.",
            steps=[
                "Move the value into a Secret and reference it with `valueFrom.secretKeyRef`.",
                "Remember base64 in a Secret manifest is encoding, not encryption — enable etcd encryption at rest and keep Secret manifests out of git.",
                "For GitOps, use Sealed Secrets, SOPS, or an External Secrets Operator so the repo holds only ciphertext.",
            ],
            example=(
                "env:\n"
                "  - name: DB_PASSWORD\n"
                "    valueFrom:\n"
                "      secretKeyRef:\n"
                "        name: db-credentials\n"
                "        key: password\n"
            ),
        ),
        cwe="CWE-798 Use of Hard-coded Credentials",
        owasp="A07:2021 Identification and Authentication Failures",
        cvss=7.5,
        extensions=set(YAML_EXT),
        tags=["kubernetes", "iac", "secret"],
    )
)


# --------------------------------------------------------------------------
# Terraform
# --------------------------------------------------------------------------

TF_PATTERNS: list[tuple[str, re.Pattern[str], Severity, str, str]] = [
    ("TF001", re.compile(r"(?i)cidr_blocks\s*=\s*\[\s*\"0\.0\.0\.0/0\""), Severity.HIGH,
     "Security group open to the internet",
     "An ingress rule allows 0.0.0.0/0. Combined with an admin port this is how databases and dashboards end up indexed by Shodan."),
    ("TF002", re.compile(r"(?i)acl\s*=\s*\"public-read(-write)?\""), Severity.CRITICAL,
     "Publicly readable object storage",
     "A public-read ACL exposes every object in the bucket to anonymous users."),
    ("TF003", re.compile(r"(?i)(?:encrypted|encryption)\s*=\s*false"), Severity.HIGH,
     "Encryption explicitly disabled",
     "Storage or volume encryption is turned off, leaving data readable from snapshots and backups."),
    ("TF004", re.compile(r"(?i)publicly_accessible\s*=\s*true"), Severity.CRITICAL,
     "Database publicly accessible",
     "A managed database is reachable from the public internet; a weak password is then the only control."),
    ("TF005", re.compile(r"(?i)(?:skip_final_snapshot)\s*=\s*true"), Severity.LOW,
     "Final snapshot skipped",
     "Deleting the resource destroys the data with no recovery point."),
    ("TF006", re.compile(r"(?i)\"\\*\"\s*\]?\s*$"), Severity.MEDIUM,
     "Wildcard in IAM policy",
     "A wildcard Action or Resource grants far more than intended; scope it to specific ARNs and verbs."),
    ("TF007", re.compile(r"(?i)(?:enable_logging|logging)\s*=\s*false"), Severity.MEDIUM,
     "Logging disabled",
     "Without access logs there is no way to reconstruct an incident on this resource."),
    ("TF008", re.compile(r"(?i)(?:access_key|secret_key|password|token)\s*=\s*\"[^\"$][^\"]{7,}\""), Severity.CRITICAL,
     "Credential hardcoded in Terraform",
     "A literal credential in .tf or .tfvars ends up in version control and in the state file."),
]

TF_REMEDIATION = Remediation(
    summary="Restrict the resource and enforce the rule in CI.",
    steps=[
        "Narrow the setting: specific CIDRs instead of 0.0.0.0/0, private ACLs, encryption on, wildcard-free IAM.",
        "Move credentials to variables sourced from a secret store; never commit .tfvars containing values.",
        "Protect the state file — it stores resource attributes in plaintext. Use a remote backend with encryption and locking.",
        "Add a policy check to CI (Checkov, tfsec, or `terraform plan` diffing) so drift is caught before apply.",
    ],
    example=(
        'resource "aws_security_group_rule" "db" {\n'
        '  type              = "ingress"\n'
        "  from_port         = 5432\n"
        "  to_port           = 5432\n"
        '  protocol          = "tcp"\n'
        "  cidr_blocks       = [var.app_subnet_cidr]  # not 0.0.0.0/0\n"
        "  security_group_id = aws_security_group.db.id\n"
        "}\n"
    ),
    references=["https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"],
)

_TF_RULES: dict[str, ContentRule] = {}


def _check_terraform(record: FileRecord, text: str):
    for line_no, raw in enumerate(text.splitlines(), start=1):
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith(("#", "//")):
            continue
        for rule_id, pattern, _sev, _title, _desc in TF_PATTERNS:
            if rule_id == "TF006":
                # Only flag wildcards inside an IAM-ish context to cut noise.
                if not re.search(r"(?i)(action|resource|principal)\s*=", line):
                    continue
                if '"*"' not in line:
                    continue
            if pattern.search(line):
                yield _TF_RULES[rule_id].finding(
                    record.path, line=line_no, evidence=stripped[:120]
                )


for _id, _pat, _sev, _title, _desc in TF_PATTERNS:
    _TF_RULES[_id] = register(
        ContentRule(
            id=_id,
            title=_title,
            severity=_sev,
            description=_desc,
            remediation=TF_REMEDIATION,
            cwe="CWE-1188 Insecure Default Initialization of Resource",
            owasp="A05:2021 Security Misconfiguration",
            mitre="T1580 Cloud Infrastructure Discovery",
            cvss=_sev.cvss_base,
            extensions=set(TF_EXT),
            tags=["terraform", "iac", "cloud"],
            check=_check_terraform if _id == "TF001" else None,
        )
    )

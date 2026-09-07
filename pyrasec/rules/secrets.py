"""Hardcoded secret detection — deterministic, three-stage.

Stage 1  Pattern match. High-confidence provider tokens (AWS, GitHub, Stripe,
         Slack, Google, JWT, private key headers) have unambiguous shapes.
         A hit here is a finding at full confidence.

Stage 2  Assignment heuristics. ``password = "..."``, ``api_key: "..."`` —
         the variable name says what the value is. Confidence depends on the
         value passing the entropy and placeholder filters.

Stage 3  Filters. Placeholder detection, entropy floor, test-path discount.
         This is what keeps the finding count honest; a scanner that flags
         ``password = "your-password-here"`` gets muted by developers and
         then it catches nothing at all.

No AI anywhere: every decision above is a regex, a character count, or a
Shannon entropy computation you can reproduce with a calculator.
"""

from __future__ import annotations

import math
import re
from collections import Counter

from ..core.models import FileRecord, Remediation, Severity, redact, snippet
from .base import ContentRule, PathRule, in_test_path, is_comment, iter_lines, register

# --------------------------------------------------------------------------
# Filters
# --------------------------------------------------------------------------

PLACEHOLDER_TOKENS = {
    "changeme", "change_me", "your_api_key", "yourapikey", "your-api-key",
    "xxxxxxxx", "placeholder", "example", "dummy", "sample", "test", "todo",
    "secret", "password", "mypassword", "notreal", "fake", "redacted",
    "insert", "replace", "value", "none", "null", "undefined", "empty",
    "abc123", "123456", "password123", "admin", "root", "foobar", "lorem",
}

PLACEHOLDER_PATTERNS = [
    re.compile(r"^\$\{.*\}$"),          # ${ENV_VAR}
    re.compile(r"^\{\{.*\}\}$"),        # {{ template }}
    re.compile(r"^<.*>$"),              # <your-key>
    re.compile(r"^%[A-Za-z_]+%$"),      # %WINDOWS_VAR%
    re.compile(r"^\$[A-Z_][A-Z0-9_]*$"),  # $ENV_VAR
    re.compile(r"^os\.environ", re.IGNORECASE),
    re.compile(r"^process\.env", re.IGNORECASE),
    re.compile(r"^(x{6,}|\*{6,}|\.{6,}|-{6,}|0{6,})$", re.IGNORECASE),
]

BASE64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
HEX_CHARS = set("0123456789abcdefABCDEF")


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character. Random base64 lands around 5.5-6.0."""
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def looks_like_placeholder(value: str) -> bool:
    lowered = value.strip().lower()
    if not lowered:
        return True
    if lowered in PLACEHOLDER_TOKENS:
        return True
    if any(p.match(value.strip()) for p in PLACEHOLDER_PATTERNS):
        return True
    if any(token in lowered for token in ("your_", "your-", "my_secret", "example.com", "changeme")):
        return True
    # A "secret" made of one repeated character carries no information.
    if len(set(lowered)) <= 3:
        return True
    return False


def is_high_entropy(value: str, min_length: int = 16) -> bool:
    """Entropy floor tuned per charset — hex is denser but less entropic."""
    value = value.strip()
    if len(value) < min_length:
        return False
    chars = set(value)
    entropy = shannon_entropy(value)
    if chars <= HEX_CHARS:
        return entropy > 3.0 and len(value) >= 32
    if chars <= BASE64_CHARS:
        return entropy > 4.0
    return entropy > 4.2


def luhn_valid(number: str) -> bool:
    """Luhn checksum — turns 'looks like a card number' into 'is one'."""
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 13:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


# --------------------------------------------------------------------------
# Stage 1 — provider token patterns
# --------------------------------------------------------------------------

# (name, regex, severity, cwe, extra note)
PROVIDER_PATTERNS: list[tuple[str, re.Pattern[str], Severity, str]] = [
    ("AWS access key ID", re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"), Severity.CRITICAL, "CWE-798"),
    ("AWS secret access key", re.compile(r"(?i)aws.{0,20}?(?:secret|private).{0,20}?['\"]([A-Za-z0-9/+=]{40})['\"]"), Severity.CRITICAL, "CWE-798"),
    ("GitHub token", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,255})\b"), Severity.CRITICAL, "CWE-798"),
    ("GitHub fine-grained PAT", re.compile(r"\b(github_pat_[A-Za-z0-9_]{60,255})\b"), Severity.CRITICAL, "CWE-798"),
    ("Slack token", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,})\b"), Severity.CRITICAL, "CWE-798"),
    ("Slack webhook", re.compile(r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_/]+)"), Severity.HIGH, "CWE-798"),
    ("Stripe live key", re.compile(r"\b((?:sk|rk)_live_[A-Za-z0-9]{20,})\b"), Severity.CRITICAL, "CWE-798"),
    ("Stripe test key", re.compile(r"\b((?:sk|rk)_test_[A-Za-z0-9]{20,})\b"), Severity.MEDIUM, "CWE-798"),
    ("Google API key", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b"), Severity.HIGH, "CWE-798"),
    ("Google OAuth client secret", re.compile(r"\b(GOCSPX-[A-Za-z0-9_-]{28,})\b"), Severity.CRITICAL, "CWE-798"),
    ("SendGrid API key", re.compile(r"\b(SG\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})\b"), Severity.CRITICAL, "CWE-798"),
    ("Twilio API key", re.compile(r"\b(SK[0-9a-fA-F]{32})\b"), Severity.HIGH, "CWE-798"),
    ("Mailgun key", re.compile(r"\b(key-[0-9a-zA-Z]{32})\b"), Severity.HIGH, "CWE-798"),
    ("npm token", re.compile(r"\b(npm_[A-Za-z0-9]{36})\b"), Severity.CRITICAL, "CWE-798"),
    ("PyPI token", re.compile(r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,})\b"), Severity.CRITICAL, "CWE-798"),
    ("OpenAI-style API key", re.compile(r"\b(sk-[A-Za-z0-9]{32,})\b"), Severity.CRITICAL, "CWE-798"),
    ("JSON Web Token", re.compile(r"\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b"), Severity.HIGH, "CWE-522"),
    ("Database connection string with password", re.compile(r"\b((?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp)://[^:\s'\"]+:[^@\s'\"]{3,}@[^\s'\"]+)"), Severity.CRITICAL, "CWE-798"),
    ("Basic auth in URL", re.compile(r"\b(https?://[^:/\s'\"]+:[^@\s'\"]{3,}@[^\s'\"]+)"), Severity.HIGH, "CWE-598"),
]

PRIVATE_KEY_HEADER = re.compile(
    r"-----BEGIN\s+(RSA|DSA|EC|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE KEY(?: BLOCK)?-----"
)

SECRET_REMEDIATION = Remediation(
    summary="Move the credential out of source control and rotate it.",
    steps=[
        "Treat the credential as compromised — anything committed to a repo is public until proven otherwise. Rotate it at the provider first.",
        "Replace the literal with an environment variable read at startup (os.environ / process.env), or a secrets manager lookup (Vault, AWS Secrets Manager, Doppler).",
        "Add the config file holding it to .gitignore and commit a .env.example with empty placeholder values instead.",
        "Purge it from git history — `git filter-repo --invert-paths --path <file>` or BFG Repo-Cleaner. Deleting it in a new commit is not enough; the old blob is still fetchable.",
        "Add a pre-commit hook so the next one is blocked before it ever lands (see `pyrasec hook install`).",
    ],
    example=(
        "# before\n"
        'STRIPE_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"\n\n'  # pyrasec:ignore SEC001,SEC002
        "# after\n"
        "import os\n"
        'STRIPE_KEY = os.environ["STRIPE_KEY"]  # raises loudly if unset\n'
    ),
    references=[
        "https://cwe.mitre.org/data/definitions/798.html",
        "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
    ],
)


def _check_provider_tokens(record: FileRecord, text: str):
    test_path = in_test_path(record.path)
    for line_no, line in iter_lines(text):
        if len(line) > 4000:  # minified bundle — skip, it's all false positives
            continue
        for name, pattern, severity, cwe in PROVIDER_PATTERNS:
            for match in pattern.finditer(line):
                value = match.group(1)
                if looks_like_placeholder(value):
                    continue
                confidence = 0.55 if test_path else 1.0
                if is_comment(line):
                    confidence *= 0.8
                yield SECRET_PROVIDER_RULE.finding(
                    record.path,
                    line=line_no,
                    column=match.start(1) + 1,
                    evidence=redact(value, keep=6),
                    severity=severity if not test_path else Severity.MEDIUM,
                    confidence=confidence,
                    description=(
                        f"{name} found in source. Live provider credentials in a repository "
                        f"can be harvested by anyone with read access — including every fork, "
                        f"CI log and cached clone."
                    ),
                    metadata={"provider": name, "cwe": cwe, "context": snippet(line)},
                )


SECRET_PROVIDER_RULE = register(
    ContentRule(
        id="SEC001",
        title="Hardcoded provider credential",
        severity=Severity.CRITICAL,
        description="A recognised cloud or SaaS provider credential is embedded in source.",
        remediation=SECRET_REMEDIATION,
        cwe="CWE-798",
        owasp="A07:2021 Identification and Authentication Failures",
        mitre="T1552.001 Unsecured Credentials: Credentials In Files",
        cvss=9.1,
        tags=["secret", "credential"],
        check=_check_provider_tokens,
    )
)


# --------------------------------------------------------------------------
# Stage 2 — assignment heuristics
# --------------------------------------------------------------------------

SENSITIVE_NAMES = (
    "password", "passwd", "pwd", "secret", "api_key", "apikey", "api-key",
    "access_key", "accesskey", "auth_token", "authtoken", "token",
    "private_key", "privatekey", "client_secret", "clientsecret",
    "jwt_secret", "jwtsecret", "signing_key", "encryption_key",
    "db_password", "database_password", "credential", "passphrase",
    "master_key", "session_secret", "cookie_secret", "webhook_secret",
)

ASSIGNMENT = re.compile(
    r"""(?ix)
    \b(?P<name>[A-Za-z_][A-Za-z0-9_.\-]{0,40})   # variable / key name
    \s*[:=]{1,2}\s*                              # = := : =>
    (?P<quote>['"])(?P<value>[^'"\n]{6,200})(?P=quote)
    """
)


def _check_assignments(record: FileRecord, text: str):
    test_path = in_test_path(record.path)
    for line_no, line in iter_lines(text):
        if len(line) > 2000:
            continue
        for match in ASSIGNMENT.finditer(line):
            name = match.group("name").lower()
            value = match.group("value")
            if not any(marker in name for marker in SENSITIVE_NAMES):
                continue
            if looks_like_placeholder(value):
                continue
            if value.startswith(("http://", "https://")) and "@" not in value:
                continue

            entropy = shannon_entropy(value)
            long_enough = len(value) >= 12
            confidence = 0.9 if (long_enough and entropy > 3.2) else 0.55
            severity = Severity.CRITICAL if confidence >= 0.9 else Severity.HIGH
            if test_path:
                confidence *= 0.5
                severity = Severity.MEDIUM
            if is_comment(line):
                confidence *= 0.7

            yield SECRET_ASSIGNMENT_RULE.finding(
                record.path,
                line=line_no,
                column=match.start("value") + 1,
                evidence=redact(value),
                severity=severity,
                confidence=round(confidence, 2),
                description=(
                    f"The identifier `{match.group('name')}` is assigned a literal string value. "
                    f"Names like this hold credentials, and the value passed the placeholder and "
                    f"entropy filters (H={entropy:.2f} bits/char, length={len(value)})."
                ),
                metadata={
                    "identifier": match.group("name"),
                    "entropy": round(entropy, 3),
                    "length": len(value),
                    "context": snippet(line.replace(value, redact(value))),
                },
            )


SECRET_ASSIGNMENT_RULE = register(
    ContentRule(
        id="SEC002",
        title="Credential assigned to a literal",
        severity=Severity.HIGH,
        description="A variable whose name implies a credential is assigned a hardcoded string.",
        remediation=SECRET_REMEDIATION,
        cwe="CWE-798",
        owasp="A07:2021 Identification and Authentication Failures",
        mitre="T1552.001 Unsecured Credentials: Credentials In Files",
        cvss=8.2,
        tags=["secret", "credential"],
        check=_check_assignments,
    )
)


# --------------------------------------------------------------------------
# Private keys
# --------------------------------------------------------------------------


def _check_private_key_material(record: FileRecord, text: str):
    for line_no, line in iter_lines(text):
        match = PRIVATE_KEY_HEADER.search(line)
        if match:
            kind = (match.group(1) or "generic").upper()
            yield PRIVATE_KEY_RULE.finding(
                record.path,
                line=line_no,
                evidence=f"BEGIN {kind} PRIVATE KEY",
                description=(
                    f"A {kind} private key block is stored in this file. Private key material "
                    f"in a repository lets an attacker impersonate the server, sign artefacts, "
                    f"or decrypt captured traffic."
                ),
                metadata={"key_type": kind},
            )
            return  # one finding per file is enough


PRIVATE_KEY_RULE = register(
    ContentRule(
        id="SEC003",
        title="Private key material in repository",
        severity=Severity.CRITICAL,
        description="A PEM-encoded private key block was found inside a tracked file.",
        remediation=Remediation(
            summary="Rotate the key pair and store private keys outside the repo.",
            steps=[
                "Generate a new key pair and revoke/replace the old one everywhere it is trusted (authorized_keys, TLS termination, code signing).",
                "Store the private key in a secrets manager or on the host at 0600, injected at deploy time — never in git.",
                "Add `*.pem`, `*.key`, `id_rsa*`, `*.p12`, `*.pfx` to .gitignore.",
                "Scrub the key from git history with git filter-repo or BFG.",
            ],
            example="# .gitignore\n*.pem\n*.key\n*.p12\n*.pfx\nid_rsa*\n",
            references=["https://cwe.mitre.org/data/definitions/321.html"],
        ),
        cwe="CWE-321 Use of Hard-coded Cryptographic Key",
        owasp="A02:2021 Cryptographic Failures",
        mitre="T1552.004 Private Keys",
        cvss=9.8,
        tags=["secret", "crypto"],
        check=_check_private_key_material,
    )
)


# --------------------------------------------------------------------------
# Generic high-entropy strings (last resort, low confidence by design)
# --------------------------------------------------------------------------

QUOTED_STRING = re.compile(r"['\"]([A-Za-z0-9+/=_-]{24,120})['\"]")
ENTROPY_SKIP_EXTENSIONS = {".lock", ".min.js", ".map", ".svg", ".csv", ".po"}
ENTROPY_SKIP_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "gemfile.lock", "cargo.lock", "composer.lock", "go.sum",
}


def _check_entropy(record: FileRecord, text: str):
    if record.name.lower() in ENTROPY_SKIP_NAMES:
        return
    if record.extension in ENTROPY_SKIP_EXTENSIONS:
        return
    seen: set[str] = set()
    for line_no, line in iter_lines(text):
        if len(line) > 1000 or is_comment(line):
            continue
        for match in QUOTED_STRING.finditer(line):
            value = match.group(1)
            if value in seen or looks_like_placeholder(value):
                continue
            if not is_high_entropy(value, min_length=24):
                continue
            # Hashes and IDs are high entropy but usually harmless — only flag
            # when the surrounding line hints at authentication.
            context = line.lower()
            if not any(marker in context for marker in SENSITIVE_NAMES + ("auth", "bearer", "signature")):
                continue
            seen.add(value)
            yield ENTROPY_RULE.finding(
                record.path,
                line=line_no,
                column=match.start(1) + 1,
                evidence=redact(value),
                metadata={
                    "entropy": round(shannon_entropy(value), 3),
                    "length": len(value),
                    "context": snippet(line.replace(value, redact(value))),
                },
            )


ENTROPY_RULE = register(
    ContentRule(
        id="SEC004",
        title="High-entropy string near an auth keyword",
        severity=Severity.MEDIUM,
        description=(
            "A long, high-entropy literal appears on a line that mentions authentication. "
            "Reported at reduced confidence — verify before acting."
        ),
        remediation=SECRET_REMEDIATION,
        cwe="CWE-798",
        owasp="A07:2021 Identification and Authentication Failures",
        cvss=5.3,
        confidence=0.5,
        fast=False,
        tags=["secret", "entropy"],
        check=_check_entropy,
    )
)


# --------------------------------------------------------------------------
# Payment card data (PCI DSS relevance)
# --------------------------------------------------------------------------

CARD_CANDIDATE = re.compile(r"\b((?:\d[ -]?){13,19})\b")


def _check_card_numbers(record: FileRecord, text: str):
    for line_no, line in iter_lines(text):
        if len(line) > 2000:
            continue
        for match in CARD_CANDIDATE.finditer(line):
            raw = match.group(1)
            digits = re.sub(r"[ -]", "", raw)
            if len(digits) < 13 or len(digits) > 19:
                continue
            if not luhn_valid(digits):
                continue
            if digits.startswith(("4111111111", "5555555555", "4242424242", "378282246")):
                severity, confidence = Severity.LOW, 0.3  # well-known test PANs
            else:
                severity, confidence = Severity.HIGH, 0.8
            yield CARD_RULE.finding(
                record.path,
                line=line_no,
                evidence=f"{digits[:6]}{'*' * (len(digits) - 10)}{digits[-4:]}",
                severity=severity,
                confidence=confidence,
                metadata={"luhn_valid": True, "length": len(digits)},
            )


CARD_RULE = register(
    ContentRule(
        id="SEC005",
        title="Possible payment card number",
        severity=Severity.HIGH,
        description="A Luhn-valid 13-19 digit sequence was found — this may be cardholder data.",
        remediation=Remediation(
            summary="Remove cardholder data from source and storage you do not need to hold.",
            steps=[
                "Confirm whether this is real cardholder data or a test PAN.",
                "If real: PCI DSS 3.x forbids storing the PAN in source. Delete it, purge git history, and report per your incident process.",
                "Use tokenisation — let the payment processor hold the PAN and store only their token.",
                "If a card number is genuinely needed in a fixture, use a documented test PAN (4111 1111 1111 1111).",
            ],
            references=["https://www.pcisecuritystandards.org/"],
        ),
        cwe="CWE-311 Missing Encryption of Sensitive Data",
        owasp="A02:2021 Cryptographic Failures",
        cvss=7.5,
        fast=False,
        tags=["secret", "pci", "compliance"],
        check=_check_card_numbers,
    )
)


# --------------------------------------------------------------------------
# Key files by name — the walker sees these without opening them
# --------------------------------------------------------------------------

KEY_FILE_EXTENSIONS = {".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".ppk"}
KEY_FILE_NAMES = {"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".htpasswd", ".netrc", ".pgpass"}


def _check_key_files(record: FileRecord):
    if record.is_dir:
        return
    name = record.name.lower()
    if record.extension in KEY_FILE_EXTENSIONS or name in KEY_FILE_NAMES:
        yield KEY_FILE_RULE.finding(
            record.path,
            evidence=record.name,
            description=(
                f"`{record.name}` is a credential or key file. Its presence in the project "
                f"tree means it can be committed, copied into a container image, or served "
                f"by a misconfigured web root."
            ),
            metadata={"mode": record.mode_octal, "size": record.size},
        )


KEY_FILE_RULE = register(
    PathRule(
        id="SEC006",
        title="Credential file in project tree",
        severity=Severity.HIGH,
        description="A file whose name or extension marks it as key/credential material.",
        remediation=Remediation(
            summary="Move key files out of the project and ignore the pattern.",
            steps=[
                "Move the file outside the repository (e.g. ~/.ssh or a secrets mount).",
                "Add the extension to .gitignore so it cannot be re-added by accident.",
                "Add it to .dockerignore too — otherwise `COPY . .` bakes it into the image layer.",
                "Set filesystem permissions to 0600 wherever it does live.",
            ],
            example="# .gitignore and .dockerignore\n*.pem\n*.key\n*.p12\n.netrc\nid_rsa*\n",
        ),
        cwe="CWE-538 Insertion of Sensitive Information into Externally-Accessible File",
        owasp="A01:2021 Broken Access Control",
        mitre="T1552.004 Private Keys",
        cvss=7.5,
        tags=["secret", "filesystem"],
        check=_check_key_files,
    )
)

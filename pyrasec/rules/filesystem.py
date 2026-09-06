"""Filesystem posture rules — permissions, leftovers, and risky placement.

This is the part of PyraSec that no diff-based tool sees. A code review shows
you what changed inside a file; it never shows you that the file is 0777, that
it is called `db.sql.bak`, or that it is sitting three folders below `public/`.
"""

from __future__ import annotations

import stat

from ..core.models import FileRecord, Remediation, Severity
from .base import PathRule, ProjectRule, register

# --------------------------------------------------------------------------
# Permissions
# --------------------------------------------------------------------------

SENSITIVE_EXTENSIONS = {
    ".env", ".pem", ".key", ".p12", ".pfx", ".jks", ".sql", ".db",
    ".sqlite", ".sqlite3", ".yaml", ".yml", ".conf", ".cfg", ".ini",
}

SENSITIVE_NAMES = {
    ".env", ".env.local", ".env.production", ".env.prod", ".env.staging",
    "credentials", "secrets.json", "config.json", ".npmrc", ".pypirc",
    ".dockercfg", ".docker/config.json", "settings.py", "wp-config.php",
    ".htpasswd", ".netrc", "id_rsa", "known_hosts", "authorized_keys",
}


def _is_sensitive(record: FileRecord) -> bool:
    name = record.name.lower()
    return (
        name in SENSITIVE_NAMES
        or name.startswith(".env")
        or record.extension in SENSITIVE_EXTENSIONS
    )


def _check_world_writable(record: FileRecord):
    if record.is_symlink:
        return
    if not record.mode & stat.S_IWOTH:
        return
    sticky = bool(record.mode & stat.S_ISVTX)
    if record.is_dir and sticky:
        return  # /tmp-style dirs are intentional
    severity = Severity.CRITICAL if _is_sensitive(record) else Severity.HIGH
    target = "directory" if record.is_dir else "file"
    yield WORLD_WRITABLE_RULE.finding(
        record.path,
        evidence=f"mode {record.mode_octal}",
        severity=severity,
        description=(
            f"This {target} is writable by every user on the system (mode {record.mode_octal}). "
            f"Any local account, any compromised service, or any process escaping a container "
            f"onto the same host can overwrite it — turning a read-only foothold into code execution."
        ),
        metadata={"mode": record.mode_octal, "is_dir": record.is_dir},
    )


WORLD_WRITABLE_RULE = register(
    PathRule(
        id="FS001",
        title="World-writable path",
        severity=Severity.HIGH,
        description="The path grants write permission to the 'other' class.",
        remediation=Remediation(
            summary="Strip the world-writable bit.",
            steps=[
                "For files: `chmod o-w <path>` (or `chmod 640` for config, `644` for public assets).",
                "For directories: `chmod 755 <dir>` — or `chmod 1777` only if it genuinely needs to be a shared scratch dir.",
                "Set the process umask to 027 so new files are never created group/world-writable.",
                "In a Dockerfile, add an explicit `RUN chmod -R go-w /app` after COPY, and run as a non-root USER.",
            ],
            example="chmod 640 config/.env\nchmod 750 scripts/\numask 027",
            references=["https://cwe.mitre.org/data/definitions/732.html"],
        ),
        cwe="CWE-732 Incorrect Permission Assignment for Critical Resource",
        owasp="A01:2021 Broken Access Control",
        mitre="T1222 File and Directory Permissions Modification",
        cvss=7.8,
        tags=["permissions", "filesystem"],
        check=_check_world_writable,
    )
)


def _check_sensitive_readable(record: FileRecord):
    if record.is_dir or record.is_symlink:
        return
    if not _is_sensitive(record):
        return
    if not record.mode & stat.S_IROTH:
        return
    yield SENSITIVE_READABLE_RULE.finding(
        record.path,
        evidence=f"mode {record.mode_octal}",
        description=(
            f"`{record.name}` holds configuration or credential material but is readable by "
            f"every user (mode {record.mode_octal}). On a shared host or a multi-tenant "
            f"container this is a direct credential disclosure."
        ),
        metadata={"mode": record.mode_octal},
    )


SENSITIVE_READABLE_RULE = register(
    PathRule(
        id="FS002",
        title="Sensitive file is world-readable",
        severity=Severity.MEDIUM,
        description="A config or credential file grants read access to 'other'.",
        remediation=Remediation(
            summary="Restrict to owner (and group where needed).",
            steps=[
                "`chmod 600 <file>` for pure secrets, `640` where a service group must read it.",
                "Confirm ownership with `chown app:app <file>` so the restricted mode is actually useful.",
                "Prefer injecting these values as environment variables or a mounted secret rather than a file on disk.",
            ],
            example="chmod 600 .env\nchown app:app .env",
        ),
        cwe="CWE-732 Incorrect Permission Assignment for Critical Resource",
        owasp="A01:2021 Broken Access Control",
        cvss=6.5,
        tags=["permissions", "filesystem"],
        check=_check_sensitive_readable,
    )
)


def _check_setuid(record: FileRecord):
    if record.is_dir or record.is_symlink:
        return
    if record.mode & (stat.S_ISUID | stat.S_ISGID):
        bit = "setuid" if record.mode & stat.S_ISUID else "setgid"
        yield SETUID_RULE.finding(
            record.path,
            evidence=f"mode {record.mode_octal} ({bit})",
            description=(
                f"`{record.name}` carries the {bit} bit. It executes with the owner's privileges "
                f"regardless of who runs it — a classic local privilege escalation primitive if "
                f"the binary is writable, vulnerable, or invokes anything from $PATH."
            ),
            metadata={"mode": record.mode_octal, "bit": bit},
        )


SETUID_RULE = register(
    PathRule(
        id="FS003",
        title="setuid/setgid binary in project tree",
        severity=Severity.HIGH,
        description="An executable in the project carries setuid or setgid.",
        remediation=Remediation(
            summary="Remove the bit unless it is genuinely required and audited.",
            steps=[
                "`chmod u-s,g-s <file>` unless the elevation is deliberate and documented.",
                "If elevation is required, use Linux capabilities instead: `setcap cap_net_bind_service=+ep <file>`.",
                "Add `--security-opt=no-new-privileges` to container runs so setuid cannot be exploited inside.",
            ],
            example="chmod u-s,g-s ./bin/helper\nsetcap cap_net_bind_service=+ep ./bin/server",
        ),
        cwe="CWE-250 Execution with Unnecessary Privileges",
        owasp="A04:2021 Insecure Design",
        mitre="T1548.001 Setuid and Setgid",
        cvss=7.8,
        tags=["permissions", "privesc"],
        check=_check_setuid,
    )
)


# --------------------------------------------------------------------------
# Leftover artefacts
# --------------------------------------------------------------------------

LEFTOVER_SUFFIXES = (
    ".bak", ".backup", ".old", ".orig", ".save", ".swp", ".swo", ".tmp",
    ".temp", ".copy", ".rej", ".dump", ".sql.gz", "~",
)
LEFTOVER_MARKERS = (".bak.", ".old.", "-backup", "_backup", "copy of ", " copy.")
DUMP_EXTENSIONS = {".sql", ".dump", ".sqlite", ".sqlite3", ".db", ".mdb", ".bson"}
LOG_EXTENSIONS = {".log", ".out", ".err"}
MERGE_CONFLICT_SUFFIXES = (".orig", ".rej", ".LOCAL", ".REMOTE", ".BASE")


def _check_leftovers(record: FileRecord):
    if record.is_dir:
        return
    name = record.name.lower()

    if name.endswith(LEFTOVER_SUFFIXES) or any(m in name for m in LEFTOVER_MARKERS):
        yield LEFTOVER_RULE.finding(
            record.path,
            evidence=record.name,
            description=(
                f"`{record.name}` looks like an editor or manual backup. Backups of source files "
                f"are served as plain text by most web servers (they have no handler mapping), so "
                f"`config.php.bak` hands over the source that `config.php` would have executed."
            ),
            metadata={"size": record.size, "mode": record.mode_octal},
        )

    if record.extension in DUMP_EXTENSIONS and record.size > 1024:
        yield DB_DUMP_RULE.finding(
            record.path,
            evidence=f"{record.name} ({record.size // 1024} KB)",
            description=(
                f"`{record.name}` is a database file or dump ({record.size // 1024} KB). "
                f"Dumps carry production rows — user records, password hashes, tokens — and are "
                f"one of the first paths an attacker requests."
            ),
            metadata={"size": record.size},
        )

    if record.extension in LOG_EXTENSIONS and record.size > 0:
        yield LOG_FILE_RULE.finding(
            record.path,
            evidence=record.name,
            metadata={"size": record.size},
        )

    if name.endswith(MERGE_CONFLICT_SUFFIXES):
        yield MERGE_ARTIFACT_RULE.finding(record.path, evidence=record.name)


LEFTOVER_RULE = register(
    PathRule(
        id="FS010",
        title="Backup or editor leftover file",
        severity=Severity.MEDIUM,
        description="A .bak/.old/.orig/~ style file is present in the tree.",
        remediation=Remediation(
            summary="Delete it; let version control be the backup.",
            steps=[
                "Delete the file — git already holds every previous version.",
                "Add the patterns to .gitignore: `*.bak`, `*.old`, `*.orig`, `*~`, `*.swp`.",
                "Configure the web server to refuse these extensions outright as defence in depth.",
                "Add the same patterns to .dockerignore so they never reach an image.",
            ],
            example=(
                "# nginx — deny leftovers even if one slips through\n"
                "location ~* \\.(bak|old|orig|save|swp|tmp)$ {\n"
                "    deny all;\n"
                "    return 404;\n"
                "}\n"
            ),
        ),
        cwe="CWE-530 Exposure of Backup File to an Unauthorized Control Sphere",
        owasp="A05:2021 Security Misconfiguration",
        mitre="T1083 File and Directory Discovery",
        cvss=5.3,
        tags=["leftover", "filesystem"],
        check=_check_leftovers,
    )
)

DB_DUMP_RULE = register(
    PathRule(
        id="FS011",
        title="Database file or dump in project",
        severity=Severity.HIGH,
        description="A .sql/.dump/.sqlite file is present in the project tree.",
        remediation=Remediation(
            summary="Move dumps out of the repo and out of the web root.",
            steps=[
                "Delete the dump from the tree; store backups in object storage with server-side encryption and restricted IAM.",
                "Add `*.sql`, `*.dump`, `*.sqlite*` to .gitignore — but keep intentional migration files, which belong in a `migrations/` folder.",
                "If it was ever committed, treat every credential and hash inside as compromised and purge git history.",
                "Never place dumps under a directory the web server can serve.",
            ],
            example="# .gitignore\n*.sql\n*.dump\n*.sqlite3\n!migrations/*.sql\n",
        ),
        cwe="CWE-538 Insertion of Sensitive Information into Externally-Accessible File",
        owasp="A01:2021 Broken Access Control",
        cvss=7.5,
        tags=["leftover", "data", "filesystem"],
        check=_check_leftovers,  # shared dispatcher, see note below
    )
)

LOG_FILE_RULE = register(
    PathRule(
        id="FS012",
        title="Log file committed to project",
        severity=Severity.LOW,
        description="Application logs are present in the tree.",
        remediation=Remediation(
            summary="Ship logs to a log system, not to the repo.",
            steps=[
                "Delete the log file and add `*.log`, `logs/` to .gitignore.",
                "Write logs to stdout/stderr and let the platform collect them (12-factor).",
                "Check the contents before deleting — logs routinely capture tokens, session IDs and full request bodies.",
            ],
            example="# .gitignore\n*.log\nlogs/\nnpm-debug.log*\n",
        ),
        cwe="CWE-532 Insertion of Sensitive Information into Log File",
        owasp="A09:2021 Security Logging and Monitoring Failures",
        cvss=3.7,
        tags=["leftover", "filesystem"],
        check=_check_leftovers,
    )
)

MERGE_ARTIFACT_RULE = register(
    PathRule(
        id="FS013",
        title="Merge conflict artefact",
        severity=Severity.LOW,
        description="A .orig/.rej/.LOCAL file left behind by a merge tool.",
        remediation=Remediation(
            summary="Delete it and add the pattern to .gitignore.",
            steps=[
                "Delete the file; the merge is already resolved in the tracked version.",
                "Add `*.orig`, `*.rej`, `*.BACKUP.*`, `*.LOCAL.*`, `*.REMOTE.*` to .gitignore.",
            ],
        ),
        cwe="CWE-530 Exposure of Backup File to an Unauthorized Control Sphere",
        owasp="A05:2021 Security Misconfiguration",
        cvss=3.1,
        tags=["leftover", "filesystem"],
        check=_check_leftovers,
    )
)

# The four leftover rules share one dispatcher so each file is classified once.
# Only FS010 is wired into the scanner; the others are referenced by it.
for _rule in (DB_DUMP_RULE, LOG_FILE_RULE, MERGE_ARTIFACT_RULE):
    _rule.check = None


# --------------------------------------------------------------------------
# Risky placement — the relational rule the pitch deck calls out
# --------------------------------------------------------------------------

PUBLIC_DIRS = {
    "public", "static", "assets", "www", "htdocs", "web", "wwwroot",
    "dist", "build", "docs", "site", "_site", "out",
}

SECRET_FILE_MARKERS = (".env", "secret", "credential", "config.json", ".pem", ".key", "backup")


def _check_placement(records: list[FileRecord]):
    for record in records:
        if record.is_dir:
            continue
        parts = record.path.lower().split("/")
        if len(parts) < 2:
            continue
        public_ancestor = next((p for p in parts[:-1] if p in PUBLIC_DIRS), None)
        if not public_ancestor:
            continue
        name = parts[-1]
        if not any(marker in name for marker in SECRET_FILE_MARKERS):
            continue
        yield PLACEMENT_RULE.finding(
            record.path,
            evidence=f"{public_ancestor}/ → {record.name}",
            description=(
                f"`{record.name}` sits inside `{public_ancestor}/`, a directory that is normally "
                f"served directly by the web server or copied verbatim into a CDN. Anyone who "
                f"guesses the path can fetch the file — no authentication involved."
            ),
            metadata={"public_dir": public_ancestor},
        )


PLACEMENT_RULE = register(
    ProjectRule(
        id="FS020",
        title="Sensitive file inside a publicly served directory",
        severity=Severity.CRITICAL,
        description="A config/credential/backup file is located under a public asset directory.",
        remediation=Remediation(
            summary="Move it above the web root; never rely on obscurity.",
            steps=[
                "Move the file outside the served directory entirely — one level above the web root, or into a config volume.",
                "Rotate anything it contains: assume it has already been fetched.",
                "Add an explicit deny rule in the server config for dotfiles and config extensions inside the public path.",
                "In SPA builds, confirm the bundler is not copying `.env` into `dist/` — Vite only exposes `VITE_`-prefixed vars, CRA only `REACT_APP_`, and both still inline them into the client bundle.",
            ],
            example=(
                "# nginx\n"
                "location ~ /\\.(?!well-known) { deny all; return 404; }\n"
                "location ~* \\.(env|ini|conf|sql|bak|pem|key)$ { deny all; return 404; }\n"
            ),
            references=["https://owasp.org/Top10/A01_2021-Broken_Access_Control/"],
        ),
        cwe="CWE-552 Files or Directories Accessible to External Parties",
        owasp="A01:2021 Broken Access Control",
        mitre="T1083 File and Directory Discovery",
        cvss=9.1,
        tags=["placement", "filesystem", "exposure"],
        check=_check_placement,
    )
)

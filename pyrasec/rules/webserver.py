"""Web server configuration rules — nginx and Apache.

The web server is the last thing between a misplaced file and the internet,
so these rules pull double duty: they catch dangerous directives, and they
catch the *absence* of the deny rules that would have neutralised several
findings from the filesystem module.
"""

from __future__ import annotations

import re

from ..core.models import FileRecord, Remediation, Severity
from .base import ContentRule, iter_lines, register

NGINX_NAMES = {"nginx.conf", "default.conf", "site.conf", "app.conf"}
NGINX_EXT = {".conf"}
APACHE_NAMES = {".htaccess", "httpd.conf", "apache2.conf", "000-default.conf"}

HARDEN_REMEDIATION = Remediation(
    summary="Harden the server block: deny dotfiles, hide the banner, add security headers.",
    steps=[
        "Deny dotfiles and config extensions explicitly — this single block neutralises most 'file exposed in public folder' findings.",
        "Turn off directory listing (`autoindex off` / `Options -Indexes`).",
        "Suppress the version banner (`server_tokens off` / `ServerTokens Prod`).",
        "Add HSTS, X-Content-Type-Options, X-Frame-Options and a Content-Security-Policy.",
        "Reload and verify with `curl -I https://yoursite/.env` — expect 404, not 200.",
    ],
    example=(
        "server_tokens off;\n"
        "autoindex off;\n\n"
        "location ~ /\\.(?!well-known) { deny all; return 404; }\n"
        "location ~* \\.(env|ini|conf|cfg|sql|bak|old|orig|swp|log|pem|key)$ { deny all; return 404; }\n"
        "location ~ /\\.git { deny all; return 404; }\n\n"
        'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;\n'
        'add_header X-Content-Type-Options "nosniff" always;\n'
        'add_header X-Frame-Options "DENY" always;\n'
        "add_header Content-Security-Policy \"default-src 'self'\" always;\n"
    ),
    references=["https://owasp.org/www-project-secure-headers/"],
)

NGINX_PATTERNS: list[tuple[str, re.Pattern[str], Severity, str, str]] = [
    ("WEB001", re.compile(r"(?i)^\s*autoindex\s+on\s*;"), Severity.MEDIUM,
     "Directory listing enabled",
     "autoindex on turns any directory without an index file into a browsable file listing, handing an attacker a map of the deployment."),
    ("WEB002", re.compile(r"(?i)^\s*server_tokens\s+on\s*;"), Severity.LOW,
     "Server version disclosed",
     "The exact nginx version is advertised in responses, letting an attacker match it against known CVEs without probing."),
    ("WEB003", re.compile(r"(?i)ssl_protocols[^;]*\b(SSLv2|SSLv3|TLSv1|TLSv1\.1)\b"), Severity.HIGH,
     "Obsolete TLS protocol enabled",
     "SSLv3/TLS 1.0/1.1 are deprecated and vulnerable to downgrade and padding attacks; modern clients already refuse them."),
    ("WEB004", re.compile(r"(?i)^\s*ssl_verify_client\s+off"), Severity.LOW,
     "Client certificate verification off",
     "Only relevant where mTLS was intended; confirm this endpoint does not rely on client certs for authentication."),
    ("WEB005", re.compile(r"(?i)add_header\s+Access-Control-Allow-Origin\s+[\"']?\*"), Severity.MEDIUM,
     "Wildcard CORS origin",
     "Any site can read responses from this origin. If the endpoint returns user data, that is a cross-origin data leak."),
    ("WEB006", re.compile(r"(?i)^\s*proxy_pass\s+http://\$"), Severity.HIGH,
     "proxy_pass to a variable target",
     "A proxy target built from a request variable enables server-side request forgery and open-proxy abuse."),
]

_NGINX_RULES: dict[str, ContentRule] = {}


def _looks_like_nginx(text: str) -> bool:
    return bool(re.search(r"(?m)^\s*(server|http|location|upstream)\s*\{", text))


def _check_nginx(record: FileRecord, text: str):
    if not _looks_like_nginx(text):
        return
    for line_no, raw in iter_lines(text):
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for rule_id, pattern, _s, _t, _d in NGINX_PATTERNS:
            if pattern.search(line):
                yield _NGINX_RULES[rule_id].finding(
                    record.path, line=line_no, evidence=stripped[:120]
                )

    # Absence checks — only meaningful once we know it's a real server config.
    if "server {" in text or re.search(r"(?m)^\s*server\s*\{", text):
        if not re.search(r"location\s*~\s*/\\?\.", text):
            yield _NGINX_RULES["WEB010"].finding(
                record.path,
                evidence="no dotfile deny block",
                description=(
                    "This nginx config has no rule denying dotfiles. Without it, `/.env`, `/.git/config` "
                    "and `/.htpasswd` are served as plain text if they exist anywhere under the root."
                ),
            )
        if "Strict-Transport-Security" not in text and "ssl_certificate" in text:
            yield _NGINX_RULES["WEB011"].finding(
                record.path, evidence="no Strict-Transport-Security header"
            )


for _id, _pat, _sev, _title, _desc in NGINX_PATTERNS:
    _NGINX_RULES[_id] = register(
        ContentRule(
            id=_id,
            title=_title,
            severity=_sev,
            description=_desc,
            remediation=HARDEN_REMEDIATION,
            cwe="CWE-16 Configuration",
            owasp="A05:2021 Security Misconfiguration",
            cvss=_sev.cvss_base,
            extensions=set(NGINX_EXT),
            filenames=set(NGINX_NAMES),
            tags=["webserver", "nginx", "config"],
            check=_check_nginx if _id == "WEB001" else None,
        )
    )

_NGINX_RULES["WEB010"] = register(
    ContentRule(
        id="WEB010",
        title="No dotfile deny rule in nginx config",
        severity=Severity.HIGH,
        description="The server block does not block requests for dotfiles.",
        remediation=HARDEN_REMEDIATION,
        cwe="CWE-552 Files or Directories Accessible to External Parties",
        owasp="A01:2021 Broken Access Control",
        cvss=7.5,
        extensions=set(NGINX_EXT),
        filenames=set(NGINX_NAMES),
        tags=["webserver", "nginx", "exposure"],
    )
)

_NGINX_RULES["WEB011"] = register(
    ContentRule(
        id="WEB011",
        title="HTTPS enabled without HSTS",
        severity=Severity.MEDIUM,
        description="TLS is configured but Strict-Transport-Security is not sent.",
        remediation=HARDEN_REMEDIATION,
        cwe="CWE-319 Cleartext Transmission of Sensitive Information",
        owasp="A02:2021 Cryptographic Failures",
        cvss=5.3,
        extensions=set(NGINX_EXT),
        filenames=set(NGINX_NAMES),
        tags=["webserver", "nginx", "crypto"],
    )
)


# --------------------------------------------------------------------------
# Apache
# --------------------------------------------------------------------------

APACHE_PATTERNS: list[tuple[str, re.Pattern[str], Severity, str, str]] = [
    ("WEB020", re.compile(r"(?i)^\s*Options[^\n]*\+?Indexes"), Severity.MEDIUM,
     "Apache directory indexing enabled",
     "`Options +Indexes` produces a browsable listing for directories without an index file."),
    ("WEB021", re.compile(r"(?i)^\s*ServerTokens\s+(Full|OS|Minor|Minimal)"), Severity.LOW,
     "Apache version disclosed",
     "ServerTokens is set above Prod, advertising the server and OS version in every response."),
    ("WEB022", re.compile(r"(?i)^\s*ServerSignature\s+On"), Severity.LOW,
     "Server signature on error pages",
     "Error pages append the server version and hostname."),
    ("WEB023", re.compile(r"(?i)AllowOverride\s+All"), Severity.LOW,
     "AllowOverride All",
     "Any writable directory can then change server behaviour through a dropped .htaccess file."),
    ("WEB024", re.compile(r"(?i)^\s*Options[^\n]*\+?ExecCGI"), Severity.MEDIUM,
     "CGI execution enabled",
     "Combined with an upload directory this turns a file upload into remote code execution."),
]

_APACHE_RULES: dict[str, ContentRule] = {}

APACHE_REMEDIATION = Remediation(
    summary="Tighten Options, hide the banner, deny sensitive extensions.",
    steps=[
        "Set `Options -Indexes -ExecCGI` on served directories.",
        "Set `ServerTokens Prod` and `ServerSignature Off` in the main config.",
        "Add a FilesMatch block denying config, backup and key extensions.",
        "Prefer main-config directives over .htaccess: they are faster and cannot be overridden by a dropped file.",
    ],
    example=(
        "ServerTokens Prod\n"
        "ServerSignature Off\n"
        "<Directory /var/www/html>\n"
        "    Options -Indexes -ExecCGI\n"
        "    AllowOverride None\n"
        "</Directory>\n"
        '<FilesMatch "(^\\.|\\.(env|ini|conf|sql|bak|old|log|pem|key)$)">\n'
        "    Require all denied\n"
        "</FilesMatch>\n"
    ),
)


def _check_apache(record: FileRecord, text: str):
    for line_no, raw in iter_lines(text):
        line = raw.rstrip()
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for rule_id, pattern, _s, _t, _d in APACHE_PATTERNS:
            if pattern.search(line):
                yield _APACHE_RULES[rule_id].finding(
                    record.path, line=line_no, evidence=stripped[:120]
                )


for _id, _pat, _sev, _title, _desc in APACHE_PATTERNS:
    _APACHE_RULES[_id] = register(
        ContentRule(
            id=_id,
            title=_title,
            severity=_sev,
            description=_desc,
            remediation=APACHE_REMEDIATION,
            cwe="CWE-16 Configuration",
            owasp="A05:2021 Security Misconfiguration",
            cvss=_sev.cvss_base,
            filenames=set(APACHE_NAMES),
            extensions={".htaccess"},
            tags=["webserver", "apache", "config"],
            check=_check_apache if _id == "WEB020" else None,
        )
    )

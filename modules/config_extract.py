"""Config/backup file extraction.

dir_enum and wordpress_enum already *detect* exposed backup/config files
(.env, wp-config.php.bak, .git/config, etc.) but stop at flagging them.
This module takes those hits, downloads the body, and parses out
credentials/secrets so the pentest assistant can use them directly
(e.g. for credential reuse against other services).
"""

import re

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from modules import wordlist_tools

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

CONFIG_FILE_SIGNATURES = (
    ".env", ".bak", ".old", ".orig", ".swp", ".save", "~",
    "config.php", "wp-config", "settings.py", "web.config",
    "database.yml", "credentials", ".git/config",
)

KEY_VALUE_PATTERNS = [
    re.compile(r"(?im)^\s*(DB_PASSWORD|DATABASE_PASSWORD|DB_PASS)\s*=\s*['\"]?([^'\"\n#]+)"),
    re.compile(r"(?im)^\s*(DB_USER(?:NAME)?|DATABASE_USER)\s*=\s*['\"]?([^'\"\n#]+)"),
    re.compile(r"(?im)^\s*(API_KEY|SECRET_KEY|APP_KEY|AUTH_KEY|JWT_SECRET)\s*=\s*['\"]?([^'\"\n#]+)"),
    re.compile(r"(?im)^\s*(AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY)\s*=\s*['\"]?([^'\"\n#]+)"),
    re.compile(r"define\(\s*['\"]DB_PASSWORD['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)"),
    re.compile(r"define\(\s*['\"]DB_USER['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)"),
]

GENERIC_PASSWORD_PATTERN = re.compile(r"(?i)password\s*[:=]\s*['\"]?([^'\"\s]+)")


def is_config_hit(path):
    lowered = path.lower()
    return any(sig in lowered for sig in CONFIG_FILE_SIGNATURES)


def _get(url, timeout=8):
    try:
        return requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
    except requests.RequestException:
        return None


def extract_secrets(text):
    secrets = {}
    for pattern in KEY_VALUE_PATTERNS:
        for match in pattern.finditer(text):
            groups = match.groups()
            if len(groups) == 2:
                key, value = groups
            else:
                key, value = pattern.pattern[:20], groups[0]
            value = value.strip()
            if value and len(value) < 200:
                secrets.setdefault(key.upper(), value)
    creds = wordlist_tools.extract_credentials(text)
    return secrets, creds


def harvest(dir_hits, report=None):
    """Download every dir-enum hit that looks like a config/backup file
    and extract any credentials/secrets found. Returns a list of
    {'url', 'secrets', 'credentials'} for hits that yielded something."""
    results = []
    for hit in dir_hits or []:
        if not is_config_hit(hit.get("path", "")):
            continue
        resp = _get(hit["url"])
        if not resp or resp.status_code != 200 or not resp.text:
            continue

        secrets, creds = extract_secrets(resp.text)
        if not secrets and not creds:
            continue

        results.append({"url": hit["url"], "secrets": secrets, "credentials": creds})
        if report:
            parts = []
            if secrets:
                parts.append(", ".join(f"{k}={v}" for k, v in secrets.items()))
            if creds:
                parts.append(", ".join(f"{c['username']}:{c['password']}" for c in creds))
            report.add_finding(
                "Config Extraction",
                f"Credentials/secrets extracted from exposed file: {hit['url']}",
                "; ".join(parts), "CRITICAL", vuln_id="config_file_leaked",
            )
    return results

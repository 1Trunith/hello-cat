"""Common vulnerability checks module for Hello Cat.

Lightweight, signature-based checks for well-known misconfigurations and
CVEs that are frequently seen in TryHackMe / CTF-style boxes. These are
intentionally non-destructive (no exploitation, just detection probes).
"""

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


def _get(url, timeout=5):
    try:
        return requests.get(url, timeout=timeout, verify=False, allow_redirects=False)
    except requests.RequestException:
        return None


def check_anonymous_ftp(target, open_ports, report=None):
    if not any(p["port"] == 21 for p in open_ports):
        return
    import ftplib
    try:
        ftp = ftplib.FTP(timeout=5)
        ftp.connect(target, 21)
        ftp.login("anonymous", "anonymous@")
        ftp.quit()
        if report:
            report.add_finding("Vulnerability Check", "Anonymous FTP login allowed",
                                "FTP server accepts anonymous credentials", "HIGH")
    except Exception:
        pass


def check_smb_signing(target, open_ports, report=None):
    if not any(p["port"] in (139, 445) for p in open_ports):
        return
    if report:
        report.add_finding("Vulnerability Check", "SMB service exposed",
                            "Ports 139/445 open - consider enum4linux/smbclient/smbmap for "
                            "null session, share enumeration, and EternalBlue/MS17-010 checks",
                            "MEDIUM")


def check_http_methods(base_url, report=None):
    try:
        resp = requests.options(base_url, timeout=5, verify=False)
    except requests.RequestException:
        return
    allow = resp.headers.get("Allow", "")
    risky = {"PUT", "DELETE", "TRACE"}
    found = [m for m in risky if m in allow]
    if found and report:
        report.add_finding("Vulnerability Check", f"Risky HTTP methods enabled: {', '.join(found)}",
                            f"Allow header: {allow}", "MEDIUM")


def check_security_headers(base_url, report=None):
    resp = _get(base_url)
    if not resp:
        return
    missing = []
    for header in ("X-Frame-Options", "X-Content-Type-Options",
                   "Content-Security-Policy", "Strict-Transport-Security"):
        if header not in resp.headers:
            missing.append(header)
    if missing and report:
        report.add_finding("Vulnerability Check", "Missing security headers",
                            f"Missing: {', '.join(missing)}", "LOW")


def check_default_creds_pages(dir_hits, report=None):
    default_cred_paths = {"phpmyadmin", "wp-login.php", "admin", "manager", "cpanel"}
    for hit in dir_hits:
        if hit["path"].lower() in default_cred_paths and hit["status"] in (200, 401):
            if report:
                report.add_finding("Vulnerability Check",
                                    f"Login panel exposed: /{hit['path']}",
                                    "Consider testing default/weak credentials "
                                    "(authorized lab environment only)", "MEDIUM")


def run_checks(target, base_url, open_ports, dir_hits, report=None):
    check_anonymous_ftp(target, open_ports, report=report)
    check_smb_signing(target, open_ports, report=report)
    check_http_methods(base_url, report=report)
    check_security_headers(base_url, report=report)
    check_default_creds_pages(dir_hits, report=report)

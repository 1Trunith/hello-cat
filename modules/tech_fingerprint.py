"""Technology fingerprinting module for Hello Cat.

Inspects HTTP response headers and body for server software, frameworks,
and CMS signatures.
"""

import re

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

BODY_SIGNATURES = {
    r"wp-content|wp-includes": "WordPress",
    r"Joomla!": "Joomla",
    r"Drupal.settings": "Drupal",
    r"laravel_session": "Laravel (PHP)",
    r"csrftoken": "Django",
    r"__NEXT_DATA__": "Next.js",
    r"ng-version": "Angular",
    r"react": "React",
    r"jquery": "jQuery",
    r"bootstrap": "Bootstrap",
    r"phpMyAdmin": "phpMyAdmin",
    r"Powered by Tomcat": "Apache Tomcat",
}

OUTDATED_HINTS = {
    "apache/2.2": ("MEDIUM", "Apache 2.2.x is end-of-life; check for known CVEs"),
    "apache/2.4.7": ("MEDIUM", "Apache 2.4.7 has known vulnerabilities"),
    "nginx/1.1": ("MEDIUM", "Old nginx version; check for known CVEs"),
    "php/5": ("HIGH", "PHP 5.x is end-of-life and unsupported"),
    "php/7.0": ("MEDIUM", "PHP 7.0 is end-of-life"),
    "microsoft-iis/6.0": ("HIGH", "IIS 6.0 is very old and vulnerable to multiple CVEs"),
    "openssl/0.9": ("CRITICAL", "Ancient OpenSSL, likely vulnerable to Heartbleed and others"),
    "openssl/1.0.1": ("HIGH", "OpenSSL 1.0.1 may be vulnerable to Heartbleed (CVE-2014-0160)"),
}


def fingerprint(target, scheme="http", port=None, report=None):
    base_url = f"{scheme}://{target}"
    if port and port not in (80, 443):
        base_url += f":{port}"

    tech_found = set()
    try:
        resp = requests.get(base_url, timeout=6, verify=False, allow_redirects=True)
    except requests.RequestException as exc:
        if report:
            report.add_finding("Technology Fingerprinting", "HTTP request failed",
                                str(exc), "INFO")
        return [], base_url

    headers = resp.headers
    server = headers.get("Server", "")
    powered_by = headers.get("X-Powered-By", "")

    if server:
        tech_found.add(f"Server: {server}")
    if powered_by:
        tech_found.add(f"X-Powered-By: {powered_by}")

    for header_name in ("X-AspNet-Version", "X-Generator", "X-Drupal-Cache"):
        if header_name in headers:
            tech_found.add(f"{header_name}: {headers[header_name]}")

    body = resp.text[:200000] if resp.text else ""
    for pattern, name in BODY_SIGNATURES.items():
        if re.search(pattern, body, re.IGNORECASE):
            tech_found.add(name)

    if report:
        report.set_section("tech_fingerprint", {
            "base_url": base_url,
            "status_code": resp.status_code,
            "technologies": sorted(tech_found),
            "headers": dict(headers),
        })
        if not tech_found:
            report.add_finding("Technology Fingerprinting", "No clear technology signatures found",
                                f"{base_url} returned HTTP {resp.status_code}", "INFO")
        for tech in sorted(tech_found):
            report.add_finding("Technology Fingerprinting", tech, f"Detected at {base_url}", "INFO")

        combined = f"{server} {powered_by}".lower()
        for sig, (sev, desc) in OUTDATED_HINTS.items():
            if sig in combined:
                report.add_finding("Technology Fingerprinting", f"Potentially outdated: {sig}",
                                    desc, sev)

    return sorted(tech_found), base_url

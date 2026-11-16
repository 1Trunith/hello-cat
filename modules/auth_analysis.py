import re

import requests
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

LOGIN_PATH_HINTS = [
    "login", "signin", "sign-in", "admin", "administrator", "wp-login.php",
    "user/login", "accounts/login", "panel", "cpanel", "dashboard",
]

SQL_ERROR_SIGNATURES = [
    r"SQL syntax.*MySQL", r"Warning.*mysqli?_", r"mysql_fetch",
    r"valid MySQL result", r"ORA-\d{5}", r"Microsoft OLE DB Provider for ODBC Drivers",
    r"Unclosed quotation mark", r"PostgreSQL.*ERROR", r"org\.postgresql\.util\.PSQLException",
    r"SQLite/JDBCDriver", r"SQLite\.Exception", r"System\.Data\.SQLite\.SQLiteException",
    r"Warning.*pg_",
]

SQLI_PAYLOAD = "'"
COMMON_INJECTABLE_PARAMS = ["id", "page", "cat", "category", "search", "q", "query", "item", "product"]

DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("administrator", "administrator"),
    ("root", "root"),
    ("root", "toor"),
    ("admin", ""),
    ("test", "test"),
    ("guest", "guest"),
    ("admin", "changeme"),
]


def _get(url, timeout=6, **kwargs):
    try:
        return requests.get(url, timeout=timeout, verify=False, allow_redirects=False, **kwargs)
    except requests.RequestException:
        return None


def discover_login_forms(base_url, dir_hits=None):
    candidates = set()
    for hint in LOGIN_PATH_HINTS:
        candidates.add(f"{base_url}/{hint}")
    if dir_hits:
        for hit in dir_hits:
            path_lower = hit["path"].lower()
            if any(h in path_lower for h in ("login", "admin", "signin", "panel", "cpanel")):
                candidates.add(hit["url"])

    confirmed = []
    for url in candidates:
        resp = _get(url)
        if not resp or resp.status_code >= 500:
            continue
        if resp.status_code in (200, 401, 403) or (300 <= resp.status_code < 400):
            body = (resp.text or "").lower()
            if "password" in body or "login" in body or resp.status_code in (401, 403):
                confirmed.append(url)
    return confirmed


def check_sql_injection(base_url, report=None):
    findings = []
    for param in COMMON_INJECTABLE_PARAMS:
        test_url = f"{base_url}/?{param}=1{SQLI_PAYLOAD}"
        resp = _get(test_url, allow_redirects=True)
        if not resp or not resp.text:
            continue
        for pattern in SQL_ERROR_SIGNATURES:
            if re.search(pattern, resp.text, re.IGNORECASE):
                findings.append({"param": param, "url": test_url, "signature": pattern})
                if report:
                    report.add_finding(
                        "Web Application Analysis",
                        f"Possible SQL injection via parameter '{param}'",
                        f"Error-based signature '{pattern}' observed at {test_url}. "
                        "Heuristic detection only - confirm manually.", "HIGH",
                        vuln_id="sql_injection_suspected",
                    )
                break
    if not findings and report:
        report.add_finding("Web Application Analysis", "No error-based SQL injection signatures found",
                            f"Tested params: {', '.join(COMMON_INJECTABLE_PARAMS)} on {base_url}", "INFO")
    return findings


def check_session_cookies(base_url, report=None):
    resp = _get(base_url)
    if not resp:
        return []
    issues = []
    for cookie in resp.cookies:
        missing = []
        if not cookie.secure:
            missing.append("Secure")
        has_httponly = "httponly" in [k.lower() for k in cookie._rest.keys()] if hasattr(cookie, "_rest") else False
        if not has_httponly:
            missing.append("HttpOnly")
        samesite = cookie._rest.get("SameSite") if hasattr(cookie, "_rest") else None
        if not samesite:
            missing.append("SameSite")
        if missing:
            issues.append({"cookie": cookie.name, "missing": missing})
            if report:
                report.add_finding(
                    "Web Application Analysis",
                    f"Session cookie '{cookie.name}' missing security flags: {', '.join(missing)}",
                    "Cookies without these flags are more exposed to theft via XSS or "
                    "network interception", "LOW", vuln_id="weak_session_cookie",
                )
    if not issues and resp.cookies and report:
        report.add_finding("Web Application Analysis", "Session cookies carry expected security flags",
                            f"Checked {len(resp.cookies)} cookie(s) from {base_url}", "INFO")
    return issues


def _extract_login_form(html, page_url):
    soup = BeautifulSoup(html or "", "html.parser")
    form = soup.find("form")
    if not form:
        return None
    action = form.get("action") or page_url
    if action.startswith("/") or not action.startswith("http"):
        from urllib.parse import urljoin
        action = urljoin(page_url, action)
    method = (form.get("method") or "post").lower()

    user_field = pass_field = None
    extra_fields = {}
    for inp in form.find_all("input"):
        name = inp.get("name")
        if not name:
            continue
        itype = (inp.get("type") or "text").lower()
        if itype == "password" and not pass_field:
            pass_field = name
        elif itype in ("text", "email") and not user_field and \
                any(h in name.lower() for h in ("user", "email", "login", "name")):
            user_field = name
        elif itype == "hidden":
            extra_fields[name] = inp.get("value", "")
    if not user_field or not pass_field:
        return None
    return {"action": action, "method": method, "user_field": user_field,
            "pass_field": pass_field, "extra_fields": extra_fields}


def attempt_default_credentials(login_url, report=None):
    resp = _get(login_url, allow_redirects=True)
    if not resp:
        return None
    form = _extract_login_form(resp.text, login_url)
    if not form:
        return None

    baseline_len = len(resp.text or "")
    session = requests.Session()
    session.verify = False

    for username, password in DEFAULT_CREDENTIALS:
        payload = dict(form["extra_fields"])
        payload[form["user_field"]] = username
        payload[form["pass_field"]] = password
        try:
            if form["method"] == "post":
                attempt = session.post(form["action"], data=payload, timeout=6,
                                        allow_redirects=True, verify=False)
            else:
                attempt = session.get(form["action"], params=payload, timeout=6,
                                       allow_redirects=True, verify=False)
        except requests.RequestException:
            continue

        attempt_body = (attempt.text or "").lower()
        failure_indicators = ["invalid", "incorrect", "failed", "error", "denied", "try again"]
        looks_like_failure = any(ind in attempt_body for ind in failure_indicators)
        length_changed = abs(len(attempt.text or "") - baseline_len) > 200
        redirected_away = attempt.url != login_url and attempt.history

        if (length_changed or redirected_away) and not looks_like_failure:
            if report:
                report.add_finding(
                    "Web Application Analysis",
                    f"Default credentials may have succeeded: {username}:{password or '(blank)'}",
                    f"Login attempt at {login_url} produced a different response than a "
                    "failed login (redirect or significant content change). Verify manually "
                    "in-browser before relying on this.", "CRITICAL",
                    vuln_id="default_creds_confirmed",
                )
            return {"username": username, "password": password, "url": login_url}

    if report:
        report.add_finding("Web Application Analysis", "No default credentials succeeded",
                            f"Tried {len(DEFAULT_CREDENTIALS)} common pairs against {login_url}", "INFO")
    return None


def run_analysis(target, scheme="http", port=None, dir_hits=None, report=None, skip_authtest=False):
    base_url = f"{scheme}://{target}"
    if port and port not in (80, 443):
        base_url += f":{port}"

    login_urls = discover_login_forms(base_url, dir_hits=dir_hits)
    if report:
        if login_urls:
            report.add_finding("Web Application Analysis", f"Login form(s) discovered: {len(login_urls)}",
                                ", ".join(login_urls), "INFO")
        else:
            report.add_finding("Web Application Analysis", "No login forms discovered",
                                f"Checked common paths/hints on {base_url}", "INFO")

    check_sql_injection(base_url, report=report)
    check_session_cookies(base_url, report=report)

    if not skip_authtest:
        for url in login_urls:
            attempt_default_credentials(url, report=report)
    elif report:
        report.add_finding("Web Application Analysis", "Default credential testing skipped",
                            "--skip-authtest was set", "INFO")

    return {"base_url": base_url, "login_urls": login_urls}

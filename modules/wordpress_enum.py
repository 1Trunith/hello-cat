import re

import requests
from bs4 import BeautifulSoup
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from modules.progress import ProgressBar

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

COMMON_PLUGINS = [
    "akismet", "contact-form-7", "yoast-seo", "wordfence", "elementor",
    "woocommerce", "jetpack", "wp-super-cache", "all-in-one-seo-pack",
    "wp-fastest-cache", "duplicator", "really-simple-ssl", "updraftplus",
    "classic-editor", "ninja-forms", "wpforms-lite", "mailchimp-for-wp",
    "google-site-kit", "wp-optimize", "litespeed-cache", "redirection",
]

COMMON_THEMES = [
    "twentytwentyfour", "twentytwentythree", "twentytwentytwo",
    "twentytwentyone", "twentytwenty", "astra", "oceanwp", "divi",
    "generatepress", "hello-elementor", "storefront",
]

INTERESTING_PATHS = [
    "wp-config.php.bak", "wp-config.php.old", "wp-config.php~",
    "wp-config.txt", ".wp-config.php.swp", "wp-content/debug.log",
    "wp-content/uploads/", "xmlrpc.php", "wp-json/", "wp-json/wp/v2/users",
    "wp-cron.php", "readme.html", "license.txt", "wp-admin/install.php",
    "wp-content/backup-db/", "wp-content/plugins/", "wp-content/themes/",
]


def _get(url, timeout=6):
    try:
        return requests.get(url, timeout=timeout, verify=False, allow_redirects=True)
    except requests.RequestException:
        return None


def detect_wordpress(base_url):
    resp = _get(base_url)
    if not resp:
        return False, None
    body = resp.text or ""
    indicators = ["wp-content", "wp-includes", "/wp-json/", "wordpress"]
    if any(ind in body.lower() for ind in indicators):
        return True, resp
    wp_login = _get(f"{base_url}/wp-login.php")
    if wp_login and wp_login.status_code in (200, 302, 401, 403):
        return True, resp
    return False, resp


def get_version(base_url, homepage_resp):
    version = None
    if homepage_resp and homepage_resp.text:
        match = re.search(r'content="WordPress\s+([0-9.]+)"', homepage_resp.text, re.IGNORECASE)
        if match:
            version = match.group(1)
    if not version:
        readme = _get(f"{base_url}/readme.html")
        if readme and readme.status_code == 200:
            match = re.search(r"Version\s+([0-9.]+)", readme.text)
            if match:
                version = match.group(1)
    return version


def enumerate_plugins_themes(base_url, threads=1):
    found_plugins, found_themes = [], []
    bar = ProgressBar(total=len(COMMON_PLUGINS) + len(COMMON_THEMES), label="Checking plugins/themes")
    try:
        for slug in COMMON_PLUGINS:
            resp = _get(f"{base_url}/wp-content/plugins/{slug}/")
            if resp and resp.status_code in (200, 403):
                found_plugins.append(slug)
            bar.update()
        for slug in COMMON_THEMES:
            resp = _get(f"{base_url}/wp-content/themes/{slug}/")
            if resp and resp.status_code in (200, 403):
                found_themes.append(slug)
            bar.update()
        bar.finish(f"{len(found_plugins)} plugin(s), {len(found_themes)} theme(s) found")
    except KeyboardInterrupt:
        bar.finish(f"Interrupted - {len(found_plugins)} plugin(s), {len(found_themes)} theme(s) found so far")
        print("[!] Plugin/theme check interrupted by user.")
        raise
    return found_plugins, found_themes


def enumerate_users_rest(base_url):
    users = []
    resp = _get(f"{base_url}/wp-json/wp/v2/users")
    if resp and resp.status_code == 200:
        try:
            data = resp.json()
            for entry in data:
                if isinstance(entry, dict) and "slug" in entry:
                    users.append(entry.get("slug") or entry.get("name"))
        except ValueError:
            pass
    return users


def enumerate_users_author_archive(base_url, max_id=10):
    users = []
    for author_id in range(1, max_id + 1):
        resp = _get(f"{base_url}/?author={author_id}", timeout=4)
        if not resp:
            continue
        final_url = resp.url
        match = re.search(r"/author/([^/]+)/?", final_url)
        if match:
            users.append(match.group(1))
    return sorted(set(users))


def check_interesting_paths(base_url):
    hits = []
    for path in INTERESTING_PATHS:
        resp = _get(f"{base_url}/{path}")
        if resp and resp.status_code == 200:
            hits.append({"path": path, "status": resp.status_code, "length": len(resp.content)})
    return hits


def enumerate(target, scheme="http", port=None, threads=20, report=None):
    base_url = f"{scheme}://{target}"
    if port and port not in (80, 443):
        base_url += f":{port}"

    is_wp, homepage_resp = detect_wordpress(base_url)
    if report and not is_wp:
        report.add_finding("WordPress Enumeration", "WordPress not detected",
                            f"No WordPress indicators found at {base_url}", "INFO")
        return {"detected": False}

    report and report.add_finding("WordPress Enumeration", "WordPress detected", base_url, "INFO")

    version = get_version(base_url, homepage_resp)
    if report:
        if version:
            report.add_finding("WordPress Enumeration", f"WordPress version: {version}",
                                "Check this version against known WordPress core CVEs",
                                "INFO", vuln_id="wp_outdated")
        else:
            report.add_finding("WordPress Enumeration", "WordPress version not disclosed",
                                "Version string not found in homepage meta tag or readme.html", "INFO")

    plugins, themes = enumerate_plugins_themes(base_url)
    if report:
        if plugins:
            report.add_finding("WordPress Enumeration", f"Plugins detected: {', '.join(plugins)}",
                                "Cross-reference each plugin/version against wpscan.com vulnerability DB",
                                "INFO")
        if themes:
            report.add_finding("WordPress Enumeration", f"Themes detected: {', '.join(themes)}",
                                "Cross-reference each theme/version against known CVEs", "INFO")

    users = enumerate_users_rest(base_url)
    if not users:
        users = enumerate_users_author_archive(base_url)
    if report and users:
        report.add_finding("WordPress Enumeration", f"Usernames exposed: {', '.join(users)}",
                            "Exposed usernames narrow brute-force/credential-stuffing targeting",
                            "MEDIUM", vuln_id="wp_user_enum")

    xmlrpc = _get(f"{base_url}/xmlrpc.php")
    if report and xmlrpc and xmlrpc.status_code == 200 and "XML-RPC server accepts POST" in (xmlrpc.text or ""):
        report.add_finding("WordPress Enumeration", "xmlrpc.php is enabled",
                            "Can be abused for pingback-based port scanning or amplified "
                            "brute-force (system.multicall)", "MEDIUM", vuln_id="wp_xmlrpc_enabled")

    hits = check_interesting_paths(base_url)
    if report:
        for hit in hits:
            severity = "INFO"
            vuln_id = None
            if "bak" in hit["path"] or "old" in hit["path"] or hit["path"].endswith("~") \
                    or hit["path"].endswith(".txt") or hit["path"].endswith(".swp"):
                severity, vuln_id = "CRITICAL", "wp_config_backup"
            report.add_finding("WordPress Enumeration", f"Interesting path found: /{hit['path']}",
                                f"HTTP {hit['status']} ({hit['length']} bytes)", severity,
                                vuln_id=vuln_id)

    login_resp = _get(f"{base_url}/wp-login.php")
    if report and login_resp:
        soup = BeautifulSoup(login_resp.text or "", "html.parser")
        has_login_form = soup.find("form", id="loginform") is not None
        report.add_finding(
            "WordPress Enumeration",
            "Login page: /wp-login.php" + (" (standard login form present)" if has_login_form else ""),
            "Consider default/weak credential testing in the authorized lab scope "
            "(see Web Application Analysis menu option)",
            "INFO", vuln_id="default_creds_panel" if has_login_form else None,
        )

    return {
        "detected": True,
        "base_url": base_url,
        "version": version,
        "plugins": plugins,
        "themes": themes,
        "users": users,
        "interesting_paths": hits,
    }

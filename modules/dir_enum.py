import os
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from modules.progress import ProgressBar

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

BUNDLED_WORDLIST = os.path.join(os.path.dirname(__file__), "..", "wordlists", "common_dirs.txt")

SECLISTS_CANDIDATES = [
    "/usr/share/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt",
    "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirb/wordlists/common.txt",
]

INTERESTING_STATUS = {200, 204, 301, 302, 307, 401, 403}

SENSITIVE_HITS = {
    ".git/config": ("HIGH", "Exposed .git directory - source code may be recoverable", "exposed_git"),
    ".env": ("CRITICAL", "Exposed .env file - may contain credentials/secrets", "exposed_env"),
    ".svn": ("MEDIUM", "Exposed .svn directory", None),
    "phpinfo.php": ("MEDIUM", "phpinfo() exposed - leaks server configuration", "phpinfo_exposed"),
    "wp-login.php": ("INFO", "WordPress login page found", None),
    ".htpasswd": ("HIGH", "Exposed .htpasswd file", "exposed_htpasswd"),
    "id_rsa": ("CRITICAL", "Possible exposed private SSH key", "exposed_private_key"),
    "backup.sql": ("HIGH", "Possible exposed database backup", "exposed_backup_sql"),
    "db_backup.sql": ("HIGH", "Possible exposed database backup", "exposed_backup_sql"),
    "web.config": ("MEDIUM", "Exposed IIS web.config file", None),
    "server-status": ("MEDIUM", "Apache server-status page exposed", "server_status_exposed"),
    "actuator/health": ("MEDIUM", "Spring Boot actuator health endpoint exposed", "actuator_health_exposed"),
}


def resolve_wordlist(custom_path=None):
    if custom_path and os.path.isfile(custom_path):
        return custom_path
    for candidate in SECLISTS_CANDIDATES:
        if os.path.isfile(candidate):
            return candidate
    return os.path.normpath(BUNDLED_WORDLIST)


def _load_words(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    except OSError:
        return []


def _check_path(base_url, word, timeout=4):
    url = f"{base_url}/{word}"
    try:
        resp = requests.get(url, timeout=timeout, allow_redirects=False, verify=False)
        if resp.status_code in INTERESTING_STATUS:
            return {"path": word, "url": url, "status": resp.status_code,
                     "length": len(resp.content)}
    except requests.RequestException:
        return None
    return None


def enumerate_dirs(target, scheme="http", port=None, wordlist_path=None,
                    threads=40, report=None):
    base_url = f"{scheme}://{target}"
    if port and port not in (80, 443):
        base_url += f":{port}"

    wordlist_file = resolve_wordlist(wordlist_path)
    words = _load_words(wordlist_file)

    hits = []
    interrupted = False
    if words:
        bar = ProgressBar(total=len(words), label="Brute-forcing directories")
        executor = ThreadPoolExecutor(max_workers=threads)
        try:
            futures = {executor.submit(_check_path, base_url, w): w for w in words}
            for future in as_completed(futures):
                result = future.result()
                if result:
                    hits.append(result)
                bar.update()
            bar.finish(f"Directory brute force complete - {len(hits)} found")
        except KeyboardInterrupt:
            interrupted = True
            bar.finish(f"Interrupted - {len(hits)} found so far")
            print("[!] Directory enumeration interrupted by user.")
        finally:
            executor.shutdown(wait=False, cancel_futures=True)

    hits.sort(key=lambda h: h["path"])

    if report:
        report.set_section("directory_enum", {
            "base_url": base_url,
            "wordlist_used": wordlist_file,
            "hits": hits,
        })
        if not hits:
            report.add_finding("Directory Enumeration", "No interesting paths found",
                                f"wordlist: {wordlist_file}", "INFO")
        for hit in hits:
            severity, note, vuln_id = "INFO", "", None
            for sig, (sev, desc, vid) in SENSITIVE_HITS.items():
                if sig in hit["path"]:
                    severity, note, vuln_id = sev, f" | {desc}", vid
                    break
            detail = f"{hit['url']} -> HTTP {hit['status']} ({hit['length']} bytes){note}"
            report.add_finding("Directory Enumeration", f"Found: /{hit['path']}",
                                detail, severity, vuln_id=vuln_id)

    if interrupted:
        raise KeyboardInterrupt
    return hits, base_url

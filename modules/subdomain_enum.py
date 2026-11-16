"""Subdomain discovery module for Hello Cat.

Only runs when a --domain is supplied (an IP alone cannot be brute-forced
for subdomains). Resolves candidate subdomains concurrently via DNS.
"""

import os
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

BUNDLED_WORDLIST = os.path.join(os.path.dirname(__file__), "..", "wordlists", "common_subdomains.txt")


def _load_words(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            return [line.strip() for line in fh if line.strip() and not line.startswith("#")]
    except OSError:
        return []


def _resolve(sub, domain):
    fqdn = f"{sub}.{domain}"
    try:
        addr = socket.gethostbyname(fqdn)
        return {"subdomain": fqdn, "ip": addr}
    except socket.gaierror:
        return None


def enumerate_subdomains(domain=None, wordlist_path=None, threads=50, report=None):
    if not domain:
        if report:
            report.add_finding("Subdomain Enumeration", "Skipped",
                                "No --domain supplied; subdomain brute-forcing requires a "
                                "hostname and was skipped for this IP-only target.", "INFO")
        return [], None

    wordlist_file = wordlist_path if wordlist_path and os.path.isfile(wordlist_path) \
        else os.path.normpath(BUNDLED_WORDLIST)
    words = _load_words(wordlist_file)

    found = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(_resolve, w, domain): w for w in words}
        for future in as_completed(futures):
            result = future.result()
            if result:
                found.append(result)

    found.sort(key=lambda r: r["subdomain"])

    if report:
        report.set_section("subdomain_enum", {"domain": domain, "found": found,
                                                 "wordlist_used": wordlist_file})
        if not found:
            report.add_finding("Subdomain Enumeration", "No subdomains resolved",
                                f"domain: {domain}", "INFO")
        for f in found:
            report.add_finding("Subdomain Enumeration", f"Resolved: {f['subdomain']}",
                                f"-> {f['ip']}", "INFO")

    return found, wordlist_file

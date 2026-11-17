"""Known-CVE matching from fingerprinted software/versions.

Takes the Server/X-Powered-By strings tech_fingerprint.fingerprint
already collects (report.sections['tech_fingerprint']) plus any
WordPress/plugin version wordpress_enum found, matches them against a
small bundled table (cve_table.py) and, if searchsploit is installed,
against the full exploit-db index. Never runs msfconsole/searchsploit
exploit code automatically - only reports the module/path to run
manually, same convention as bruteforce.py's "install hydra" fallback.
"""

import json
import re
import shutil
import subprocess

from modules import cve_table


def candidate_strings(report):
    """Pull every version-bearing string we've already collected onto the
    report during recon (tech fingerprint + WordPress enum)."""
    strings = []
    section = (report.sections or {}).get("tech_fingerprint") if report else None
    if section:
        headers = section.get("headers", {})
        for key in ("Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"):
            if headers.get(key):
                strings.append(headers[key])
        strings.extend(section.get("technologies", []))

    wp_section = (report.sections or {}).get("wordpress_enum") if report else None
    if wp_section and wp_section.get("version"):
        strings.append(f"WordPress {wp_section['version']}")

    return strings


def match_bundled(strings):
    matches = []
    for s in strings:
        matches.extend(cve_table.match(s))
    seen, unique = set(), []
    for m in matches:
        if m["cve"] not in seen:
            seen.add(m["cve"])
            unique.append(m)
    return unique


def _parse_product_version(s):
    match = re.search(r"([A-Za-z][A-Za-z0-9._-]*)[/ ]([0-9][0-9.]*)", s)
    if match:
        return match.group(1), match.group(2)
    return s.strip(), None


def searchsploit_lookup(strings, max_results=5):
    tool = shutil.which("searchsploit")
    if not tool:
        return None

    results = []
    for s in strings:
        product, version = _parse_product_version(s)
        query = f"{product} {version}" if version else product
        try:
            proc = subprocess.run([tool, "--json", query], capture_output=True,
                                   timeout=15, text=True)
            data = json.loads(proc.stdout or "{}")
        except Exception:
            continue
        for entry in data.get("RESULTS_EXPLOIT", [])[:max_results]:
            results.append({"title": entry.get("Title"), "path": entry.get("Path"),
                             "edb_id": entry.get("EDB-ID"), "matched": s})
    return results


def run(report=None):
    if not report:
        return {"bundled": [], "searchsploit": None}

    strings = candidate_strings(report)
    bundled = match_bundled(strings)
    for entry in bundled:
        report.add_finding(
            "CVE Matching", f"Known CVE match: {entry['cve']}",
            f"{entry['note']} | Metasploit/manual: {entry['exploit']}",
            "HIGH", vuln_id="cve_match",
        )

    searchsploit_results = searchsploit_lookup(strings)
    if searchsploit_results:
        for entry in searchsploit_results:
            report.add_finding(
                "CVE Matching", f"searchsploit match for {entry['matched']}: {entry['title']}",
                f"exploit-db path: {entry['path']} (EDB-ID {entry['edb_id']})",
                "MEDIUM", vuln_id="cve_match",
            )
    elif strings:
        report.add_finding(
            "CVE Matching", "searchsploit not available for extended CVE lookup",
            "Install exploitdb/searchsploit for a full exploit-db cross-reference "
            f"of: {', '.join(strings)}", "INFO",
        )

    return {"bundled": bundled, "searchsploit": searchsploit_results}

"""Reporting/output module for Hello Cat.

Collects findings from all recon modules and renders them to the console
with severity ratings, and optionally saves JSON and/or plain-text reports.
"""

import json
from datetime import datetime, timezone

try:
    import colorama
    colorama.init(autoreset=False)
except ImportError:
    pass

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

SEVERITY_COLORS = {
    "CRITICAL": "\033[41m\033[97m",  # white on red
    "HIGH": "\033[91m",              # red
    "MEDIUM": "\033[93m",            # yellow
    "LOW": "\033[94m",               # blue
    "INFO": "\033[92m",              # green
}
RESET = "\033[0m"
BOLD = "\033[1m"


class Finding:
    def __init__(self, category, title, detail, severity="INFO"):
        self.category = category
        self.title = title
        self.detail = detail
        self.severity = severity.upper()

    def to_dict(self):
        return {
            "category": self.category,
            "title": self.title,
            "detail": self.detail,
            "severity": self.severity,
        }


class ReconReport:
    def __init__(self, target, domain=None):
        self.target = target
        self.domain = domain
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.findings = []
        self.sections = {}

    def add_finding(self, category, title, detail, severity="INFO"):
        finding = Finding(category, title, detail, severity)
        self.findings.append(finding)
        return finding

    def set_section(self, name, data):
        """Store raw structured data for a module (ports, dirs, subdomains, etc.)."""
        self.sections[name] = data

    def _sorted_findings(self):
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    def print_console(self):
        print(f"\n{BOLD}========== HELLO CAT RECON REPORT =========={RESET}")
        print(f"Target : {self.target}")
        if self.domain:
            print(f"Domain : {self.domain}")
        print(f"Started: {self.started_at}")
        print(f"{BOLD}=============================================={RESET}\n")

        if not self.findings:
            print("No findings recorded.")
            return

        counts = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1

        summary = "  ".join(
            f"{SEVERITY_COLORS.get(sev, '')}{sev}: {counts.get(sev, 0)}{RESET}"
            for sev in SEVERITY_ORDER
            if counts.get(sev)
        )
        print(f"Summary: {summary}\n")

        current_category = None
        for f in self._sorted_findings():
            if f.category != current_category:
                current_category = f.category
                print(f"\n{BOLD}--- {current_category} ---{RESET}")
            color = SEVERITY_COLORS.get(f.severity, "")
            print(f"[{color}{f.severity:<8}{RESET}] {f.title}")
            if f.detail:
                print(f"           {f.detail}")

    def to_dict(self):
        return {
            "target": self.target,
            "domain": self.domain,
            "started_at": self.started_at,
            "findings": [f.to_dict() for f in self._sorted_findings()],
            "sections": self.sections,
        }

    def save_json(self, path):
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2)

    def save_text(self, path):
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(f"HELLO CAT RECON REPORT\nTarget: {self.target}\n")
            if self.domain:
                fh.write(f"Domain: {self.domain}\n")
            fh.write(f"Started: {self.started_at}\n")
            fh.write("=" * 46 + "\n\n")
            for f in self._sorted_findings():
                fh.write(f"[{f.severity}] ({f.category}) {f.title}\n")
                if f.detail:
                    fh.write(f"    {f.detail}\n")
            fh.write("\n")

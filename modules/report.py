import json
from datetime import datetime, timezone

from modules.vuln_database import get_detail

try:
    import colorama
    colorama.init(autoreset=False)
except ImportError:
    pass

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

SEVERITY_COLORS = {
    "CRITICAL": "\033[41m\033[97m",
    "HIGH": "\033[91m",
    "MEDIUM": "\033[93m",
    "LOW": "\033[94m",
    "INFO": "\033[92m",
}
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


class Finding:
    def __init__(self, category, title, detail, severity="INFO", vuln_id=None):
        self.category = category
        self.title = title
        self.detail = detail
        self.severity = severity.upper()
        self.vuln_id = vuln_id
        self.full_detail = get_detail(vuln_id) if vuln_id else None

    def to_dict(self):
        d = {
            "category": self.category,
            "title": self.title,
            "detail": self.detail,
            "severity": self.severity,
        }
        if self.full_detail:
            d["deep_dive"] = self.full_detail
        return d


class ReconReport:
    def __init__(self, target, domain=None):
        self.target = target
        self.domain = domain
        self.started_at = datetime.now(timezone.utc).isoformat()
        self.findings = []
        self.sections = {}

    def add_finding(self, category, title, detail, severity="INFO", vuln_id=None):
        finding = Finding(category, title, detail, severity, vuln_id=vuln_id)
        self.findings.append(finding)
        return finding

    def set_section(self, name, data):
        self.sections[name] = data

    def _sorted_findings(self):
        return sorted(self.findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    def _print_full_detail(self, detail):
        def _block(label, value):
            print(f"           {BOLD}{label}:{RESET} {value}")

        def _list_block(label, items):
            print(f"           {BOLD}{label}:{RESET}")
            for item in items:
                print(f"             - {item}")

        _block("What it is", detail["title"])
        _block("Why it exists", detail["cause"])
        _block("Impact", detail["impact"])
        _block("How to validate", detail["validation"])
        _list_block("Reproduction steps", detail["reproduction"])
        _list_block("Relevant tools", detail["tools"])
        _block("Remediation", detail["remediation"])
        print()

    def print_console(self, verbose=False):
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

        if not verbose and any(f.full_detail for f in self.findings):
            print(f"{DIM}(Run with --verbose for full vulnerability deep-dives: "
                  f"cause, impact, reproduction steps, and remediation){RESET}\n")

        current_category = None
        for f in self._sorted_findings():
            if f.category != current_category:
                current_category = f.category
                print(f"\n{BOLD}--- {current_category} ---{RESET}")
            color = SEVERITY_COLORS.get(f.severity, "")
            print(f"[{color}{f.severity:<8}{RESET}] {f.title}")
            if f.detail:
                print(f"           {f.detail}")
            if f.full_detail:
                if verbose:
                    self._print_full_detail(f.full_detail)
                else:
                    print(f"           {DIM}(deep-dive available - rerun with --verbose){RESET}")

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
                if f.full_detail:
                    d = f.full_detail
                    fh.write(f"    Why it exists: {d['cause']}\n")
                    fh.write(f"    Impact: {d['impact']}\n")
                    fh.write(f"    How to validate: {d['validation']}\n")
                    fh.write("    Reproduction steps:\n")
                    for step in d["reproduction"]:
                        fh.write(f"      - {step}\n")
                    fh.write(f"    Relevant tools: {', '.join(d['tools'])}\n")
                    fh.write(f"    Remediation: {d['remediation']}\n")
                fh.write("\n")

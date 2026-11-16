import socket
import sys

from modules import (
    banner, port_scanner, dir_enum, subdomain_enum, tech_fingerprint,
    vuln_check, wordpress_enum, auth_analysis, dns_tls, history, netutils,
)
from modules.report import ReconReport
from modules.main_utils import clear_screen

try:
    import colorama
    _CYAN = colorama.Fore.CYAN
    _YELLOW = colorama.Fore.YELLOW
    _GREEN = colorama.Fore.GREEN
    _BOLD = colorama.Style.BRIGHT
    _RESET = colorama.Style.RESET_ALL
except ImportError:
    _CYAN = _YELLOW = _GREEN = _BOLD = _RESET = ""

MENU_TEXT = """{bold}{cyan}       MADE BY @.TRUNITH{reset}
  ============================

  {green}[1]{reset} Run Scan
  {green}[2]{reset} Deep Vulnerability Analysis
  {green}[3]{reset} WordPress Enumeration
  {green}[4]{reset} Web Application Analysis
  {green}[5]{reset} DNS & Hostname Discovery
  {green}[6]{reset} View Previous Scan Results
  {green}[7]{reset} Change Target IP / Domain
  {yellow}[0]{reset} Clear Terminal
  {yellow}[99]{reset} Exit

  ============================
"""


class SessionState:
    def __init__(self):
        self.target = None
        self.domain = None
        self.scheme = "http"
        self.http_port = None
        self.threads = 100
        self.verbose = False
        self.skip_authtest = False
        self.last_report = None
        self.last_open_ports = []
        self.last_dir_hits = []


def show_menu(state):
    clear_screen()
    banner.print_banner()
    print(MENU_TEXT.format(bold=_BOLD, cyan=_CYAN, green=_GREEN, yellow=_YELLOW, reset=_RESET))
    if state.target:
        print(f"  Current target: {state.target}" + (f" (domain: {state.domain})" if state.domain else ""))
        print()


def prompt_target(state):
    default_hint = f" [{state.target}]" if state.target else ""
    try:
        entered = input(f"Enter target IP or hostname{default_hint}: ").strip()
    except EOFError:
        entered = ""
    if not entered and state.target:
        return state.target
    if not entered:
        return None
    try:
        return netutils.resolve_target(entered)
    except socket.gaierror:
        print(f"[!] Could not resolve '{entered}'.")
        return None


def pause():
    try:
        input("\nPress Enter to return to the main menu...")
    except EOFError:
        pass


def determine_http_port(open_ports, state):
    http_port = state.http_port
    scheme = state.scheme
    if not http_port and open_ports:
        for candidate in (443, 8443, 80, 8080, 8000):
            if any(p["port"] == candidate for p in open_ports):
                http_port = candidate
                if candidate in (443, 8443):
                    scheme = "https"
                break
    return http_port, scheme


def auto_detect_domain(state, hostname):
    if state.domain or not hostname:
        return
    labels = hostname.split(".")
    if len(labels) >= 2:
        state.domain = ".".join(labels[-2:])
        print(f"[*] Auto-enabling subdomain enumeration for discovered domain: {state.domain}")


def run_full_scan(state):
    target = prompt_target(state)
    if not target:
        print("[!] No target provided.")
        return
    state.target = target

    report = ReconReport(target=target, domain=state.domain)

    print(f"\n[*] Starting port scan ({'nmap' if port_scanner.nmap_available() else 'python fallback'})...")
    open_ports, scan_method = port_scanner.scan(target, threads=state.threads, report=report)
    print(f"[+] Port scan complete via {scan_method}: {len(open_ports)} open port(s) found.")
    state.last_open_ports = open_ports

    http_port, scheme = determine_http_port(open_ports, state)
    state.http_port, state.scheme = http_port, scheme
    base_url = f"{scheme}://{target}"
    if http_port and http_port not in (80, 443):
        base_url += f":{http_port}"

    dns_result = dns_tls.run(target, open_ports, report=report)
    auto_detect_domain(state, dns_result.get("hostname"))

    print(f"\n[*] Running directory/file enumeration on {base_url}...")
    dir_hits, base_url = dir_enum.enumerate_dirs(target, scheme=scheme, port=http_port,
                                                  threads=state.threads, report=report)
    print(f"[+] Directory enumeration complete: {len(dir_hits)} interesting path(s) found.")
    state.last_dir_hits = dir_hits

    print(f"\n[*] Running technology fingerprinting on {base_url}...")
    technologies, _ = tech_fingerprint.fingerprint(target, scheme=scheme, port=http_port, report=report)
    print(f"[+] Fingerprinting complete: {len(technologies)} signature(s) found.")

    print("\n[*] Running subdomain enumeration...")
    subdomains, _ = subdomain_enum.enumerate_subdomains(domain=state.domain, threads=state.threads, report=report)
    print(f"[+] Subdomain enumeration complete: {len(subdomains)} subdomain(s) resolved.")

    print("\n[*] Running common vulnerability checks...")
    vuln_check.run_checks(target, base_url, open_ports, dir_hits, report=report)
    print("[+] Vulnerability checks complete.")

    print("\n[*] Checking for WordPress...")
    wordpress_enum.enumerate(target, scheme=scheme, port=http_port, threads=state.threads, report=report)

    state.last_report = report
    path = history.save_scan(report)
    report.print_console(verbose=state.verbose)
    print(f"\n[+] Scan saved to {path}")
    pause()


def run_deep_vuln_analysis(state):
    if not state.last_report:
        print("[!] No scan results yet. Run a scan first (option 1).")
        pause()
        return
    state.last_report.print_console(verbose=True)
    pause()


def run_wordpress_enum(state):
    target = prompt_target(state)
    if not target:
        print("[!] No target provided.")
        return
    state.target = target
    report = ReconReport(target=target, domain=state.domain)
    print(f"\n[*] Running WordPress enumeration against {target}...")
    wordpress_enum.enumerate(target, scheme=state.scheme, port=state.http_port,
                              threads=state.threads, report=report)
    report.print_console(verbose=state.verbose)
    history.save_scan(report)
    pause()


def run_web_app_analysis(state):
    target = prompt_target(state)
    if not target:
        print("[!] No target provided.")
        return
    state.target = target
    report = ReconReport(target=target, domain=state.domain)
    print(f"\n[*] Running web application analysis against {target}...")
    auth_analysis.run_analysis(target, scheme=state.scheme, port=state.http_port,
                                dir_hits=state.last_dir_hits, report=report,
                                skip_authtest=state.skip_authtest)
    report.print_console(verbose=state.verbose)
    history.save_scan(report)
    pause()


def run_dns_discovery(state):
    target = prompt_target(state)
    if not target:
        print("[!] No target provided.")
        return
    state.target = target
    report = ReconReport(target=target, domain=state.domain)
    open_ports = state.last_open_ports
    if not open_ports:
        print(f"\n[*] No prior port scan for {target}, scanning now...")
        open_ports, _ = port_scanner.scan(target, threads=state.threads, report=report)
        state.last_open_ports = open_ports
    dns_result = dns_tls.run(target, open_ports, report=report)
    auto_detect_domain(state, dns_result.get("hostname"))
    if state.domain:
        subdomain_enum.enumerate_subdomains(domain=state.domain, threads=state.threads, report=report)
    report.print_console(verbose=state.verbose)
    history.save_scan(report)
    pause()


def view_previous_scans(state):
    entries = history.list_scans()
    if not entries:
        print("\n[!] No previous scan results found.")
        pause()
        return

    print(f"\n{_BOLD}Previous scans:{_RESET}")
    for i, (path, target, started_at, count) in enumerate(entries, start=1):
        print(f"  [{i}] {target}  ({started_at})  - {count} finding(s)")

    try:
        choice = input("\nEnter a number to view, or press Enter to go back: ").strip()
    except EOFError:
        choice = ""
    if not choice:
        return
    try:
        index = int(choice) - 1
        path = entries[index][0]
    except (ValueError, IndexError):
        print("[!] Invalid selection.")
        pause()
        return

    data = history.load_scan(path)
    print(f"\n{_BOLD}Target:{_RESET} {data.get('target')}")
    print(f"{_BOLD}Started:{_RESET} {data.get('started_at')}")
    counts = history.summarize_findings(data)
    print(f"{_BOLD}Severity counts:{_RESET} " +
          "  ".join(f"{sev}: {n}" for sev, n in counts.items()))
    print()
    for f in data.get("findings", []):
        print(f"[{f['severity']:<8}] ({f['category']}) {f['title']}")
        if f.get("detail"):
            print(f"           {f['detail']}")
    pause()


def change_target(state):
    try:
        new_target = input("Enter new target IP or hostname: ").strip()
    except EOFError:
        new_target = ""
    if new_target:
        try:
            state.target = netutils.resolve_target(new_target)
        except socket.gaierror:
            print(f"[!] Could not resolve '{new_target}'.")
            pause()
            return
    try:
        new_domain = input("Enter domain for subdomain enumeration (blank to leave unset): ").strip()
    except EOFError:
        new_domain = ""
    if new_domain:
        state.domain = new_domain
    print(f"[+] Target set to {state.target}" + (f", domain {state.domain}" if state.domain else ""))
    pause()


HANDLERS = {
    "1": run_full_scan,
    "2": run_deep_vuln_analysis,
    "3": run_wordpress_enum,
    "4": run_web_app_analysis,
    "5": run_dns_discovery,
    "6": view_previous_scans,
    "7": change_target,
}


def run_menu_loop(state):
    while True:
        show_menu(state)
        try:
            choice = input("  Enter Option: ").strip()
        except EOFError:
            choice = "99"

        if choice == "0":
            continue
        if choice == "99":
            print("\nGoodbye.")
            sys.exit(0)

        handler = HANDLERS.get(choice)
        if handler:
            handler(state)
        else:
            print("[!] Invalid option.")
            pause()

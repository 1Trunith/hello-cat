import socket
import sys

from modules import (
    banner, port_scanner, dir_enum, subdomain_enum, tech_fingerprint,
    vuln_check, wordpress_enum, auth_analysis, dns_tls, history, netutils,
    bruteforce, hash_tools, wordlist_tools, token_analysis, log_analysis,
    xss_module, pentest_assistant,
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

MENU_TEXT = """{bold}{cyan}  MAIN MENU{reset}
  ============================

  {green}[1]{reset} Run Scan
  {green}[2]{reset} Deep Vulnerability Analysis
  {green}[3]{reset} WordPress Enumeration
  {green}[4]{reset} Web Application Analysis
  {green}[5]{reset} DNS & Hostname Discovery
  {green}[6]{reset} View Previous Scan Results
  {green}[7]{reset} Change Target IP / Domain
  {green}[8]{reset} Authentication & Credential Testing
  {green}[9]{reset} XSS Exploitation Module
  {green}[10]{reset} Pentesting Assistant (Natural Language)
  {green}[11]{reset} User Agreement / Disclaimer
  {yellow}[0]{reset} Clear Terminal
  {yellow}[99]{reset} Exit

  ============================
"""

AUTH_MENU_TEXT = """{bold}{cyan}  AUTHENTICATION & CREDENTIAL TESTING{reset}
  ============================

  {green}[1]{reset} Brute Force a Service (SSH/FTP/SMB/RDP)
  {green}[2]{reset} Brute Force HTTP Login Form
  {green}[3]{reset} Password Spray
  {green}[4]{reset} Default Credential Check
  {green}[5]{reset} Validate a Single Credential Pair
  {green}[6]{reset} Hash Identifier / Cracker
  {green}[7]{reset} Wordlist & Username Tools
  {green}[8]{reset} Token Analyzer (JWT / NTLM / OAuth / SAML)
  {green}[9]{reset} Authentication Log Analyzer
  {yellow}[0]{reset} Back to Main Menu

  ============================
"""

USER_AGREEMENT_TEXT = """{bold}{cyan}  USER AGREEMENT / DISCLAIMER{reset}
  ============================

  This tool is provided for authorized security testing, CTF challenges
  (e.g. TryHackMe), and educational use only.

  Hello-Cat and @.Trunith are not responsible for any misuse of this
  tool. By using it you agree that:

    - You will only run scans, brute-force attempts, exploitation
      modules, or any other feature of this tool against systems you
      own or are explicitly authorized to test.
    - You assume full responsibility for how you use this tool and
      for any consequences of that use, including legal consequences.
    - Hello-Cat / @.Trunith accept no liability for damage, data loss,
      legal action, or any other outcome resulting from use or misuse
      of this tool.
    - Running this tool against systems you do not have permission to
      test is illegal in most jurisdictions.

  ============================
"""

AUTHORIZATION_WARNING = (
    "This performs live authentication attempts against the target. "
    "Only proceed if you are authorized to test it (TryHackMe lab, your "
    "own system, or a signed engagement)."
)


class SessionState:
    def __init__(self):
        self.target = None
        self.domain = None
        self.scheme = "http"
        self.http_port = None
        self.suggested_path = ""
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
        entered = input(f"Enter target (IP, hostname, or full URL){default_hint}: ").strip()
    except (EOFError, KeyboardInterrupt):
        entered = ""
    if not entered and state.target:
        return state.target
    if not entered:
        return None

    parsed = netutils.parse_target_input(entered)
    try:
        resolved = netutils.resolve_target(parsed["host"])
    except socket.gaierror:
        print(f"[!] Could not resolve '{parsed['host']}'.")
        return None

    state.scheme = parsed["scheme"]
    state.http_port = parsed["port"]
    state.suggested_path = parsed["path"]
    return resolved


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
    open_ports, dir_hits = [], []

    try:
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
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user - showing results gathered so far.")

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
    try:
        print(f"\n[*] Running WordPress enumeration against {target}...")
        wordpress_enum.enumerate(target, scheme=state.scheme, port=state.http_port,
                                  threads=state.threads, report=report)
    except KeyboardInterrupt:
        print("\n[!] WordPress enumeration interrupted by user - showing results gathered so far.")
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
    try:
        print(f"\n[*] Running web application analysis against {target}...")
        auth_analysis.run_analysis(target, scheme=state.scheme, port=state.http_port,
                                    dir_hits=state.last_dir_hits, report=report,
                                    skip_authtest=state.skip_authtest)
    except KeyboardInterrupt:
        print("\n[!] Web application analysis interrupted by user - showing results gathered so far.")
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
    try:
        open_ports = state.last_open_ports
        if not open_ports:
            print(f"\n[*] No prior port scan for {target}, scanning now...")
            open_ports, _ = port_scanner.scan(target, threads=state.threads, report=report)
            state.last_open_ports = open_ports
        dns_result = dns_tls.run(target, open_ports, report=report)
        auto_detect_domain(state, dns_result.get("hostname"))
        if state.domain:
            subdomain_enum.enumerate_subdomains(domain=state.domain, threads=state.threads, report=report)
    except KeyboardInterrupt:
        print("\n[!] DNS discovery interrupted by user - showing results gathered so far.")
    report.print_console(verbose=state.verbose)
    history.save_scan(report)
    pause()


def run_xss_module(state):
    if not confirm_authorized("Active XSS testing: injects payloads into parameters and forms."):
        pause()
        return
    target = prompt_target(state)
    if not target:
        print("[!] No target provided.")
        return
    state.target = target
    report = ReconReport(target=target, domain=state.domain)
    try:
        print(f"\n[*] Running XSS exploitation module against {target}...")
        xss_module.run(target, scheme=state.scheme, port=state.http_port,
                        dir_hits=state.last_dir_hits, report=report)
    except KeyboardInterrupt:
        print("\n[!] XSS module interrupted by user - showing results gathered so far.")
    report.print_console(verbose=state.verbose)
    history.save_scan(report)
    pause()


def run_pentest_assistant(state):
    target = prompt_target(state)
    if not target:
        print("[!] No target provided.")
        return
    state.target = target

    print(f"\n  Target: {target}")
    print("  Tell me what you want done, e.g. \"Can you assess this website for me?\", "
          "\"Could you breach this website for me?\", or \"Could you bypass this login "
          "page/give me the credentials?\"")
    try:
        request_text = input("  Request: ").strip()
    except (EOFError, KeyboardInterrupt):
        request_text = ""
    if not request_text:
        print("[!] No request text provided.")
        pause()
        return

    intent = pentest_assistant.classify_intent(request_text)

    if intent == "login_bypass":
        print(f"\n[*] Understood as a LOGIN BYPASS request - running recon, then attempting "
              f"to bypass the login page and retrieve/forge valid credentials for {target}.")
        report, footholds = pentest_assistant.run_login_bypass(target, state, confirm_authorized)
    elif intent == "breach":
        print(f"\n[*] Understood as a BREACH request - running recon, then attempting to "
              f"gain access to {target}.")
        report, footholds = pentest_assistant.run_breach(target, state, confirm_authorized)
    else:
        print(f"\n[*] Understood as an ASSESS request - running read-only recon and "
              f"vulnerability analysis against {target}.")
        report = pentest_assistant.run_assess(target, state)
        footholds = []

    state.last_report = report
    path = history.save_scan(report)
    report.print_console(verbose=state.verbose)
    if footholds:
        print(f"\n[+] {len(footholds)} credential/access finding(s):")
        for f in footholds:
            print(f"    - {f}")
    print(f"\n[+] Scan saved to {path}")
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


def confirm_authorized(action_description):
    print(f"\n[!] {action_description}")
    print(f"    {AUTHORIZATION_WARNING}")
    try:
        answer = input("    Type YES to continue: ").strip()
    except EOFError:
        answer = ""
    return answer == "YES"


def prompt_path(label):
    try:
        path = input(f"{label}: ").strip()
    except EOFError:
        path = ""
    return path or None


def auth_brute_force(state):
    if not confirm_authorized("Live brute force against a network service."):
        pause()
        return
    target = prompt_target(state)
    if not target:
        return
    state.target = target
    service = prompt_path("Service (ssh/ftp/smb/rdp)")
    if not service:
        return
    port = prompt_path("Port (blank for default)")
    userlist = prompt_path("Path to username wordlist (blank to use a single username)")
    username = None if userlist else prompt_path("Username")
    passlist = prompt_path("Path to password wordlist (blank to use a single password)")
    password = None if passlist else prompt_path("Password")

    report = ReconReport(target=target)
    result = None
    try:
        result = bruteforce.brute_force(service, target, port=int(port) if port else None,
                                         userlist=userlist, username=username,
                                         passlist=passlist, password=password, report=report)
    except ValueError as exc:
        print(f"[!] {exc}")
        pause()
        return
    except KeyboardInterrupt:
        print("\n[!] Brute force interrupted by user - no result captured from the engine.")

    report.print_console(verbose=state.verbose)
    history.save_scan(report)
    if result:
        print(f"\n[+] Found: {result['username']}:{result['password']}")
    pause()


def auth_brute_force_http(state):
    if not confirm_authorized("Live brute force against an HTTP login form."):
        pause()
        return
    target = prompt_target(state)
    if not target:
        return
    state.target = target
    base_url = f"{state.scheme}://{target}"
    if state.http_port and state.http_port not in (80, 443):
        base_url += f":{state.http_port}"
    default_url = base_url + state.suggested_path
    login_url = prompt_path(f"Login page URL (full path, query string, etc. all fine) [{default_url}]") or default_url
    userlist = prompt_path("Path to username wordlist (blank = auto-detect: WordPress users, "
                            "then SecLists, then bundled list)")
    passlist = prompt_path("Path to password wordlist (blank = auto-detect rockyou.txt, "
                            "else bundled common-password list)")

    report = ReconReport(target=target)
    if not userlist:
        print("[*] No username list given - detecting site type and auto-discovering usernames...")
    if not passlist:
        print("[*] No password list given - checking for rockyou.txt...")
    result = auth_analysis.brute_force_http_form(login_url, userlist, passlist, report=report)
    report.print_console(verbose=state.verbose)
    history.save_scan(report)
    if result:
        print(f"\n[+] Found: {result['username']}:{result['password']}")
    pause()


def auth_password_spray(state):
    if not confirm_authorized("Live password spray against a network service."):
        pause()
        return
    target = prompt_target(state)
    if not target:
        return
    state.target = target
    service = prompt_path("Service (ssh/ftp/smb/rdp)")
    userlist = prompt_path("Path to username wordlist")
    password = prompt_path("Single password to spray")
    if not service or not userlist or not password:
        print("[!] Service, username wordlist, and password are all required.")
        pause()
        return

    report = ReconReport(target=target)
    result = None
    try:
        result = bruteforce.password_spray(service, target, userlist, password, report=report)
    except KeyboardInterrupt:
        print("\n[!] Password spray interrupted by user - no result captured from the engine.")
    report.print_console(verbose=state.verbose)
    history.save_scan(report)
    if result:
        print(f"\n[+] Found: {result['username']}:{result['password']}")
    pause()


def auth_default_creds(state):
    if not confirm_authorized("Live default-credential check against a network service."):
        pause()
        return
    target = prompt_target(state)
    if not target:
        return
    state.target = target
    service = prompt_path("Service (ssh/ftp/smb/rdp)")
    if not service:
        return

    report = ReconReport(target=target)
    result = None
    try:
        result = bruteforce.check_default_service_credentials(service, target, report=report)
    except KeyboardInterrupt:
        print("\n[!] Default credential check interrupted by user - no result captured from the engine.")
    report.print_console(verbose=state.verbose)
    history.save_scan(report)
    if result:
        print(f"\n[+] Found: {result['username']}:{result['password']}")
    pause()


def auth_validate_single(state):
    target = prompt_target(state)
    if not target:
        return
    state.target = target
    base_url = f"{state.scheme}://{target}"
    if state.http_port and state.http_port not in (80, 443):
        base_url += f":{state.http_port}"
    default_url = base_url + state.suggested_path
    login_url = prompt_path(f"Login page URL [{default_url}]") or default_url
    username = prompt_path("Username")
    password = prompt_path("Password") or ""

    report = ReconReport(target=target)
    result = auth_analysis.validate_credentials(login_url, username, password, report=report)
    report.print_console(verbose=state.verbose)
    history.save_scan(report)
    print(f"\n[{'+' if result else '-'}] Credential check: {'succeeded' if result else 'failed/unclear'}")
    pause()


def auth_hash_tools(state):
    value = prompt_path("Enter a hash value")
    if not value:
        return
    matches = hash_tools.identify_hash(value)
    if not matches:
        print("[!] Hash type could not be identified.")
        pause()
        return
    print("\nPossible hash types:")
    for m in matches:
        print(f"  - {m['type']}" + (f" (hashcat mode {m['hashcat_mode']})" if m["hashcat_mode"] is not None else ""))

    try:
        crack_it = input("\nAttempt to crack it with a wordlist? (y/N): ").strip().lower()
    except EOFError:
        crack_it = "n"
    if crack_it == "y":
        wordlist = prompt_path("Path to wordlist")
        if wordlist:
            report = ReconReport(target=state.target or "hash-analysis")
            hash_tools.crack_hash(value, wordlist, report=report)
            report.print_console(verbose=state.verbose)
            history.save_scan(report)
    pause()


def auth_wordlist_tools(state):
    print(AUTH_MENU_TEXT.format(bold=_BOLD, cyan=_CYAN, green=_GREEN, yellow=_YELLOW, reset=_RESET))
    print("  [a] Merge/dedupe wordlists")
    print("  [b] Generate password variants from base words")
    print("  [c] Generate username variations from a name")
    print("  [d] Extract credentials from a text/log file")
    try:
        choice = input("\nEnter option: ").strip().lower()
    except EOFError:
        choice = ""

    if choice == "a":
        paths_raw = prompt_path("Comma-separated wordlist paths to merge")
        if not paths_raw:
            return
        paths = [p.strip() for p in paths_raw.split(",") if p.strip()]
        merged = wordlist_tools.merge_lists(paths)
        out_path = prompt_path("Output path for merged list")
        if out_path:
            wordlist_tools.save_list(merged, out_path)
            print(f"[+] Wrote {len(merged)} unique entries to {out_path}")
    elif choice == "b":
        words_raw = prompt_path("Comma-separated base words")
        if not words_raw:
            return
        words = [w.strip() for w in words_raw.split(",") if w.strip()]
        variants = wordlist_tools.generate_password_variants(words)
        out_path = prompt_path("Output path for generated wordlist")
        if out_path:
            wordlist_tools.save_list(variants, out_path)
            print(f"[+] Wrote {len(variants)} variants to {out_path}")
    elif choice == "c":
        first = prompt_path("First name")
        last = prompt_path("Last name")
        if first and last:
            usernames = wordlist_tools.generate_usernames(first, last)
            print("\n".join(usernames))
            out_path = prompt_path("Output path (blank to skip saving)")
            if out_path:
                wordlist_tools.save_list(usernames, out_path)
    elif choice == "d":
        file_path = prompt_path("Path to text/log file")
        if file_path:
            creds = wordlist_tools.extract_credentials_from_file(file_path)
            print(f"\n[+] Found {len(creds)} candidate credential(s):")
            for c in creds[:50]:
                print(f"  {c['username']}:{c['password']}")
    pause()


def auth_token_analyzer(state):
    print(AUTH_MENU_TEXT.format(bold=_BOLD, cyan=_CYAN, green=_GREEN, yellow=_YELLOW, reset=_RESET))
    print("  [a] Decode/analyze a JWT")
    print("  [b] Check for OAuth/SAML endpoints")
    print("  [c] Check for NTLM authentication")
    try:
        choice = input("\nEnter option: ").strip().lower()
    except EOFError:
        choice = ""

    report = ReconReport(target=state.target or "token-analysis")
    if choice == "a":
        token = prompt_path("Paste the JWT")
        if token:
            token_analysis.analyze_jwt(token, report=report)
    elif choice == "b":
        target = prompt_target(state)
        if target:
            base_url = f"{state.scheme}://{target}"
            token_analysis.check_oauth_saml(base_url, report=report)
    elif choice == "c":
        target = prompt_target(state)
        if target:
            base_url = f"{state.scheme}://{target}"
            token_analysis.check_ntlm_auth(base_url, report=report)

    report.print_console(verbose=state.verbose)
    if report.findings:
        history.save_scan(report)
    pause()


def auth_log_analyzer(state):
    file_path = prompt_path("Path to authentication log file")
    if not file_path:
        return
    report = ReconReport(target=state.target or "log-analysis")
    log_analysis.analyze_log(file_path, report=report)
    report.print_console(verbose=state.verbose)
    history.save_scan(report)
    pause()


AUTH_HANDLERS = {
    "1": auth_brute_force,
    "2": auth_brute_force_http,
    "3": auth_password_spray,
    "4": auth_default_creds,
    "5": auth_validate_single,
    "6": auth_hash_tools,
    "7": auth_wordlist_tools,
    "8": auth_token_analyzer,
    "9": auth_log_analyzer,
}


def run_auth_menu(state):
    while True:
        clear_screen()
        banner.print_banner()
        print(AUTH_MENU_TEXT.format(bold=_BOLD, cyan=_CYAN, green=_GREEN, yellow=_YELLOW, reset=_RESET))
        if state.target:
            print(f"  Current target: {state.target}\n")
        try:
            choice = input("  Enter Option: ").strip()
        except EOFError:
            choice = "0"
        except KeyboardInterrupt:
            continue

        if choice == "0":
            return

        handler = AUTH_HANDLERS.get(choice)
        if handler:
            try:
                handler(state)
            except KeyboardInterrupt:
                print("\n[!] Task interrupted by user - returning to menu.")
        else:
            print("[!] Invalid option.")
            pause()


def change_target(state):
    try:
        new_target = input("Enter new target (IP, hostname, or full URL): ").strip()
    except (EOFError, KeyboardInterrupt):
        new_target = ""
    if new_target:
        parsed = netutils.parse_target_input(new_target)
        try:
            state.target = netutils.resolve_target(parsed["host"])
        except socket.gaierror:
            print(f"[!] Could not resolve '{parsed['host']}'.")
            pause()
            return
        state.scheme = parsed["scheme"]
        state.http_port = parsed["port"]
        state.suggested_path = parsed["path"]
    try:
        new_domain = input("Enter domain for subdomain enumeration (blank to leave unset): ").strip()
    except EOFError:
        new_domain = ""
    if new_domain:
        state.domain = new_domain
    print(f"[+] Target set to {state.target}" + (f", domain {state.domain}" if state.domain else ""))
    pause()


def show_user_agreement(state):
    print(USER_AGREEMENT_TEXT.format(bold=_BOLD, cyan=_CYAN, green=_GREEN, yellow=_YELLOW, reset=_RESET))
    pause()


HANDLERS = {
    "1": run_full_scan,
    "2": run_deep_vuln_analysis,
    "3": run_wordpress_enum,
    "4": run_web_app_analysis,
    "5": run_dns_discovery,
    "6": view_previous_scans,
    "7": change_target,
    "8": run_auth_menu,
    "9": run_xss_module,
    "10": run_pentest_assistant,
    "11": show_user_agreement,
}


def run_menu_loop(state):
    while True:
        show_menu(state)
        try:
            choice = input("  Enter Option: ").strip()
        except EOFError:
            choice = "99"
        except KeyboardInterrupt:
            continue

        if choice == "0":
            continue
        if choice == "99":
            print("\nGoodbye.")
            sys.exit(0)

        handler = HANDLERS.get(choice)
        if handler:
            try:
                handler(state)
            except KeyboardInterrupt:
                print("\n[!] Task interrupted by user - returning to menu.")
        else:
            print("[!] Invalid option.")
            pause()

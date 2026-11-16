#!/usr/bin/env python3
"""
Hello Cat - Made By @.Trunith
=====================================================

For use against authorized lab targets only (TryHackMe, CTF ranges,
your own infrastructure, or systems you have written permission to test).

Usage:
    python hello-cat.py <target_ip> [options]   # non-interactive
    python hello-cat.py                         # interactive: prompts for a target
"""

import argparse
import ipaddress
import os
import socket
import sys

from modules import banner, port_scanner, dir_enum, subdomain_enum, tech_fingerprint, vuln_check
from modules.report import ReconReport


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def parse_args():
    parser = argparse.ArgumentParser(
        prog="hello-cat.py",
        description="Hello Cat - automated TryHackMe/CTF reconnaissance tool",
    )
    parser.add_argument("target", nargs="?", default=None,
                         help="Target IP address (or hostname). Omit to be prompted interactively.")
    parser.add_argument("--domain", help="Domain name to use for subdomain brute-forcing "
                                          "(optional, required to enable that module)")
    parser.add_argument("--ports", default=port_scanner.DEFAULT_PORTS,
                         help="Port range/list for scanning (default: common ports + top 1000)")
    parser.add_argument("--wordlist", help="Custom wordlist path for directory brute-forcing")
    parser.add_argument("--sub-wordlist", help="Custom wordlist path for subdomain brute-forcing")
    parser.add_argument("--threads", type=int, default=100, help="Thread count (default: 100)")
    parser.add_argument("--scheme", choices=["http", "https"], default="http",
                         help="HTTP scheme to use for web-based modules (default: http)")
    parser.add_argument("--http-port", type=int, help="HTTP port if non-standard (default: 80/443)")
    parser.add_argument("--output", help="Save report to this base filename (adds .json/.txt)")
    parser.add_argument("--verbose", action="store_true",
                         help="Print full vulnerability deep-dives (cause, impact, reproduction "
                              "steps, remediation) in the console instead of just a summary")
    parser.add_argument("--skip-ports", action="store_true", help="Skip port scanning")
    parser.add_argument("--skip-dirs", action="store_true", help="Skip directory enumeration")
    parser.add_argument("--skip-vulns", action="store_true", help="Skip vulnerability checks")
    return parser.parse_args()


def resolve_target(target):
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        try:
            return socket.gethostbyname(target)
        except socket.gaierror:
            print(f"[!] Could not resolve target '{target}'. Exiting.")
            sys.exit(1)


def prompt_for_target():
    try:
        target = input("Enter target IP address (or hostname): ").strip()
    except EOFError:
        target = ""
    if not target:
        print("[!] No target entered. Exiting.")
        sys.exit(1)
    return target


def main():
    args = parse_args()

    if args.target is None:
        clear_screen()
        banner.print_banner()
        args.target = prompt_for_target()
    else:
        banner.print_banner()

    target_ip = resolve_target(args.target)
    print(f"[*] Target resolved to: {target_ip}")
    if args.domain:
        print(f"[*] Domain supplied for subdomain enumeration: {args.domain}")

    report = ReconReport(target=target_ip, domain=args.domain)

    open_ports, scan_method = [], "skipped"
    if not args.skip_ports:
        print(f"\n[*] Starting port scan ({'nmap' if port_scanner.nmap_available() else 'python fallback'})...")
        open_ports, scan_method = port_scanner.scan(
            target_ip, ports=args.ports, threads=args.threads, report=report)
        print(f"[+] Port scan complete via {scan_method}: {len(open_ports)} open port(s) found.")
    else:
        print("\n[*] Skipping port scan (--skip-ports).")

    http_port = args.http_port
    if not http_port and open_ports:
        for candidate in (443, 8443, 80, 8080, 8000):
            if any(p["port"] == candidate for p in open_ports):
                http_port = candidate
                if candidate in (443, 8443):
                    args.scheme = "https"
                break

    dir_hits, base_url = [], f"{args.scheme}://{target_ip}"
    if not args.skip_dirs:
        print(f"\n[*] Starting directory/file enumeration on {base_url}...")
        dir_hits, base_url = dir_enum.enumerate_dirs(
            target_ip, scheme=args.scheme, port=http_port,
            wordlist_path=args.wordlist, threads=args.threads, report=report)
        print(f"[+] Directory enumeration complete: {len(dir_hits)} interesting path(s) found.")
    else:
        print("\n[*] Skipping directory enumeration (--skip-dirs).")

    print(f"\n[*] Running technology fingerprinting on {base_url}...")
    technologies, _ = tech_fingerprint.fingerprint(
        target_ip, scheme=args.scheme, port=http_port, report=report)
    print(f"[+] Fingerprinting complete: {len(technologies)} signature(s) found.")

    print(f"\n[*] Running subdomain enumeration...")
    subdomains, _ = subdomain_enum.enumerate_subdomains(
        domain=args.domain, wordlist_path=args.sub_wordlist,
        threads=args.threads, report=report)
    print(f"[+] Subdomain enumeration complete: {len(subdomains)} subdomain(s) resolved.")

    if not args.skip_vulns:
        print(f"\n[*] Running common vulnerability checks...")
        vuln_check.run_checks(target_ip, base_url, open_ports, dir_hits, report=report)
        print("[+] Vulnerability checks complete.")
    else:
        print("\n[*] Skipping vulnerability checks (--skip-vulns).")

    report.print_console(verbose=args.verbose)

    if args.output:
        json_path = f"{args.output}.json"
        text_path = f"{args.output}.txt"
        report.save_json(json_path)
        report.save_text(text_path)
        print(f"\n[+] Report saved to {json_path} and {text_path}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Exiting.")
        sys.exit(130)

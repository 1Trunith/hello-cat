# Hello Cat 🐱

Made By @.Trunith — an interactive TryHackMe/CTF reconnaissance and
vulnerability analysis framework. One-time setup, then a persistent
terminal menu drives port scanning, service detection, directory and
subdomain enumeration, technology fingerprinting, WordPress enumeration,
web application/authentication analysis, and deep vulnerability write-ups,
all tied together with persistent scan history.

> ⚠️ **Authorized use only.** Only run Hello Cat against systems you own or
> are explicitly authorized to test (e.g. TryHackMe machines, your own lab,
> or a signed pentest engagement). Unauthorized scanning of systems you do
> not have permission to test may be illegal in your jurisdiction.

## Quick Start

**Linux / Mac / WSL:**

```bash
git clone https://github.com/1Trunith/hello-cat.git && cd hello-cat && ./setup.sh
```

**Windows (cmd or PowerShell):**

```bash
git clone https://github.com/1Trunith/hello-cat.git && cd hello-cat && setup.bat
```

`setup.sh`/`setup.bat` only needs to run once — it creates a local virtual
environment (`.venv`), installs dependencies into it, and remembers that
state (checked against a hash of `requirements.txt`), so later runs skip
reinstalling entirely. Every run after the first should use the reusable
launcher instead:

```bash
./start.sh     # Linux/Mac/WSL
start.bat      # Windows
```

Either launcher drops you into the interactive menu:

```
       MADE BY @.TRUNITH
  ============================

  [1] Run Scan
  [2] Deep Vulnerability Analysis
  [3] WordPress Enumeration
  [4] Web Application Analysis
  [5] DNS & Hostname Discovery
  [6] View Previous Scan Results
  [7] Change Target IP / Domain
  [0] Clear Terminal
  [99] Exit

  Enter Option:
```

Pick `[1]`, type in a target IP, and the framework handles reconnaissance
automatically. When the scan finishes it returns to this same menu — no
restart, no reinstall.

## Features

- Purple ASCII cat banner on every launch
- One-time setup, persistent virtual environment, instant reusable launch
- Interactive menu that stays open across scans
- Port scanning with `nmap` (service/version detection) when available,
  automatic fallback to a threaded pure-Python TCP scanner otherwise
- Directory/file brute-forcing (bundled wordlist, auto-detected SecLists,
  or a custom wordlist)
- Reverse DNS, TLS certificate inspection, and automatic subdomain
  enumeration once a hostname is discovered
- Technology fingerprinting (server headers, frameworks, CMS signatures)
- Dedicated WordPress enumeration: version, plugins/themes, exposed
  usernames, xmlrpc.php, exposed backups/config files, login page
- Web application analysis: login form discovery, error-based SQL
  injection probing, session cookie security flags, and lab-scoped default
  credential testing against discovered login forms
- Follow-up enumeration recommendations based on discovered services
- Deep vulnerability analysis: cause, impact, validation, step-by-step
  reproduction, tools, and remediation for every flagged issue
- Persistent scan history under `scan_history/`, browsable from the menu
- Severity-rated findings: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
- Optional JSON/text report export for non-interactive runs

## Menu Options

| Option | Description |
|---|---|
| `[1]` Run Scan | Full reconnaissance pipeline against a target IP/hostname |
| `[2]` Deep Vulnerability Analysis | Reprints the last scan with full cause/impact/reproduction/remediation detail |
| `[3]` WordPress Enumeration | Standalone WordPress-focused scan |
| `[4]` Web Application Analysis | Login discovery, SQLi probing, session cookie checks, default credential testing |
| `[5]` DNS & Hostname Discovery | Reverse DNS, TLS certificate inspection, subdomain enumeration |
| `[6]` View Previous Scan Results | Browse and reopen saved scans from `scan_history/` |
| `[7]` Change Target IP / Domain | Update the active target/domain for subsequent menu actions |
| `[0]` Clear Terminal | Redraws the banner and menu |
| `[99]` Exit | Quits the tool |

## Non-Interactive / Scripted Usage

Passing a target directly on the command line skips the menu entirely and
runs the full pipeline once, for automation or CI-style usage:

```bash
.venv/bin/python hello-cat.py 10.10.123.45 --verbose --output report
```

### Options

| Flag | Description |
|---|---|
| `--domain DOMAIN` | Hostname to use for subdomain brute-forcing |
| `--ports PORTS` | Port range/list to scan, e.g. `1-65535` or `22,80,443` |
| `--wordlist PATH` | Custom wordlist for directory brute-forcing |
| `--sub-wordlist PATH` | Custom wordlist for subdomain brute-forcing |
| `--threads N` | Thread count (default: 100) |
| `--scheme {http,https}` | HTTP scheme for web modules (default: `http`) |
| `--http-port PORT` | Override the HTTP port used for web modules |
| `--output NAME` | Save report as `NAME.json` and `NAME.txt` |
| `--verbose` | Print full vulnerability deep-dives in the console |
| `--skip-ports` / `--skip-dirs` / `--skip-vulns` | Skip the respective stage |
| `--skip-authtest` | Skip default credential testing in web application analysis |

## Deep Vulnerability Analysis

Every finding tagged with a known vulnerability includes:

- **What it is** — plain description
- **Why it exists** — the root cause/misconfiguration
- **Impact** — what an attacker could do with it
- **How to validate** — confirming it's real, not a false positive
- **Reproduction steps** — a concrete sequence for the lab
- **Relevant tools** — the tools/commands typically used
- **Remediation** — how it would be fixed in production

Shown automatically in `[2] Deep Vulnerability Analysis` or with
`--verbose`; always included in saved `--output` reports.

## Manual Installation

```bash
git clone https://github.com/1Trunith/hello-cat.git
cd hello-cat
pip install -r requirements.txt
```

(Optional but recommended) install `nmap` for faster, more accurate
scanning with service/version detection:

```bash
sudo apt install nmap     # Debian/Ubuntu/Kali
brew install nmap          # macOS
```

## Project Structure

```
hello-cat/
├── main.py                   # CLI mode + interactive menu entry point
├── hello-cat.py               # Thin launcher
├── setup.sh / setup.bat       # One-time setup (creates .venv, installs deps)
├── start.sh / start.bat       # Reusable launcher (no reinstall)
├── modules/
│   ├── banner.py              # ASCII cat banner
│   ├── menu.py                 # Interactive menu + session state
│   ├── netutils.py             # Target resolution helpers
│   ├── main_utils.py           # Shared terminal helpers
│   ├── port_scanner.py        # nmap + Python fallback port scanning
│   ├── dir_enum.py            # Directory/file brute-forcing
│   ├── subdomain_enum.py      # Subdomain discovery
│   ├── tech_fingerprint.py    # Technology/CMS fingerprinting
│   ├── dns_tls.py              # Reverse DNS, TLS inspection, recommendations
│   ├── wordpress_enum.py       # WordPress-specific enumeration
│   ├── auth_analysis.py        # Login/SQLi/session/credential analysis
│   ├── vuln_check.py          # Common vulnerability checks
│   ├── vuln_database.py       # Deep-dive vulnerability knowledge base
│   ├── history.py              # Persistent scan history
│   └── report.py              # Severity-rated reporting + JSON/text export
├── wordlists/
│   ├── common_dirs.txt
│   └── common_subdomains.txt
├── scan_history/               # Saved scans (created at runtime, gitignored)
├── requirements.txt
├── setup.py
├── .gitignore
└── README.md
```

## Disclaimer

This tool is provided for educational purposes and authorized security
testing only (TryHackMe, CTFs, labs, and engagements you have explicit
permission for). The authors are not responsible for any misuse. Always
obtain proper authorization before scanning any system.

## License

MIT

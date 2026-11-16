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
- Web application analysis: login form discovery, SQLi probing, CSRF/CAPTCHA/
  lockout/rate-limit checks, session fixation/expiration/hijacking risk,
  username enumeration (login response and password reset), registration/API
  auth checks, and lab-scoped default credential testing
- Authentication & credential testing suite: Hydra/Medusa/Ncrack-backed
  brute force (SSH/FTP/SMB/RDP/HTTP forms), password spraying, brute-force
  protection testing, Hashcat/John-backed hash identification and cracking,
  wordlist/username generation, credential extraction from text/logs, JWT/
  NTLM/OAuth/SAML token analysis, and an authentication log analyzer
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
| `[8]` Authentication & Credential Testing | Submenu: brute force, hash cracking, wordlist/username tools, token analysis, log analysis |
| `[9]` XSS Exploitation Module | Reflected, stored, and DOM-based XSS detection with filter-bypass payloads and impact demonstration |
| `[0]` Clear Terminal | Redraws the banner and menu |
| `[99]` Exit | Quits the tool |

### `[8]` Authentication & Credential Testing Submenu

| Option | Description |
|---|---|
| `[1]` Brute Force a Service | SSH/FTP/SMB/RDP via Hydra, Medusa, or Ncrack (whichever is installed) |
| `[2]` Brute Force HTTP Login Form | Multi-threaded dictionary attack against any login URL (full paths/ports/query strings supported). Detects site type (WordPress/PHP/generic); on WordPress, pulls real usernames via `/wp-json`/author-archive enumeration. Leaving the password list blank uses `rockyou.txt` (checks for it locally, else downloads and caches a copy in `~/.hello_cat/wordlists/` on first use); leaving the username list blank does the same with a SecLists username list. Both fall back to a small bundled list if neither is found and the download fails (e.g. no internet access). Stops immediately on success, and aborts early if it detects an account-lockout response. Handles CSRF-token-protected forms by refreshing the token each attempt |
| `[3]` Password Spray | One password against many usernames (lower lockout risk than per-user brute force) |
| `[4]` Default Credential Check | Tries a small built-in default credential list against a service |
| `[5]` Validate a Single Credential Pair | Confirms one specific username/password against a login form |
| `[6]` Hash Identifier / Cracker | Identifies hash type, optionally cracks via Hashcat or John the Ripper |
| `[7]` Wordlist & Username Tools | Merge/dedupe wordlists, generate password/username variants, extract creds from text |
| `[8]` Token Analyzer | Decode/inspect JWTs, detect OAuth/SAML endpoints, probe NTLM auth |
| `[9]` Authentication Log Analyzer | Parses a log file for failed/successful logins and brute-force patterns |

Every live authentication-testing action requires typing `YES` to confirm
you're authorized to test the target before it runs.

## Authentication & Credential Testing — Feature Mapping

This table maps every requested authentication/credential testing
capability to where it actually lives in the tool. Most map directly;
some overlapping requests were consolidated into one broader check, and
a few deep protocol audits (LDAP/Kerberos/NTLM internals) are implemented
as detection + manual guidance rather than a full custom protocol client,
since that reliably needs specialized tooling (`ldapsearch`, `impacket`)
rather than a reimplementation here.

| Requested tool | Implementation |
|---|---|
| HTTP Brute Force | `[8][2]` — `auth_analysis.brute_force_http_form` |
| SSH / FTP / SMB / RDP Brute Force | `[8][1]` — `bruteforce.brute_force` (Hydra/Medusa/Ncrack) |
| WordPress Login Tester | `[3]` WordPress Enumeration + `[8][5]` validate a credential pair against `/wp-login.php` |
| Login Form Detector | `auth_analysis.discover_login_forms` (runs inside `[4]`) |
| Hydra / Medusa / Ncrack Integration | `bruteforce.py` — auto-detects whichever is installed |
| Username Enumerator | `wordpress_enum` (WP users) + `auth_analysis.check_login_response_enumeration` |
| Password List Manager | `[8][7]a` — `wordlist_tools.merge_lists`/`dedupe`/`filter_*` |
| Credential Checker | `[8][5]` — `auth_analysis.validate_credentials` |
| Hash Cracker | `[8][6]` — `hash_tools.crack_hash` (Hashcat/John) |
| Session Analyzer | `check_session_cookies` + `check_session_expiration` (in `[4]`) |
| Default Credential Checker | `[8][4]` — `bruteforce.check_default_service_credentials`; web panels via `[4]` |
| Basic Auth Tester / Digest Auth Tester | `auth_analysis.check_basic_digest_auth` (in `[4]`) |
| Form Authentication Analyzer | `auth_analysis._extract_login_form` (used throughout `[4]`) |
| Multi-Step Login Detector | `auth_analysis.detect_multistep_login` (in `[4]`) |
| CAPTCHA Detector | `auth_analysis.check_captcha` (in `[4]`) |
| Rate-Limit Analyzer | `bruteforce.detect_brute_force_protection` |
| Account Lockout Analyzer | `auth_analysis.check_account_lockout` (in `[4]`) |
| Password Policy Analyzer | `auth_analysis.check_registration_page` (policy-hint inspection) |
| MFA Security Tester / OTP Analyzer | `auth_analysis.check_mfa_otp_indicators` (in `[4]`) |
| Password Reset Analyzer | `auth_analysis.check_password_reset` (in `[4]`) |
| Registration Analyzer | `auth_analysis.check_registration_page` (in `[4]`) |
| JWT Analyzer | `[8][8]` — `token_analysis.analyze_jwt` |
| Cookie Security Analyzer | `auth_analysis.check_session_cookies` (in `[4]`) |
| Session Fixation Tester | `auth_analysis.check_session_fixation` (in `[4]`) |
| Session Expiration Tester | `auth_analysis.check_session_expiration` (in `[4]`) |
| CSRF Login Tester | `auth_analysis.check_csrf_protection` (in `[4]`) |
| LDAP Authentication Tester | Detection + manual commands via DNS/TLS follow-up recommendations (`[5]`) |
| Kerberos Analyzer | Detection + manual commands via DNS/TLS follow-up recommendations (`[5]`) |
| NTLM Analyzer | `[8][8]` — `token_analysis.check_ntlm_auth` |
| OAuth Analyzer / SAML Analyzer | `[8][8]` — `token_analysis.check_oauth_saml` |
| Credential Reuse Checker | `auth_analysis.check_credential_reuse` (flags candidates; manual retest by design) |
| Hashcat Integration / John the Ripper Integration | `hash_tools.run_hashcat` / `run_john` |
| Wordlist Generator | `[8][7]b` — `wordlist_tools.generate_password_variants` |
| Username Generator | `[8][7]c` — `wordlist_tools.generate_usernames` |
| Credential Extractor | `[8][7]d` — `wordlist_tools.extract_credentials_from_file` |
| Authentication Log Analyzer | `[8][9]` — `log_analysis.analyze_log` |
| Authentication Fingerprinter | `auth_analysis.fingerprint_auth_tech` (in `[4]`) |
| Login Response Analyzer | `auth_analysis.check_login_response_enumeration` (in `[4]`) |
| Hidden Login Discovery | Expanded `LOGIN_PATH_HINTS` in `discover_login_forms` |
| API Authentication Tester | `auth_analysis.check_api_auth` (in `[4]`) |
| Password Spraying Simulator | `[8][3]` — `bruteforce.password_spray` |
| Brute Force Detection Tester | `bruteforce.detect_brute_force_protection` |
| Credential Format Detector | `hash_tools.identify_hash` |
| Hash Comparison | `hash_tools.compare_hashes` |
| Session Hijacking Risk Analyzer | `auth_analysis.assess_session_hijacking_risk` (in `[4]`) |
| Authentication Report Generator | The existing severity-rated report/history system (`report.py`, `vuln_database.py`) |

## XSS Exploitation Module (`[9]`)

A dedicated module for TryHackMe-style XSS labs, in `modules/xss_module.py`:

- **Reflected XSS** — injects a payload set (including filter-bypass
  variants: case variation, no-space SVG, nested-tag bypass, attribute
  breakout, `javascript:` URIs, etc.) into every query parameter on the
  target URL plus common parameter names, and checks for unescaped
  reflection in the response
- **Stored XSS** — discovers forms on the page, submits a payload through
  each text field, then re-checks the original page and the form's own
  page for the payload rendering back unescaped
- **DOM-based XSS** — statically scans inline and linked JavaScript for
  attacker-controllable sources (`location.hash`, `location.search`,
  `document.referrer`, `window.name`) flowing into dangerous sinks
  (`innerHTML`, `document.write`, `eval`, etc.)
- **Context-aware severity** — classifies whether a reflection lands in
  the HTML body, an attribute, a script block, or a comment, to judge how
  likely it is to actually execute
- **Impact demonstration** — when a confirmed XSS exists and the session
  cookie lacks the `HttpOnly` flag, shows exactly what `document.cookie`
  would expose to an injected script (using the cookie value the tool
  already has from the HTTP response)
- **Honest reporting** — raw-reflection detection is a strong signal but
  not a browser-confirmed execution; the report says so. If `selenium`
  and a browser driver are installed, `xss_module.try_confirm_with_browser`
  can load the page headlessly and check for a real JS side effect for a
  genuine confirmation instead of a heuristic

Every finding records the vulnerable URL, the exact injection point
(parameter name or form), the payload used, the reflection context, and
a full cause/impact/reproduction/remediation write-up.

This is active testing (it submits data to forms and injects payloads
into parameters) — the interactive menu requires typing `YES` to confirm
authorization before it runs, same as the brute-force actions. In
non-interactive/CLI mode it's opt-in via `--run-xss`.

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
| `--run-xss` | Run the XSS exploitation module (opt-in; injects payloads into parameters and forms) |

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

The Authentication & Credential Testing submenu is also optional-dependency
aware — it works without them (falling back to built-in HTTP-form brute
forcing and identification-only hash analysis), but gets significantly
more capable with:

```bash
sudo apt install hydra medusa ncrack hashcat john   # Debian/Ubuntu/Kali
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
│   ├── xss_module.py            # Reflected/stored/DOM XSS detection + exploitation
│   ├── bruteforce.py            # Hydra/Medusa/Ncrack wrappers, password spray
│   ├── hash_tools.py            # Hash identification, Hashcat/John wrappers
│   ├── wordlist_tools.py        # Wordlist manager, generators, extractor
│   ├── token_analysis.py        # JWT/NTLM/OAuth/SAML analysis
│   ├── log_analysis.py          # Authentication log analyzer
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

# Hello Cat 🐱

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](#license)
[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](#manual-installation)
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)](#quick-start)
[![Use](https://img.shields.io/badge/use-authorized%20testing%20only-critical.svg)](#disclaimer)

**Made by [@.Trunith](https://github.com/1Trunith)** — an interactive
TryHackMe/CTF reconnaissance, vulnerability analysis, and exploitation
framework. One-time setup, then a persistent terminal menu drives port
scanning, service detection, directory and subdomain enumeration,
technology fingerprinting, WordPress enumeration, web application and
authentication analysis, a natural-language pentesting assistant that
chains recon straight into exploitation, and deep vulnerability
write-ups — all tied together with persistent scan history.

> ⚠️ **Authorized use only.** Only run Hello Cat against systems you own or
> are explicitly authorized to test (e.g. TryHackMe machines, your own lab,
> or a signed pentest engagement). Unauthorized scanning or exploitation of
> systems you do not have permission to test may be illegal in your
> jurisdiction. See [Disclaimer](#disclaimer).

## Contents

- [Quick Start](#quick-start)
- [Features](#features)
- [Menu Options](#menu-options)
- [Pentesting Assistant (Natural Language)](#10-pentesting-assistant-natural-language)
- [Authentication & Credential Testing Submenu](#8-authentication--credential-testing-submenu)
- [XSS Exploitation Module](#xss-exploitation-module-9)
- [Non-Interactive / Scripted Usage](#non-interactive--scripted-usage)
- [Deep Vulnerability Analysis](#deep-vulnerability-analysis)
- [Manual Installation](#manual-installation)
- [Project Structure](#project-structure)
- [Disclaimer](#disclaimer)
- [License](#license)

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
  [8] Authentication & Credential Testing
  [9] XSS Exploitation Module
  [10] Pentesting Assistant (Natural Language)
  [11] User Agreement / Disclaimer
  [0] Clear Terminal
  [99] Exit

  Enter Option:
```

Pick `[1]`, type in a target IP, and the framework handles reconnaissance
automatically. When the scan finishes it returns to this same menu — no
restart, no reinstall.

## Features

- Purple ASCII cat banner on every launch
- Flexible target input — paste an IP, a hostname, or a full URL
  (`https://host:port/path?query`) anywhere you're asked for a target;
  scheme, port, and path are parsed out automatically
- Live purple progress bars with percentage for every long-running task
  (port scanning, directory/subdomain brute-forcing, WordPress plugin/
  theme checks, XSS parameter testing, login brute force)
- Press Ctrl+C to stop any running task early — shows whatever was found
  so far and returns to the menu instead of crashing the whole program
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
- Natural-language **Pentesting Assistant** (`[10]`) — describe what you
  want in plain English ("assess this site" / "breach this box") and it
  chains the entire recon pipeline into either a read-only assessment or
  a full automated exploitation attempt, gated behind one authorization
  prompt. See [Pentesting Assistant](#10-pentesting-assistant-natural-language)
- A dozen dedicated exploitation modules used by breach mode: JWT
  `alg=none`/weak-secret bypass, OAuth `redirect_uri` manipulation,
  session fixation/hijacking, 2FA/MFA bypass, known-CVE matching, SQLi →
  webshell, file-upload filter bypass → RCE, insecure deserialization,
  SSRF against cloud metadata, XXE file disclosure, config/backup secret
  extraction, and pass-the-hash against SMB
- Deep vulnerability analysis: cause, impact, validation, step-by-step
  reproduction, tools, and remediation for every flagged issue
- Persistent scan history under `scan_history/`, browsable from the menu
- Severity-rated findings: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
- Optional JSON/text report export for non-interactive runs
- Built-in user agreement/disclaimer (`[11]`), viewable at any time from the menu

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
| `[10]` Pentesting Assistant (Natural Language) | Describe a goal in plain English; classifies it as assess (read-only) or breach (active) and runs the matching pipeline |
| `[11]` User Agreement / Disclaimer | Prints the authorized-use disclaimer |
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

## `[10]` Pentesting Assistant (Natural Language)

A free-text front end over the rest of the tool, in `modules/pentest_assistant.py`.
It adds no new attack capability of its own — it reads what you typed,
classifies the intent, and calls the same recon/exploitation modules the
dedicated menu options use, in a sensible order.

1. **Prompts for a target**, then a plain-English request, e.g.
   *"can you assess this website for me?"* or *"could you breach this
   box for me?"*
2. **Classifies intent** by keyword — `breach` (hack, exploit, pwn,
   compromise, own this, attack, ...) vs. `assess` (audit, review, scan,
   enumerate, investigate, ...). Defaults to the safer `assess` if
   nothing matches.
3. **Assess mode** runs the full read-only recon chain: port scan,
   DNS/TLS, directory/subdomain enumeration, technology fingerprinting,
   vulnerability checks, WordPress enumeration, web/auth analysis,
   config/backup secret extraction, SSRF/XXE probing, OAuth/OIDC/SAML
   discovery, and known-CVE matching against fingerprinted versions.
4. **Breach mode** runs the same recon, then — after a single
   `confirm_authorized()` prompt — attempts, in order: default/brute-force
   credentials against discovered logins and open SSH/FTP/RDP; the XSS
   module; JWT `alg=none`/weak-secret bypass; OAuth `redirect_uri`
   manipulation; SQL injection escalated to a webshell drop; file-upload
   filter bypass for RCE; insecure deserialization; session
   fixation/hijacking; 2FA/MFA bypass; then retries any credentials it
   confirmed against every other discovered service (credential reuse)
   and, if SMB is open, attempts pass-the-hash with them.
5. **Reports and saves** a severity-rated finding set the same way every
   other scan does, listing any confirmed credential/access footholds.

| New exploitation module | What it does |
|---|---|
| `jwt_exploit.py` | Strips the signature on `alg=none` tokens and replays a forged claim; tries a small built-in secret list against HMAC-signed tokens offline |
| `oauth_exploit.py` | Tests whether a discovered OAuth/OIDC authorize endpoint validates `redirect_uri` strictly |
| `session_exploit.py` | Harvests session identifiers leaked in URLs/logs/redirects, then replays one against likely authenticated endpoints |
| `mfa_bypass.py` | Tests for missing OTP rate-limiting, brute-forceable backup codes, and replayable "remember this device" cookies |
| `cve_match.py` / `cve_table.py` | Matches fingerprinted software/versions against a small curated CVE table, and against the full `searchsploit` index if installed — reports the exploit module/path, never auto-runs it |
| `sqli_exploit.py` | Takes an error-based SQLi hit and escalates it: UNION-based extraction, then a heuristic MySQL `INTO OUTFILE`/MSSQL `xp_cmdshell` webshell drop |
| `upload_exploit.py` | Tries common extension/content-type filter bypasses to land a minimal PHP webshell through a discovered upload form, then confirms execution |
| `deserialize_exploit.py` | Detects Java/PHP/Python serialized-object signatures; sends a generated gadget chain via `ysoserial`/`phpggc` if installed |
| `ssrf_exploit.py` | Probes URL-fetching parameters with cloud metadata (`169.254.169.254`) and internal targets |
| `xxe_exploit.py` | Sends a classic external-entity payload to likely XML-parsing endpoints to read `/etc/passwd` / `win.ini` |
| `config_extract.py` | Downloads exposed backup/config files (`.env`, `wp-config.php.bak`, `.git/config`, ...) already flagged by recon and parses out credentials |
| `ntlm_pth.py` | Pass-the-hash/NTLM auth against SMB using confirmed credentials, via `impacket`'s `psexec.py`/`wmiexec.py`/`smbexec.py` if installed |

Every module that has no installed external dependency (`searchsploit`,
`ysoserial`, `phpggc`, `impacket`) still reports the finding and the exact
manual command to run, the same fallback convention `bruteforce.py` uses
for Hydra/Medusa/Ncrack.

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
│   ├── pentest_assistant.py   # Natural-language assess/breach orchestrator
│   ├── jwt_exploit.py         # JWT alg=none / weak-secret bypass
│   ├── oauth_exploit.py       # OAuth/OIDC redirect_uri manipulation
│   ├── session_exploit.py     # Session fixation/hijacking harvest + replay
│   ├── mfa_bypass.py          # 2FA/MFA bypass vectors
│   ├── cve_match.py            # Fingerprinted-version -> known-CVE matching
│   ├── cve_table.py            # Bundled table of common THM-box CVEs
│   ├── sqli_exploit.py        # SQL injection -> data extraction / webshell
│   ├── upload_exploit.py      # File upload filter bypass -> RCE
│   ├── deserialize_exploit.py # Insecure deserialization detection/exploitation
│   ├── ssrf_exploit.py        # SSRF against cloud metadata / internal services
│   ├── xxe_exploit.py          # XXE file disclosure
│   ├── config_extract.py      # Exposed backup/config file secret extraction
│   ├── ntlm_pth.py              # Pass-the-hash / NTLM auth against SMB
│   ├── history.py              # Persistent scan history
│   ├── report.py              # Severity-rated reporting + JSON/text export
│   └── progress.py              # Purple terminal progress bars
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

This tool is provided for authorized security testing, CTF challenges
(e.g. TryHackMe), and educational use only. The same text is available
any time from the menu (`[11] User Agreement / Disclaimer`).

Hello-Cat and [@.Trunith](https://github.com/1Trunith) are not
responsible for any misuse of this tool. By using it you agree that:

- You will only run scans, brute-force attempts, exploitation modules,
  or any other feature of this tool against systems you own or are
  explicitly authorized to test.
- You assume full responsibility for how you use this tool and for any
  consequences of that use, including legal consequences.
- Hello-Cat / @.Trunith accept no liability for damage, data loss, legal
  action, or any other outcome resulting from use or misuse of this tool.
- Running this tool against systems you do not have permission to test
  is illegal in most jurisdictions.

## License

MIT

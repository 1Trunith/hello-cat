# Hello Cat 🐱

```
    #####                                            #####
   #######                                          #######
  ####   ####                                      ####   ####
  ###     ###        H E L L O    C A T            ###     ###
```

**Hello Cat** — Made By @.Trunith — is an automated reconnaissance tool built
for **TryHackMe** labs, CTF competitions, and other **authorized**
penetration-testing environments. It chains together port scanning, service
detection, directory/file brute-forcing, subdomain discovery, technology
fingerprinting, and deep-dive vulnerability analysis, then prints a single
severity-rated report.

> ⚠️ **Authorized use only.** Only run Hello Cat against systems you own or
> are explicitly authorized to test (e.g. TryHackMe machines, your own lab,
> or a signed pentest engagement). Unauthorized scanning of systems you do
> not have permission to test may be illegal in your jurisdiction.

## Features

- 🐾 Purple cat ASCII banner on every run
- ⚡ **One-command launch** — clone and run a single setup script, then just
  type in a target IP when prompted
- 🔍 Port scanning with `nmap` (service/version detection) when available,
  automatic fallback to a threaded pure-Python TCP scanner otherwise
- 📁 Directory/file brute-forcing (bundled wordlist, auto-detected SecLists,
  or your own custom wordlist)
- 🌐 Subdomain discovery (only runs when you supply `--domain`)
- 🧩 Technology fingerprinting (server headers, frameworks, CMS signatures)
- 🛡️ Common vulnerability / misconfiguration checks (anonymous FTP, SMB
  exposure, risky HTTP methods, missing security headers, exposed login
  panels, known vulnerable banners, exposed secrets/backups)
- 🧠 **Deep vulnerability analysis** — each finding can show its cause,
  impact, how to validate it, step-by-step reproduction, relevant tools, and
  remediation (`--verbose`, or always in the saved report)
- 🎯 Severity-rated findings: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
- 💾 Optional JSON and plain-text report export
- 🧵 Multi-threaded for speed

## Quick Start (one command)

**Linux / Mac / WSL:**

```bash
git clone https://github.com/1Trunith/hello-cat.git && cd hello-cat && ./setup.sh
```

**Windows (cmd or PowerShell):**

```bash
git clone https://github.com/1Trunith/hello-cat.git && cd hello-cat && setup.bat
```

Either command installs dependencies, clears the screen, shows the Hello Cat
banner, and prompts you to enter a target IP address — just type it in and
press Enter to start the scan. No manual `pip install` or `python` command
needed.

> Note: git itself cannot auto-run code on clone (no platform does this, for
> obvious security reasons) — `./setup.sh` / `setup.bat` is the one extra
> command that gets you the rest of the way there.

## Manual Installation

If you'd rather install things yourself:

```bash
git clone https://github.com/1Trunith/hello-cat.git
cd hello-cat
pip install -r requirements.txt
```

(Optional but recommended) Install `nmap` on your system for faster, more
accurate scanning with service/version detection — Hello Cat automatically
falls back to a pure-Python scanner if `nmap` isn't on your `PATH`.

```bash
# Debian/Ubuntu/Kali
sudo apt install nmap

# macOS (Homebrew)
brew install nmap
```

Or install as a package (adds a `hello-cat` console command):

```bash
pip install .
```

## Usage

**Interactive** (no arguments — prompts for a target):

```bash
python hello-cat.py
```

**Direct / scriptable** (same thing, skips the prompt):

```bash
python hello-cat.py <target_ip>
```

Example (TryHackMe VPN target):

```bash
python hello-cat.py 10.10.123.45
```

### Options

| Flag | Description |
|---|---|
| `--domain DOMAIN` | Hostname to use for subdomain brute-forcing (required to enable that module) |
| `--ports PORTS` | Port range/list to scan, e.g. `1-65535` or `22,80,443` (default: common ports + top 1000) |
| `--wordlist PATH` | Custom wordlist for directory brute-forcing |
| `--sub-wordlist PATH` | Custom wordlist for subdomain brute-forcing |
| `--threads N` | Thread count (default: 100) |
| `--scheme {http,https}` | HTTP scheme for web modules (default: `http`) |
| `--http-port PORT` | Override the HTTP port used for web modules |
| `--output NAME` | Save report as `NAME.json` and `NAME.txt` (always includes full vulnerability deep-dives) |
| `--verbose` | Print full vulnerability deep-dives (cause, impact, reproduction steps, remediation) in the console |
| `--skip-ports` | Skip port scanning |
| `--skip-dirs` | Skip directory enumeration |
| `--skip-vulns` | Skip vulnerability checks |

### Examples

Full recon with a known domain, deep-dive output, and saved report:

```bash
python hello-cat.py 10.10.123.45 --domain target.thm --verbose --output report
```

Scan all 65535 ports with more threads:

```bash
python hello-cat.py 10.10.123.45 --ports 1-65535 --threads 200
```

Web-only recon, skipping the port scan:

```bash
python hello-cat.py 10.10.123.45 --skip-ports --wordlist /path/to/wordlist.txt
```

## Deep Vulnerability Analysis

By default, each vulnerability finding prints a short summary (title +
severity). Pass `--verbose` (or open the saved `--output` report, which
always includes the full detail) to get the complete write-up for every
detected issue:

- **What it is** — plain description of the vulnerability
- **Why it exists** — the root cause / misconfiguration behind it
- **Impact** — what an attacker could actually do with it
- **How to validate** — how to confirm it's real, not a false positive
- **Reproduction steps** — a concrete, copy-pasteable sequence for the lab
- **Relevant tools** — the specific tools/commands typically used
- **Remediation** — how it would be fixed in a real environment

This is intended to help you understand *why* something is flagged and how
to dig deeper, not just that a port is open.

## Project Structure

```
hello-cat/
├── main.py                   # Entry point / CLI + interactive logic
├── hello-cat.py               # Thin launcher (python hello-cat.py [target])
├── setup.sh                   # One-command launcher: Linux/Mac/WSL
├── setup.bat                  # One-command launcher: Windows
├── modules/
│   ├── banner.py              # ASCII cat banner
│   ├── port_scanner.py        # nmap + Python fallback port scanning
│   ├── dir_enum.py            # Directory/file brute-forcing
│   ├── subdomain_enum.py      # Subdomain discovery
│   ├── tech_fingerprint.py    # Technology/CMS fingerprinting
│   ├── vuln_check.py          # Common vulnerability checks
│   ├── vuln_database.py       # Deep-dive vulnerability knowledge base
│   └── report.py              # Severity-rated reporting + JSON/text export
├── wordlists/
│   ├── common_dirs.txt
│   └── common_subdomains.txt
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

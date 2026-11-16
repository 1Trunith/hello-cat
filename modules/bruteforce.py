import os
import re
import shutil
import subprocess
import tempfile

ENGINES = ["hydra", "medusa", "ncrack"]

SERVICE_MODULE_MAP = {
    "ssh": {"hydra": "ssh", "medusa": "ssh", "ncrack": "ssh"},
    "ftp": {"hydra": "ftp", "medusa": "ftp", "ncrack": "ftp"},
    "smb": {"hydra": "smb", "medusa": "smbnt", "ncrack": "smb"},
    "rdp": {"hydra": "rdp", "medusa": "rdp", "ncrack": "rdp"},
}


def which_engine(preferred=None):
    if preferred and shutil.which(preferred):
        return preferred
    for engine in ENGINES:
        if shutil.which(engine):
            return engine
    return None


def _run(cmd, timeout=600):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout + result.stderr
    except (subprocess.TimeoutExpired, OSError) as exc:
        return str(exc)


def brute_force(service, target, port=None, userlist=None, password=None,
                 passlist=None, username=None, engine=None, threads=4, report=None):
    service = service.lower()
    if service not in SERVICE_MODULE_MAP:
        raise ValueError(f"Unsupported service: {service}")

    chosen = which_engine(engine)
    if not chosen:
        if report:
            report.add_finding(
                "Authentication Testing",
                f"{service.upper()} brute force skipped - no engine installed",
                "Install hydra, medusa, or ncrack to enable this check "
                f"(apt install hydra). Manual command: hydra -L <userlist> "
                f"-P <passlist> {service}://{target}" + (f":{port}" if port else ""),
                "INFO",
            )
        return None

    if not userlist and not username:
        raise ValueError("Provide either username or userlist")
    if not passlist and password is None:
        raise ValueError("Provide either password or passlist")

    cmd = [chosen]
    if chosen == "hydra":
        if userlist:
            cmd += ["-L", userlist]
        else:
            cmd += ["-l", username]
        if passlist:
            cmd += ["-P", passlist]
        else:
            cmd += ["-p", password]
        cmd += ["-t", str(threads), "-f"]
        if port:
            cmd += ["-s", str(port)]
        cmd += [target, SERVICE_MODULE_MAP[service]["hydra"]]
    elif chosen == "medusa":
        cmd += ["-h", target, "-M", SERVICE_MODULE_MAP[service]["medusa"], "-t", str(threads), "-f"]
        cmd += ["-U", userlist] if userlist else ["-u", username]
        cmd += ["-P", passlist] if passlist else ["-p", password]
        if port:
            cmd += ["-n", str(port)]
    else:
        target_spec = f"{target}:{port}" if port else target
        cmd += [SERVICE_MODULE_MAP[service]["ncrack"], "-p", target_spec]
        if userlist:
            cmd += ["-U", userlist]
        else:
            cmd += ["-u", username]
        if passlist:
            cmd += ["-P", passlist]
        else:
            cmd += ["-P", password]

    output = _run(cmd)
    success = _parse_engine_output(chosen, output)

    if report:
        if success:
            report.add_finding(
                "Authentication Testing",
                f"{service.upper()} credentials found: {success['username']}:{success['password']}",
                f"Discovered via {chosen} against {target}" + (f":{port}" if port else ""),
                "CRITICAL", vuln_id="brute_force_success",
            )
        else:
            report.add_finding(
                "Authentication Testing", f"{service.upper()} brute force: no valid credentials found",
                f"Engine: {chosen}, target: {target}", "INFO",
            )
    return success


def _parse_engine_output(engine, output):
    if engine == "hydra":
        match = re.search(r"login:\s*(\S+)\s+password:\s*(\S*)", output)
        if match:
            return {"username": match.group(1), "password": match.group(2)}
    elif engine == "medusa":
        match = re.search(r"ACCOUNT FOUND:.*User:\s*(\S+)\s+Password:\s*(\S*)", output)
        if match:
            return {"username": match.group(1), "password": match.group(2)}
    elif engine == "ncrack":
        match = re.search(r"Discovered credentials.*\n.*login:\s*(\S+)\s+password:\s*(\S*)", output)
        if match:
            return {"username": match.group(1), "password": match.group(2)}
    return None


DEFAULT_SERVICE_USERNAMES = ["admin", "administrator", "root", "user", "guest", "test"]
DEFAULT_SERVICE_PASSWORDS = ["admin", "password", "123456", "root", "toor", "changeme", ""]


def check_default_service_credentials(service, target, port=None, engine=None, report=None):
    userlist_path = passlist_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as uf:
            uf.write("\n".join(DEFAULT_SERVICE_USERNAMES) + "\n")
            userlist_path = uf.name
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as pf:
            pf.write("\n".join(DEFAULT_SERVICE_PASSWORDS) + "\n")
            passlist_path = pf.name
        return brute_force(service, target, port=port, userlist=userlist_path,
                            passlist=passlist_path, engine=engine, threads=2, report=report)
    finally:
        for path in (userlist_path, passlist_path):
            if path and os.path.exists(path):
                os.unlink(path)


def password_spray(service, target, userlist, password, port=None, engine=None, report=None):
    return brute_force(service, target, port=port, userlist=userlist, password=password,
                        engine=engine, threads=1, report=report)


def detect_brute_force_protection(service, target, port=None, username="testuser",
                                   wrong_password="definitely-wrong-password", attempts=5, report=None):
    import time

    engine = which_engine()
    if not engine:
        if report:
            report.add_finding("Authentication Testing", "Rate-limit/lockout test skipped",
                                "No brute force engine installed to generate test attempts", "INFO")
        return None

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as tmp:
            for i in range(attempts):
                tmp.write(f"{wrong_password}{i}\n")
            tmp_path = tmp.name

        start = time.time()
        brute_force(service, target, port=port, username=username, passlist=tmp_path, engine=engine)
        elapsed = time.time() - start

        per_attempt = elapsed / attempts if attempts else 0
        throttled = per_attempt > 1.5

        if report:
            severity = "INFO" if throttled else "MEDIUM"
            title = ("Rate limiting / throttling appears present"
                      if throttled else "No obvious rate limiting detected")
            report.add_finding("Authentication Testing", title,
                                f"{attempts} failed {service.upper()} attempts averaged "
                                f"{per_attempt:.2f}s each", severity,
                                vuln_id=None if throttled else "no_rate_limiting")
        return {"throttled": throttled, "seconds_per_attempt": per_attempt}
    finally:
        if tmp_path and os.path.exists(tmp_path):
            os.unlink(tmp_path)

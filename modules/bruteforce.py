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
    "mysql": {"hydra": "mysql", "medusa": "mysql"},
    "postgres": {"hydra": "postgres", "medusa": "postgresql"},
    "redis": {"hydra": "redis"},
    "mongodb": {"hydra": "mongodb"},
    "telnet": {"hydra": "telnet", "medusa": "telnet", "ncrack": "telnet"},
    "vnc": {"hydra": "vnc", "medusa": "vnc", "ncrack": "vnc"},
    "mssql": {"hydra": "mssql", "medusa": "mssql"},
}


def which_engine(service=None, preferred=None):
    """Pick an installed brute-force engine that also supports `service`.

    When `service` is omitted, any installed engine qualifies (legacy behavior).
    """
    supported = SERVICE_MODULE_MAP.get(service) if service else None

    def _supports(engine):
        return supported is None or engine in supported

    if preferred and shutil.which(preferred) and _supports(preferred):
        return preferred
    for engine in ENGINES:
        if shutil.which(engine) and _supports(engine):
            return engine
    return None


def _run(cmd, timeout=600):
    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
        return stdout + stderr
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        return "timed out"
    except KeyboardInterrupt:
        process.kill()
        process.communicate()
        print("[!] Brute force engine interrupted by user.")
        raise
    except OSError as exc:
        return str(exc)


def brute_force(service, target, port=None, userlist=None, password=None,
                 passlist=None, username=None, engine=None, threads=4, report=None):
    service = service.lower()
    if service not in SERVICE_MODULE_MAP:
        raise ValueError(f"Unsupported service: {service}")

    chosen = which_engine(service, engine)
    if not chosen:
        if report:
            report.add_finding(
                "Authentication Testing",
                f"{service.upper()} brute force skipped - no supporting engine installed",
                "Install hydra (widest protocol coverage: ssh, ftp, smb, rdp, mysql, "
                "postgres, redis, mongodb, telnet, vnc, mssql), medusa, or ncrack. "
                f"Manual command: hydra -L <userlist> -P <passlist> {service}://{target}"
                + (f":{port}" if port else ""),
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

# Services with their own well-known default accounts get a tighter,
# service-specific list instead of the generic OS-login set above.
SERVICE_SPECIFIC_DEFAULTS = {
    "mysql": (["root", "admin"], ["", "root", "password", "toor"]),
    "postgres": (["postgres", "admin"], ["postgres", "password", "admin", ""]),
    "redis": ([""], ["", "foobared", "redis", "password"]),
    "mongodb": (["admin", "root"], ["", "admin", "password", "mongodb"]),
    "mssql": (["sa", "admin"], ["", "sa", "Password123", "changeme"]),
    "vnc": ([""], ["password", "vnc", "changeme", "admin"]),
}


def check_default_service_credentials(service, target, port=None, engine=None, report=None):
    usernames, passwords = SERVICE_SPECIFIC_DEFAULTS.get(
        service, (DEFAULT_SERVICE_USERNAMES, DEFAULT_SERVICE_PASSWORDS))
    userlist_path = passlist_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as uf:
            uf.write("\n".join(usernames) + "\n")
            userlist_path = uf.name
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".txt") as pf:
            pf.write("\n".join(passwords) + "\n")
            passlist_path = pf.name
        return brute_force(service, target, port=port, userlist=userlist_path,
                            passlist=passlist_path, engine=engine, threads=2, report=report)
    finally:
        for path in (userlist_path, passlist_path):
            if path and os.path.exists(path):
                os.unlink(path)


def try_single_credential(service, target, username, password, port=None, engine=None, report=None):
    """Test one already-known username:password pair against a network
    service - used for cross-service credential reuse (e.g. creds found
    on FTP/a config file, retried against SSH)."""
    result = brute_force(service, target, port=port, username=username,
                          password=password, engine=engine, threads=1, report=None)
    if report:
        if result:
            report.add_finding(
                "Credential Reuse", f"Reused credentials work on {service.upper()}: {username}:{password}",
                f"Confirmed against {target}" + (f":{port}" if port else ""),
                "CRITICAL", vuln_id="credential_reuse_confirmed",
            )
        else:
            report.add_finding(
                "Credential Reuse", f"Credential reuse failed on {service.upper()}",
                f"{username}:{password} did not work against {target}" + (f":{port}" if port else ""),
                "INFO",
            )
    return result


def password_spray(service, target, userlist, password, port=None, engine=None, report=None):
    return brute_force(service, target, port=port, userlist=userlist, password=password,
                        engine=engine, threads=1, report=report)


def detect_brute_force_protection(service, target, port=None, username="testuser",
                                   wrong_password="definitely-wrong-password", attempts=5, report=None):
    import time

    engine = which_engine(service)
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

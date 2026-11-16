import re
from collections import Counter

FAILURE_PATTERNS = [
    re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)"),
    re.compile(r"authentication failure.*user=(\S+)"),
    re.compile(r"(?i)login failed.*user[:=]\s*(\S+)"),
    re.compile(r'" 401 '),
]

SUCCESS_PATTERNS = [
    re.compile(r"Accepted password for (\S+) from (\S+)"),
    re.compile(r"Accepted publickey for (\S+) from (\S+)"),
    re.compile(r"(?i)login succeeded.*user[:=]\s*(\S+)"),
]


def analyze_log(path, report=None):
    failures = []
    successes = []
    failure_ips = Counter()

    with open(path, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            for pattern in FAILURE_PATTERNS:
                match = pattern.search(line)
                if match:
                    groups = match.groups()
                    failures.append(groups)
                    if len(groups) > 1:
                        failure_ips[groups[1]] += 1
                    break
            for pattern in SUCCESS_PATTERNS:
                match = pattern.search(line)
                if match:
                    successes.append(match.groups())
                    break

    brute_force_ips = {ip: count for ip, count in failure_ips.items() if count >= 10}

    if report:
        report.add_finding("Authentication Testing", f"Log analysis: {len(failures)} failed login event(s)",
                            path, "INFO")
        report.add_finding("Authentication Testing", f"Log analysis: {len(successes)} successful login event(s)",
                            path, "INFO")
        if brute_force_ips:
            detail = ", ".join(f"{ip} ({count} failures)" for ip, count in brute_force_ips.items())
            report.add_finding("Authentication Testing", "Possible brute force pattern in logs",
                                detail, "MEDIUM")

    return {"failures": len(failures), "successes": len(successes), "suspicious_ips": brute_force_ips}

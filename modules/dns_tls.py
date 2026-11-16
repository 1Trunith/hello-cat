import socket
import ssl
from datetime import datetime

SERVICE_RECOMMENDATIONS = {
    21: "FTP open - try anonymous login, check for known vsftpd/ProFTPD backdoors",
    22: "SSH open - check version for known CVEs, consider key-based auth testing in scope",
    23: "Telnet open - cleartext protocol, consider banner grab and default creds",
    25: "SMTP open - try VRFY/EXPN user enumeration, check for open relay",
    53: "DNS open - try zone transfer (dig axfr @target domain)",
    80: "HTTP open - run Web Application Analysis and WordPress Enumeration",
    110: "POP3 open - check for plaintext auth, try default credentials",
    111: "RPCbind open - run rpcinfo -p target to enumerate RPC services",
    139: "SMB (NetBIOS) open - enumerate with enum4linux/smbclient",
    143: "IMAP open - check for plaintext auth, try default credentials",
    443: "HTTPS open - inspect the TLS certificate and run Web Application Analysis",
    445: "SMB open - enumerate shares with smbclient/smbmap, check MS17-010",
    1433: "MSSQL open - try default sa credentials, check xp_cmdshell availability",
    1521: "Oracle TNS Listener open - enumerate SIDs with tnscmd/odat",
    2049: "NFS open - check exports with showmount -e target",
    3306: "MySQL open - try default root credentials, check for remote root access",
    3389: "RDP open - check for BlueKeep (CVE-2019-0708), test weak credentials in scope",
    5432: "PostgreSQL open - try default postgres credentials",
    5900: "VNC open - check for no-auth/weak-auth VNC access",
    5985: "WinRM open - test credential access with evil-winrm",
    6379: "Redis open - check for unauthenticated access (redis-cli -h target)",
    8080: "Alt HTTP open - run Web Application Analysis against this port",
    27017: "MongoDB open - check for unauthenticated access (mongo target)",
}


def reverse_dns(target):
    try:
        hostname, _, _ = socket.gethostbyaddr(target)
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        return None


def get_tls_certificate(target, port=443, timeout=5):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target) as tls_sock:
                cert = tls_sock.getpeercert()
    except (OSError, ssl.SSLError):
        return None
    if not cert:
        return None

    subject = dict(x[0] for x in cert.get("subject", []))
    issuer = dict(x[0] for x in cert.get("issuer", []))
    san = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
    not_after = cert.get("notAfter")
    expired = False
    if not_after:
        try:
            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            expired = expiry < datetime.utcnow()
        except ValueError:
            pass

    return {
        "subject_cn": subject.get("commonName"),
        "issuer_cn": issuer.get("commonName"),
        "san": san,
        "not_after": not_after,
        "expired": expired,
    }


def recommend_followups(open_ports):
    recs = []
    for p in open_ports:
        port = p["port"]
        if port in SERVICE_RECOMMENDATIONS:
            recs.append(SERVICE_RECOMMENDATIONS[port])
    return recs


def run(target, open_ports, report=None):
    hostname = reverse_dns(target)
    if report:
        if hostname:
            report.add_finding("DNS & Hostname Discovery", f"Reverse DNS resolved: {hostname}",
                                f"{target} -> {hostname}", "INFO")
        else:
            report.add_finding("DNS & Hostname Discovery", "No reverse DNS record found",
                                f"PTR lookup failed for {target}", "INFO")

    has_tls_port = any(p["port"] in (443, 8443) for p in open_ports)
    cert = None
    if has_tls_port:
        tls_port = 443 if any(p["port"] == 443 for p in open_ports) else 8443
        cert = get_tls_certificate(target, port=tls_port)
        if report:
            if cert:
                detail = (f"CN={cert['subject_cn']} issuer={cert['issuer_cn']} "
                          f"expires={cert['not_after']} SAN={', '.join(cert['san']) or 'none'}")
                severity = "MEDIUM" if cert["expired"] else "INFO"
                title = "TLS certificate expired" if cert["expired"] else "TLS certificate inspected"
                report.add_finding("DNS & Hostname Discovery", title, detail, severity)
            else:
                report.add_finding("DNS & Hostname Discovery", "TLS certificate could not be retrieved",
                                    f"Port {tls_port} did not complete a TLS handshake", "INFO")

    recommendations = recommend_followups(open_ports)
    if report and recommendations:
        report.add_finding("Recommendations", f"{len(recommendations)} follow-up suggestion(s)",
                            " | ".join(recommendations), "INFO")

    return {"hostname": hostname, "tls_certificate": cert, "recommendations": recommendations}

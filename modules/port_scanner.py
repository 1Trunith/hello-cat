import shutil
import socket
import subprocess
import tempfile
import os
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed

from modules.progress import ProgressBar

DEFAULT_PORTS = "1-1000,1433,1521,2049,3000,3306,3389,5432,5900,5985,6379,8000,8008,8080,8443,8888,9000,9090,27017"

COMMON_VULN_BANNERS = {
    "vsftpd 2.3.4": ("CRITICAL", "vsftpd 2.3.4 backdoor (CVE-2011-2523)", "vsftpd_backdoor"),
    "proftpd 1.3.3c": ("HIGH", "ProFTPD 1.3.3c backdoor", "proftpd_backdoor"),
    "openssh 4.": ("MEDIUM", "Old OpenSSH version, check known CVEs", "old_openssh"),
    "openssh 5.": ("LOW", "Older OpenSSH version, check known CVEs", "old_openssh"),
    "samba 3.": ("HIGH", "Old Samba version vulnerable to multiple CVEs (e.g. CVE-2017-7494)", "old_samba"),
    "apache/2.2": ("MEDIUM", "Old Apache 2.2.x, check for known CVEs", "old_apache"),
    "microsoft-iis/6.0": ("HIGH", "IIS 6.0 vulnerable to CVE-2017-7269", "iis6"),
    "unrealircd": ("CRITICAL", "UnrealIRCd backdoor (CVE-2010-2075)", "unrealircd_backdoor"),
}


def nmap_available():
    return shutil.which("nmap") is not None


def run_nmap_scan(target, ports=DEFAULT_PORTS, timing="-T4", timeout=300):
    with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as tmp:
        xml_path = tmp.name
    try:
        cmd = [
            "nmap", "-sV", "-Pn", timing,
            "--host-timeout", f"{max(timeout - 20, 30)}s",
            "-p", ports,
            "-oX", xml_path,
            target,
        ]
        try:
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            check=False, timeout=timeout)
        except subprocess.TimeoutExpired:
            return None
        except OSError:
            return None
        return _parse_nmap_xml(xml_path)
    finally:
        try:
            os.unlink(xml_path)
        except OSError:
            pass


def _parse_nmap_xml(xml_path):
    results = []
    if not os.path.exists(xml_path):
        return results
    try:
        tree = ET.parse(xml_path)
    except ET.ParseError:
        return results

    for host in tree.findall("host"):
        ports_el = host.find("ports")
        if ports_el is None:
            continue
        for port_el in ports_el.findall("port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            portid = int(port_el.get("portid"))
            proto = port_el.get("protocol")
            service_el = port_el.find("service")
            service = service_el.get("name") if service_el is not None else "unknown"
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""
            banner = f"{product} {version}".strip()
            results.append({
                "port": portid,
                "protocol": proto,
                "service": service,
                "banner": banner,
            })
    return results


def _expand_ports(port_spec):
    ports = set()
    for part in port_spec.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.update(range(int(start), int(end) + 1))
        elif part:
            ports.add(int(part))
    return sorted(ports)


def _grab_banner(sock):
    try:
        sock.settimeout(1.5)
        return sock.recv(256).decode(errors="ignore").strip()
    except Exception:
        return ""


def _scan_single_port(target, port, timeout=1.0):
    try:
        with socket.create_connection((target, port), timeout=timeout) as sock:
            banner = _grab_banner(sock)
            try:
                service = socket.getservbyport(port, "tcp")
            except OSError:
                service = "unknown"
            return {
                "port": port,
                "protocol": "tcp",
                "service": service,
                "banner": banner,
            }
    except Exception:
        return None


class ScanInterrupted(Exception):
    def __init__(self, partial):
        super().__init__()
        self.partial = partial


def run_python_scan(target, ports=DEFAULT_PORTS, threads=100, timeout=1.0):
    results = []
    port_list = _expand_ports(ports)
    bar = ProgressBar(total=len(port_list), label="Scanning ports")
    executor = ThreadPoolExecutor(max_workers=threads)
    try:
        futures = {
            executor.submit(_scan_single_port, target, port, timeout): port
            for port in port_list
        }
        for future in as_completed(futures):
            res = future.result()
            if res:
                results.append(res)
            bar.update()
        bar.finish(f"Port scan complete - {len(results)} open")
    except KeyboardInterrupt:
        bar.finish(f"Interrupted - {len(results)} open so far")
        print("[!] Port scan interrupted by user.")
        raise ScanInterrupted(sorted(results, key=lambda r: r["port"]))
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
    return sorted(results, key=lambda r: r["port"])


def scan(target, ports=DEFAULT_PORTS, threads=100, report=None):
    open_ports = None
    method = "python-socket"
    interrupted = False
    if nmap_available():
        open_ports = run_nmap_scan(target, ports=ports)
        method = "nmap"
        if open_ports is None:
            if report:
                report.add_finding("Port Scan", "nmap scan timed out or failed, falling back to Python scanner",
                                    f"target: {target}", "INFO")
            open_ports = None
            method = "python-socket"

    if open_ports is None:
        try:
            open_ports = run_python_scan(target, ports=ports, threads=threads)
        except ScanInterrupted as e:
            open_ports = e.partial
            interrupted = True

    if report:
        report.set_section("port_scan", {"method": method, "open_ports": open_ports})
        if not open_ports:
            report.add_finding("Port Scan", "No open ports detected",
                                f"Scan method: {method}", "INFO")
        for p in open_ports:
            detail = f"{p['protocol']}/{p['port']} - {p['service']} {p['banner']}".strip()
            severity = "INFO"
            vuln_id = None
            banner_lower = p["banner"].lower()
            for sig, (sev, desc, vid) in COMMON_VULN_BANNERS.items():
                if sig in banner_lower:
                    severity = sev
                    vuln_id = vid
                    detail += f" | Possible issue: {desc}"
                    break
            report.add_finding("Port Scan", f"Open port {p['port']}/{p['protocol']}",
                                detail, severity, vuln_id=vuln_id)
    if interrupted:
        raise KeyboardInterrupt
    return open_ports, method

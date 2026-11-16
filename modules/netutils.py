import ipaddress
import socket
from urllib.parse import urlparse


def resolve_target(target):
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        return socket.gethostbyname(target)


def parse_target_input(raw):
    raw = raw.strip()
    scheme, port, path = None, None, ""

    if "://" in raw:
        parsed = urlparse(raw)
        host = parsed.hostname
        scheme = parsed.scheme if parsed.scheme in ("http", "https") else "http"
        port = parsed.port
        if parsed.path and parsed.path != "/":
            path = parsed.path
        if parsed.query:
            path += f"?{parsed.query}"
    elif raw.startswith("[") and "]" in raw:
        host = raw[1:raw.index("]")]
        rest = raw[raw.index("]") + 1:]
        if rest.startswith(":") and rest[1:].isdigit():
            port = int(rest[1:])
    elif raw.count(":") == 1:
        possible_host, possible_port = raw.rsplit(":", 1)
        if possible_port.isdigit():
            host, port = possible_host, int(possible_port)
        else:
            host = raw
    else:
        host = raw

    if scheme is None:
        scheme = "https" if port in (443, 8443) else "http"

    return {"host": host, "scheme": scheme, "port": port, "path": path}

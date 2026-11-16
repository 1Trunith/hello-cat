import ipaddress
import socket


def resolve_target(target):
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        return socket.gethostbyname(target)

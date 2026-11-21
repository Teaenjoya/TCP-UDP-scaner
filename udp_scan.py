import socket


def scan_udp_port(ip, port, timeout):
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET

    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)

        try:
            sock.connect((ip, port))
            sock.send(b"portscan")
            sock.recv(65535)
        except socket.timeout:
            return "no_response"
        except (ConnectionRefusedError, ConnectionResetError):
            return "closed"

    return "open"

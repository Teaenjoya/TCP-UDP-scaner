import socket


def scan_udp_port(ip, port, timeout):
    address_family = socket.AF_INET6 if ":" in ip else socket.AF_INET

    with socket.socket(address_family, socket.SOCK_DGRAM) as udp_socket:
        udp_socket.settimeout(timeout)
        try:
            udp_socket.connect((ip, port))
            udp_socket.send(b"portscan")
            udp_socket.recv(65535)
        except socket.timeout:
            return "no_response"
        except (ConnectionRefusedError, ConnectionResetError):
            return "closed"

    return "open"

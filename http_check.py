import socket
import time


def guess_http(ip, port, timeout):
    address_family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    host = ip if address_family == socket.AF_INET else f"[{ip.split('%', 1)[0]}]"
    request = f"HEAD / HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n".encode("ascii")

    response = b""
    try:
        with socket.socket(address_family, socket.SOCK_STREAM) as tcp_socket:
            tcp_socket.settimeout(timeout)
            tcp_socket.connect((ip, port))
            tcp_socket.sendall(request)

            deadline = time.monotonic() + timeout
            while b"\r\n" not in response and len(response) < 1024:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                tcp_socket.settimeout(remaining)

                data = tcp_socket.recv(1024 - len(response))
                if not data:
                    break
                response += data
    except OSError:
        return "-"

    status_line, separator, _ = response.partition(b"\r\n")
    fields = status_line.split(b" ", 2)
    if not separator or len(fields) < 2:
        return "-"

    version, status_code = fields[:2]
    if version in (b"HTTP/1.0", b"HTTP/1.1") and len(status_code) == 3 and status_code.isdigit():
        return "HTTP"
    return "-"

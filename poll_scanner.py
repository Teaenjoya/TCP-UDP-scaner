import math
import select
import time
from contextlib import ExitStack

from tcp_scanner import open_tcp_scanner, read_tcp_response, start_tcp_scan
from udp_scanner import read_udp_response, start_udp_scan


BATCH_SIZE = 64
MAX_POLL_TIMEOUT_MS = 2_147_483_647


def scan_ports(ip, ports, timeout):
    if not hasattr(select, "poll"):
        raise OSError("Для poll() запусти сканер в Ubuntu.")

    with ExitStack() as sockets:
        tcp_settings = None
        if any(protocol == "tcp" for protocol, _ in ports):
            tcp_settings = sockets.enter_context(open_tcp_scanner(ip))

        for start in range(0, len(ports), BATCH_SIZE):
            batch = ports[start:start + BATCH_SIZE]
            open_ports = scan_batch(ip, batch, timeout, tcp_settings)
            for protocol, port in batch:
                if (protocol, port) in open_ports:
                    yield protocol, port, open_ports[protocol, port]


def scan_batch(ip, ports, timeout, tcp_settings):
    poller = select.poll()
    pending_tcp = {}
    pending_udp = {}
    open_ports = {}
    tcp_socket_fd = None

    if tcp_settings is not None:
        raw_socket, source_port, source_ip_b, dest_ip_b = tcp_settings
        for protocol, port in ports:
            if protocol == "tcp":
                pending_tcp[port] = start_tcp_scan(raw_socket, source_port, source_ip_b, dest_ip_b, port)
        if pending_tcp:
            tcp_socket_fd = raw_socket.fileno()
            poller.register(tcp_socket_fd, select.POLLIN)

    with ExitStack() as sockets:
        for protocol, port in ports:
            if protocol != "udp":
                continue
            try:
                udp_socket, query = sockets.enter_context(start_udp_scan(ip, port))
            except (ConnectionRefusedError, ConnectionResetError):
                continue
            socket_fd = udp_socket.fileno()
            poller.register(socket_fd, select.POLLIN | select.POLLERR)
            pending_udp[socket_fd] = (port, udp_socket, query)

        deadline = time.monotonic() + timeout
        while pending_tcp or pending_udp:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break

            # poll ждёт миллисекунды, time.monotonic() возвращает секунды.
            wait_ms = math.ceil(min(remaining * 1000, MAX_POLL_TIMEOUT_MS))
            for socket_fd, _ in poller.poll(wait_ms):
                if socket_fd == tcp_socket_fd:
                    response = read_tcp_response(raw_socket, source_port, source_ip_b, dest_ip_b, pending_tcp)
                    if response is None:
                        continue
                    port, status = response
                    del pending_tcp[port]
                    if not pending_tcp:
                        poller.unregister(socket_fd)
                    protocol, application_protocol = "tcp", "-"
                else:
                    port, udp_socket, query = pending_udp[socket_fd]
                    response = read_udp_response(udp_socket, query)
                    if response is None:
                        continue
                    status, application_protocol = response
                    del pending_udp[socket_fd]
                    poller.unregister(socket_fd)
                    protocol = "udp"

                if status == "open":
                    open_ports[protocol, port] = application_protocol

    return open_ports

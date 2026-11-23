import random
import socket
import struct
import time
from contextlib import contextmanager


SYN = 0x02
RST = 0x04
ACK = 0x10
header_size = 20


@contextmanager
def open_tcp_scanner(ip):
    address_family = socket.AF_INET6 if ":" in ip else socket.AF_INET

    with (socket.socket(address_family, socket.SOCK_RAW, socket.IPPROTO_TCP) as raw_socket,
          socket.socket(address_family, socket.SOCK_STREAM) as free_port_socket):

        if address_family == socket.AF_INET:
            raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        raw_socket.connect((ip, 0))
        local_address = raw_socket.getsockname()
        local_ip = local_address[0]
        free_port_socket.bind((local_ip, 0, *local_address[2:]))

        source_port = free_port_socket.getsockname()[1]
        source_ip_b = socket.inet_pton(address_family, local_ip)
        dest_ip_b = socket.inet_pton(address_family, ip.split("%", 1)[0])

        raw_socket.setblocking(False)
        yield raw_socket, source_port, source_ip_b, dest_ip_b


def start_tcp_scan(raw_socket, source_port, source_ip_b, dest_ip_b, dest_port):
    sequence = random.getrandbits(2**5)
    expected_ack = (sequence + 1) & 0xFFFFFFFF

    packet = build_tcp_packet(source_ip_b, source_port, dest_ip_b, dest_port, sequence, SYN)
    sent_at = time.monotonic()
    raw_socket.send(packet)
    return expected_ack, sent_at


def read_tcp_response(raw_socket, source_port, source_ip_b, dest_ip_b, pending_tcp):
    address_family = raw_socket.family
    try:
        response = raw_socket.recv(65535)
        received_at = time.monotonic()
    except BlockingIOError:
        return None

    tcp_offset = 0
    if address_family == socket.AF_INET:
        if response[12:20] != dest_ip_b + source_ip_b:
            return None
        tcp_offset = (response[0] & 0x0F) * 4
        if tcp_offset < header_size:
            return None
    if len(response) < tcp_offset + header_size:
        return None

    response_port, response_dest_port, _, response_ack, _, flags = struct.unpack_from("!HHIIBB", response, tcp_offset)
    if response_dest_port != source_port:
        return None
    expected_ack, sent_at = pending_tcp.get(response_port, (None, None))
    if not flags & ACK or response_ack != expected_ack:
        return None

    if flags & RST:
        return response_port, "closed", None
    if flags & SYN:
        reset = build_tcp_packet(source_ip_b, source_port, dest_ip_b, response_port, response_ack, RST)
        raw_socket.send(reset)
        response_time_ms = (received_at - sent_at) * 1000
        return response_port, "open", response_time_ms
    return None


def build_tcp_packet(source_ip_b, source_port, dest_ip_b, dest_port, sequence, flags):
    window = 0 #RST
    if flags == SYN:
        window += 1024 #SYN

    if len(source_ip_b) == 4:
        ip_header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, header_size * 2, 0, 0, 64, socket.IPPROTO_TCP, 0, source_ip_b, dest_ip_b)
        ip_checksum = struct.pack("!H", checksum(ip_header))
        ip_header = ip_header[:10] + ip_checksum + ip_header[12:]
        pseudo_tcp_header = struct.pack("!4s4sBBH", source_ip_b, dest_ip_b, 0, socket.IPPROTO_TCP, header_size)
    else:
        ip_header = b""
        pseudo_tcp_header = struct.pack("!16s16sI3xB", source_ip_b, dest_ip_b, header_size, socket.IPPROTO_TCP)

    tcp_header = struct.pack("!HHIIBBHHH", source_port, dest_port, sequence, 0, 5 << 4, flags, window, 0, 0)
    tcp_checksum = struct.pack("!H", checksum(pseudo_tcp_header + tcp_header))
    tcp_header = tcp_header[:16] + tcp_checksum + tcp_header[18:]

    return ip_header + tcp_header


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


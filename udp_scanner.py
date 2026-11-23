import socket
import random
import struct
from contextlib import contextmanager


@contextmanager
def start_udp_scan(ip, dest_port):
    address_family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    query = build_dns_query("example.com")

    with socket.socket(address_family, socket.SOCK_DGRAM) as udp_socket:
        udp_socket.connect((ip, dest_port))
        udp_socket.setblocking(False)
        udp_socket.send(query)
        yield udp_socket, query


def read_udp_response(udp_socket, query):
    try:
        response = udp_socket.recv(65535)
    except BlockingIOError:
        return None
    except (ConnectionRefusedError, ConnectionResetError):
        return "closed", None

    if is_dns_response(query, response):
        return "open", "DNS"
    if response == query:
        return "open", "ECHO"
    return "open", '-'


def build_dns_query(domain_name, qtype=1):
    query_id = random.randint(0, 65535)
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)

    qname_bytes = b''
    for label in domain_name.split('.'):
        qname_bytes += bytes([len(label)]) + label.encode('ascii')
    qname_bytes += b'\x00'

    question = qname_bytes + struct.pack('!HH', qtype, 1)
    return header + question


def is_dns_response(query, response):
    dns_header_size = 12
    if len(response) < len(query):
        return False

    _, flags, question_count, _, _, _ = struct.unpack("!HHHHHH", response[:dns_header_size])
    if response[:2] != query[:2] or question_count != 1:
        return False
    if (flags & 0xF800) != 0x8000:  #qr = 1, opcode = 0
        return False

    sent_question = query[dns_header_size:]
    returned_question = response[dns_header_size:len(query)]
    return returned_question.lower() == sent_question.lower()

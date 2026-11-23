import sys

from parser import parse_args
from tcp_scanner import scan_tcp_port
from udp_scanner import scan_udp_port


def main():
    if len(sys.argv) < 2:
        print("Справка - python main.py portscan --help", file=sys.stderr)
        return 2
    if sys.argv[1] != "portscan":
        print(f"Команда '{sys.argv[1]}' не найдена.", file=sys.stderr)
        return 2

    args = parse_args(sys.argv[2:])
    for protocol, port in args.ports:
        transport = protocol.upper()
        try:
            if protocol == "tcp":
                status = scan_tcp_port(args.ip_address, port, args.timeout)
                application_protocol = "-"
            else:
                status, application_protocol = scan_udp_port(args.ip_address, port, args.timeout)
        except OSError as error:
            raise SystemExit(f"{transport} {port}: {error}")

        if status == "open":
            line = f"{transport} {port}"
            if args.guess:
                line += f" {application_protocol}"
            print(line)


if __name__ == "__main__":
    main()

import sys

from parser import parse_args
from poll_scanner import scan_ports


def main():
    if len(sys.argv) < 2:
        print("Справка - python main.py portscan --help", file=sys.stderr)
        return 2
    if sys.argv[1] != "portscan":
        print(f"Команда '{sys.argv[1]}' не найдена.", file=sys.stderr)
        return 2

    args = parse_args(sys.argv[2:])
    try:
        for protocol, port, application_protocol in scan_ports(args.ip_address, args.ports, args.timeout):
            line = f"{protocol.upper()} {port}"
            if args.guess:
                line += f" {application_protocol}"
            print(line)
    except OSError as error:
        raise SystemExit(str(error))


if __name__ == "__main__":
    main()

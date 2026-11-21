from cli import parse_args
from udp_scan import scan_udp_port


def main():
    args = parse_args()
    for protocol, port in args.ports:
        if protocol != "udp":
            continue

        try:
            status = scan_udp_port(args.ip_address, port, args.timeout)
        except OSError as error:
            raise SystemExit(f"UDP {port}: {error}")

        if status == "open":
            print(f"UDP {port}")


if __name__ == "__main__":
    main()

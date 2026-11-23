import argparse
import math
from ipaddress import ip_address
from port_selector import parse_port_selection


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog="portscan",
        description="Принимает IP-адрес и список TCP- и UDP-портов.",
        allow_abbrev=False,
    )
    parser.add_argument("ip_address", metavar="IP_ADDRESS", help="IP-адрес узла")
    parser.add_argument(
        "ports",
        nargs="*",
        metavar="PORTS",
        help="например tcp/80 или udp/3000-3100,3200; без списка берутся все порты TCP и UDP",
    )

    parser.add_argument("--timeout", type=float, default=2.0, help="таймаут в секундах (по умолчанию 2)")
    parser.add_argument("-j", "--num-threads", type=int, default=1, help="число потоков (по умолчанию 1)")
    parser.add_argument("-v", "--verbose", action="store_true", help="показывать время ответа TCP")
    parser.add_argument("-g", "--guess", action="store_true", help="определять прикладной протокол")
    args = parser.parse_args(argv)

    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout должен быть конечным числом больше нуля")
    if args.num_threads < 1:
        parser.error("--num-threads должен быть целым числом больше нуля")

    try:
        args.ip_address = str(ip_address(args.ip_address))
    except ValueError:
        parser.error(f"некорректный IP-адрес: {args.ip_address!r}")

    try:
        args.ports = parse_port_selection(args.ports)
    except ValueError as error:
        parser.error(str(error))

    return args

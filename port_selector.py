MIN_PORT = 1
MAX_PORT = 65535


def parse_port_number(value):
    if not value.isascii() or not value.isdecimal():
        raise ValueError(f"ожидался номер порта, получено {value!r}")

    port = int(value)
    if not MIN_PORT <= port <= MAX_PORT:
        raise ValueError(f"порт должен быть от {MIN_PORT} до {MAX_PORT}: {port}")
    return port


def parse_port_range(value):
    first, separator, last = value.partition("-")
    start = parse_port_number(first)
    end = parse_port_number(last) if separator else start

    if start > end:
        raise ValueError(f"начало диапазона больше конца: {value}")
    return [port for port in range(start, end + 1)]


def parse_port_selection(port_args):
    ports_pairs = []
    seen = set()

    for port_arg in port_args or ("tcp", "udp"):
        protocol, _, selection = port_arg.partition("/")
        if protocol not in ("tcp", "udp"):
            raise ValueError(f"ожидалось tcp или udp в {port_arg!r}")

        parts = selection.split(",") if selection else [f"{MIN_PORT}-{MAX_PORT}"]
        for part in parts:
            for port in parse_port_range(part):
                pair = (protocol, port)
                if pair not in seen:
                    ports_pairs.append(pair)
                    seen.add(pair)

    return ports_pairs

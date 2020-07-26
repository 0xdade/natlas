import argparse

from config import Config

config = Config()


def parse_args():
    PARSER_DESC = "Scan hosts and report data to a configured server. The server will reject your findings if they are deemed not in scope."
    PARSER_EPILOG = "Report problems to https://github.com/natlas/natlas"
    parser = argparse.ArgumentParser(
        description=PARSER_DESC, epilog=PARSER_EPILOG, prog="natlas-agent"
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {config.NATLAS_VERSION}"
    )
    mutually_exclusive = parser.add_mutually_exclusive_group()
    mutually_exclusive.add_argument(
        "--target",
        metavar="IPADDR",
        help="An IPv4 address or CIDR range to scan. e.g. 192.168.0.1, 192.168.0.1/24",
        dest="target",
    )
    mutually_exclusive.add_argument(
        "--target-file",
        metavar="FILENAME",
        help="A file of line separated target IPv4 addresses or CIDR ranges",
        dest="tfile",
    )
    return parser.parse_args()

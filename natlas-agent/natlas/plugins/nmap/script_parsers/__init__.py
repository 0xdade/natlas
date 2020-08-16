"""
    These are for parsing *intentionally* structured script outputs.
    The reason for not just storing the default structured script outputs of all scripts
    is that many scripts nest output incredibly deeply which causes storage problems.

    So if you want to store structured output from a script, add a parser here.

    known_parsers keys must be the name of the nmap script
    "parser" is the reference to the function that takes the script output
    "name" is the name of the field you'd like to store your structured data in
"""
from . import ssl_cert

known_parsers = {"ssl-cert": {"parser": ssl_cert.parse_ssl, "name": "ssl"}}


def get_parser(script_name: str):
    p = known_parsers.get(script_name, None)
    if not p:
        return None
    return p.get("parser", None)


def get_output_name(script_name: str):
    p = known_parsers.get(script_name, None)
    if not p:
        return None
    return p.get("name", None)

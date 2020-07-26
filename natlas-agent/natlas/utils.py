import ipaddress

from natlas import logging
from config import Config

utillogger = logging.get_logger("Utilities")
conf = Config()


def validate_target(target, config):
    try:
        iptarget = ipaddress.ip_address(target)
        if iptarget.is_private and not config.scan_local:
            utillogger.error("We're not configured to scan local addresses!")
            return False
    except ipaddress.AddressValueError:
        utillogger.error(f"{target} is not a valid IP Address")
        return False
    return True

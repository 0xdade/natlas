import hashlib

from natlas import logging, utils

logger = logging.get_logger("FileOperations")
services_path = utils.get_services_path()


def current_hash():
    """
        Get hash of current natlas-services file
    """
    with open(services_path, "r") as f:
        return hashlib.sha256(f.read().rstrip("\r\n").encode()).hexdigest()


def get_hash(services: str):
    """
        Calculate hash of provided services string
    """
    return hashlib.sha256(services.encode()).hexdigest()


def new_services(services_response: dict):
    """
        Ensure we have the new services file
    """
    if services_response["sha256"] == current_hash():
        logger.info("Provided hash matches hash of existing file")
        return True
    calculated_hash = get_hash(services_response["services"])
    if services_response["sha256"] != calculated_hash:
        logger.error("Provided hash doesn't match locally calculated hash of services")
        return False
    with open(services_path, "w") as f:
        f.write(services_response["services"])
    if services_response["sha256"] != current_hash():
        logger.error("Hash of written file does not match expected hash")
        return False
    return current_hash()

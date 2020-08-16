import hashlib


def calculate_hash(data):
    """
        Calculate hash of provided data and return hexdigest
        Abstracted out here so that we can change hashing algorithms
        at will.
    """
    return hashlib.sha256(data.encode()).hexdigest()


def current_file_hash(services_path):
    """
        Get hash of current natlas-services file
    """
    with open(services_path, "r") as f:
        return calculate_hash(f.read().rstrip("\r\n"))


def new_services(services_path: str, services_response: dict, logger):
    """
        Ensure we have the new services file
    """
    if services_response["sha256"] == current_file_hash():
        logger.info("Provided hash matches hash of existing file")
        return True
    calculated_hash = calculate_hash(services_response["services"])
    if services_response["sha256"] != calculated_hash:
        logger.error("Provided hash doesn't match locally calculated hash of services")
        return False
    with open(services_path, "w") as f:
        f.write(services_response["services"])
    if services_response["sha256"] != current_file_hash():
        logger.error("Hash of written file does not match expected hash")
        return False
    return current_file_hash()

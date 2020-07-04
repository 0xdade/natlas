from config import Config
from natlas import logging
from natlas.network.client import NetworkClient
import natlas.file.natlas_services as natlas_services


class NetworkInterface:

    config = None
    client = None
    logger = logging.get_logger("NetworkInterface")
    content_type = "application/json"

    def __init__(self, config: Config):
        self.config = config
        self.client = NetworkClient(config)

    def get_work(self, target: str = None):
        """
            Get work from the server. Optionally specify the address you intend to
            scan to get the config to use for the scan.
        """
        api_endpoint = "/api/getwork"
        if target:
            api_endpoint += f"?target={target}"
        self.logger.info(f"Fetching work from {self.config.server}")
        response = self.client.get(api_endpoint)
        if (
            not response
            or response.headers.get("Content-Type", None) != self.content_type
        ):
            return False
        return response.json()

    def submit_results(self, result: dict):
        """
            Results should be validated prior to reaching this step
        """
        api_endpoint = "/api/submit"
        self.logger.info(
            f"Submitting results for {result['ip']} to {self.config.server}"
        )
        response = self.client.post(api_endpoint, result)
        return response.json()

    def get_services_file(self):
        """
            Fetch services file for nmap
        """
        api_endpoint = "/api/natlas-services"
        self.logger.info(f"Fetching natlas-services file from {self.config.server}")
        response = self.client.get(api_endpoint)
        if not response:
            return False
        return natlas_services.new_services(response.json())

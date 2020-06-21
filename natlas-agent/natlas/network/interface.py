from natlas import logging
from natlas.network.client import NetworkClient


class NetworkInterface:

    config = None
    client = None
    logger = logging.get_logger("NetworkInterface")
    content_type = "application/json"

    def __init__(self, config):
        self.config = config
        self.client = NetworkClient(config)

    def get_work(self, target=None):
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

    def submit_results(self, result):
        """
            Results should be validated prior to reaching this step
        """
        api_endpoint = "/api/submit"
        self.logger.info(
            f"Submitting results for {result['ip']} to {self.config.server}"
        )
        response = self.client.post(api_endpoint, result)
        return response.json()

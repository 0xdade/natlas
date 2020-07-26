"""
natlas.network.client contains the functions that actually handle making requests on behalf of the agent.
The primary purpose of this distinction is so that we can have a centrally managed request backoff process.

"""

import time
import random
import json

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urljoin

from natlas.net import logger


class NetworkClient:

    # Loaded from config at init
    agent_id = None
    auth_token = None
    backoff_base = None
    backoff_max = None
    ignore_ssl_warn = None
    NATLAS_VERSION = None
    max_retries = None
    request_timeout = None
    server = None

    # Common request configurations
    headers = {}
    session = None

    def __init__(self, config):
        """
        Load relevant config items
        Could be improved further by using config namespacing to group network configs together
        """
        for attr, val in vars(config).items():
            if hasattr(self, attr):
                setattr(self, attr, val)

        if self.ignore_ssl_warn:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

        self.headers = self._build_headers()
        self.session = requests.Session()

    def get(self, endpoint):
        req = self._build_request("GET", endpoint)
        return self._backoff_request(req)

    def post(self, endpoint, data):
        req = self._build_request("POST", endpoint)
        req.headers["Content-Type"] = "application/json"
        req.json = json.dumps(data)
        return self._backoff_request(req)

    def _backoff_request(self, req):
        attempt = 0
        resp = None

        while attempt < self.max_retries and not resp:
            resp = self._send_request(req)
            if not resp or self._retry_check(resp):
                attempt += 1
                self._sleep(attempt)
                continue
        return resp

    def _send_request(self, req):
        try:
            return self.session.send(
                req, timeout=self.request_timeout, verify=not self.ignore_ssl_warn
            )
        except requests.ConnectionError:
            logger.warn(f"ConnectionError Connecting to {self.server}")
            return False
        except requests.Timeout:
            logger.warn(f"Request timed out after {self.request_timeout} seconds.")
            return False

    def _retry_check(self, resp):
        try:
            if resp.status_code == 200:
                return False
            r = resp.json()
            if r.get("retry", None):
                return True
        except ValueError:
            return False

    def _sleep(self, attempt):
        jitter = random.randint(0, 1000) / 1000  # jitter to reduce chance of locking
        current_sleep = min(self.backoff_max, self.backoff_base * 2 ** attempt) + jitter
        logger.debug(
            f"Request failed. Waiting {current_sleep} seconds before retrying."
        )
        time.sleep(current_sleep)

    def _build_headers(self):
        headers = {
            "User-Agent": f"natlas-agent/{self.NATLAS_VERSION}",
            "Accept": "application/json",
        }
        if self.agent_id and self.auth_token:
            headers["Authorization"] = f"Bearer {self.agent_id}:{self.auth_token}"

        return headers

    def _build_request(self, reqtype, endpoint):
        url = urljoin(self.server, endpoint)
        req = requests.Request(reqtype, url, headers=self.headers)
        return self.session.prepare_request(req)

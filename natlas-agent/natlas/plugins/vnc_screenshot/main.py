import os
import subprocess

from natlas.plugins.plugin import NatlasPlugin

from natlas import logging, ScanResult
from natlas.fs import natlas_paths
from natlas.fs.validators import is_valid_image
from natlas.fs.encoders import base64_file


class VncScreenshot(NatlasPlugin):

    __plugin__ = "vnc_screenshot"
    __author__ = "Natlas Team"
    __website__ = "https://github.com/natlas/natlas"
    __description__ = "Enables VNC screenshots based on identified open VNC ports"
    __requires__ = ["nmap"]

    logger = logging.get_plugin_logger(__plugin__)

    def init_scan(self, plugin_config):
        self.target = plugin_config["target"]
        self.config = plugin_config["plugins"][self.__plugin__]
        self.scan_id = plugin_config["scan_id"]
        self.out_dir = natlas_paths.get_scan_plugin_dir(self.scan_id, self.__plugin__)
        self.output_file = os.path.join(self.out_dir, f"vncsnapshot.{self.scan_id}.jpg")
        self.command = self.build_command()

    def build_command(self):
        return [
            "xvfb-run",
            "vncsnapshot",
            "-quality",
            "50",
            self.target,
            self.output_file,
        ]

    def run(self, result: ScanResult = None):
        self.logger.info(" ".join(self.command))
        if not self.vnc_screenshot():
            return False
        return self.parse_vnc_screenshot()

    def vnc_screenshot(self):
        process = subprocess.Popen(
            self.command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )  # nosec
        try:
            process.communicate(timeout=int(self.config["plugin_timeout"]))
        except subprocess.TimeoutExpired:
            self.logger.warning(f"TIMEOUT: Killing vncsnapshot against {self.target}")
            process.kill()
            return False
        return True

    def parse_vnc_screenshot(self):
        if not is_valid_image(self.output_file):
            return {}

        self.logger.info(f"VNC screenshot acquired for {self.target} on port 5900")
        return {
            "host": self.target,
            "port": 5900,
            "service": "VNC",
            "data": base64_file(self.output_file),
        }

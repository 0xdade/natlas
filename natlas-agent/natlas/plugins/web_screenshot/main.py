import os
import subprocess
import time

from natlas.plugins.plugin import NatlasPlugin
from natlas import logging, ScanResult
from natlas.fs import natlas_paths

from .parser import parse_aquatone_session


class WebScreenshot(NatlasPlugin):

    __plugin__ = "web_screenshot"
    __author__ = "Natlas Team"
    __website__ = "https://github.com/natlas/natlas"
    __description__ = "Enables web screenshots based on identified open http ports"
    __requires__ = ["nmap"]

    logger = logging.get_plugin_logger(__plugin__)

    def init_scan(self, plugin_config):
        self.target = plugin_config["target"]
        self.config = plugin_config["plugins"][self.__plugin__]
        self.scan_id = plugin_config["scan_id"]
        self.out_dir = natlas_paths.get_scan_plugin_dir(self.scan_id, self.__plugin__)
        self.command = self.build_command()

    def build_command(self):
        return ["aquatone", "-nmap", "-scan-timeout", "2500", "-out", self.out_dir]

    def run(self, result: ScanResult = None):
        self.logger.info(" ".join(self.command))
        if not self.aquatone():
            return False
        return parse_aquatone_session(self.out_dir, self.logger)

    def aquatone(self):
        nmap_dir = natlas_paths.get_scan_plugin_dir(self.scan_id, "nmap")
        xml_file = os.path.join(nmap_dir, f"nmap.{self.scan_id}.xml")

        with open(xml_file, "r") as f:
            process = subprocess.Popen(
                self.command, stdin=f, stdout=subprocess.DEVNULL
            )  # nosec

        try:
            process.communicate(timeout=int(self.config["plugin_timeout"]))
            if process.returncode == 0:
                # I don't know why, but without this sleep sometimes files are still 0 bytes when we read them
                time.sleep(0.5)
        except subprocess.TimeoutExpired:
            self.logger.warning(f"TIMEOUT: Killing aquatone against {self.target}")
            process.kill()
            return False

        return True

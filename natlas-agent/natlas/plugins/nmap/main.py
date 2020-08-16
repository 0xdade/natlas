import os
import subprocess

from natlas import logging, ScanResult
from natlas.plugins import NatlasPlugin
from natlas.fs import natlas_paths
from .parser import parse_nmap


class Nmap(NatlasPlugin):

    __plugin__ = "nmap"
    __author__ = "Natlas Team"
    __website__ = "https://github.com/natlas/natlas"
    __description__ = "Core nmap functionality"
    __requires__ = []

    logger = logging.get_plugin_logger(__plugin__)

    def __init__(self):
        self.services_path = os.path.join(
            natlas_paths.get_conf_plugin_dir(self.__plugin__), "natlas-services"
        )

    def init_scan(self, plugin_config):
        self.target = plugin_config["target"]
        self.scan_id = plugin_config["scan_id"]
        self.out_dir = natlas_paths.get_scan_plugin_dir(self.scan_id, self.__plugin__)
        self.config = plugin_config["plugins"][self.__plugin__]
        self.command = self.build_command()

    def build_command(self):
        outFiles = os.path.join(self.out_dir, f"nmap.{self.scan_id}")
        command = [
            "nmap",
            "--privileged",
            "-oA",
            outFiles,
            "--servicedb",
            self.services_path,
        ]

        commandDict = {
            "versionDetection": "-sV",
            "osDetection": "-O",
            "osScanLimit": "--osscan-limit",
            "noPing": "-Pn",
            "onlyOpens": "--open",
            "udpScan": "-sUS",
            "enableScripts": "--script={scripts}",
            "scriptTimeout": "--script-timeout={scriptTimeout}",
            "hostTimeout": "--host-timeout={hostTimeout}",
        }

        for k, _ in self.config.items():
            if self.config[k] and k in commandDict:
                command.append(commandDict[k].format(**self.config))

        command.append(self.target)
        return command

    def run(self, result: ScanResult = None):
        self.logger.info(" ".join(self.command))
        if not self.nmap():
            return False
        return parse_nmap(self.out_dir, self.scan_id, self.logger)

    def nmap(self):
        try:
            subprocess.run(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=int(self.config["plugin_timeout"]),
            )  # nosec
        except subprocess.TimeoutExpired:
            self.logger.warning(f"TIMEOUT: Nmap against {self.target} ({self.scan_id})")
            return False
        self.logger.info(f"Nmap {self.target} ({self.scan_id}) complete")
        return True

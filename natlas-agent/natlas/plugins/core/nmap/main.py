import os
import subprocess

from natlas import utils, logging, ScanResult
from natlas.plugins import NatlasPlugin
from .parser import parse


class Nmap(NatlasPlugin):

    __plugin__ = "nmap"
    __author__ = "Natlas Core Team"
    __website__ = "https://github.com/natlas/natlas"
    __description__ = "Core nmap functionality"
    __requires__ = []

    logger = logging.get_plugin_logger(__plugin__)

    def __init__(self, plugin_config):
        self.target = plugin_config["target"]
        self.scan_id = plugin_config["scan_id"]
        self.out_dir = utils.get_plugin_dir(self.scan_id, self.__plugin__)
        self.config = plugin_config["plugins"][self.__plugin__]
        self.services_path = os.path.join(
            utils.get_conf_dir(self.__plugin__), "natlas-services"
        )
        self.command = self.build_command()

    def run(self, result: ScanResult = None):
        if not self.nmap():
            return False
        return parse(self.out_dir, self.scan_id, self.logger)

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
        self.logger.info(" ".join(command))
        return command

    def nmap(self):
        try:
            subprocess.run(
                self.command,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=int(self.config["scanTimeout"]),
            )  # nosec
        except subprocess.TimeoutExpired:
            self.logger.warning(f"TIMEOUT: Nmap against {self.target} ({self.scan_id})")
            return False
        self.logger.info(f"Nmap {self.target} ({self.scan_id}) complete")
        return True

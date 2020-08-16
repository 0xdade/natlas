from natlas.plugins.plugin import NatlasPlugin

from natlas import logging, ScanResult
from natlas.fs import natlas_paths


class WhatWeb(NatlasPlugin):

    __plugin__ = "whatweb"
    __author__ = "Natlas Team"
    __website__ = "https://github.com/natlas/natlas"
    __description__ = "Enables web fingerprinting based on identified open http ports"
    __requires__ = ["nmap"]

    logger = logging.get_plugin_logger(__plugin__)

    def init_scan(self, plugin_config):
        self.target = plugin_config["target"]
        self.config = plugin_config["plugins"][self.__plugin__]
        self.scan_id = plugin_config["scan_id"]
        self.scan_dir = natlas_paths.get_scan_plugin_dir(self.scan_id, self.__plugin__)
        self.command = self.build_command()

    def build_command(self):
        print(f"Building command for {self.__plugin__}")
        return []

    def run(self, result: ScanResult = None):
        print(f"Running {self.__plugin__}")

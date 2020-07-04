import os
import subprocess
from libnmap.objects.report import NmapReport

from libnmap.parser import NmapParser, NmapParserException

from natlas.plugins.plugin import NatlasPlugin
from natlas import utils, logging


class Nmap(NatlasPlugin):

    __plugin__ = "nmap"
    __author__ = "Natlas Core Team"
    __website__ = "https://github.com/natlas/natlas"
    __description__ = "Core nmap functionality"
    __requires__ = ["masscan"]

    logger = logging.get_logger("Plugin::Nmap")

    def __init__(self):
        print(f"{self.__name__} Loaded")

    def activate(self, target, config, scan_id):
        self.target = target
        self.config = config
        self.command = self.build_command()
        self.scan_id = scan_id
        self.scan_dir = utils.get_scan_dir(scan_id)
        self.run()

    def build_command(self):
        outFiles = os.path.join(self.scan_dir, f"nmap.{self.scan_id}")
        servicepath = utils.get_services_path()
        command = ["nmap", "--privileged", "-oA", outFiles, "--servicedb", servicepath]

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

        for k, v in self.config.items():
            if self.config[k] and k in commandDict:
                command.append(commandDict[k].format(**self.config))

        command.append(self.target)
        return command

    def run(self):
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

    def parse_output(self):
        result = {"raw_data": {}, "is_up": None, "port_count": None, "ports": {}}
        for ext in "nmap", "gnmap", "xml":
            path = os.path.join(self.scan_dir, f"nmap.{self.scan_id}.{ext}")
            try:
                with open(path, "r") as f:
                    result["raw_data"][f"{ext}_data"] = f.read()
            except IOError:
                self.logger.warning(f"Couldn't read {path}")
                return False

        try:
            nmap_report = NmapParser.parse(result["raw_data"]["xml_data"])
        except NmapParserException:
            self.logger.warning(f"Couldn't parse nmap.{self.scan_id}.xml")
            return False

        if nmap_report.hosts_total < 1 or nmap_report.hosts_total > 1:
            self.logger.warning(
                f"Unexpected number of hosts found in nmap.{self.scan_id}.xml ({nmap_report.hosts_total})"
            )
            return False
        elif nmap_report.hosts_down == 1:
            # host is down
            result["is_up"] = False
        elif nmap_report.hosts_up == 1 and len(nmap_report.hosts) == 0:
            # host is up but no reportable ports were found
            result["is_up"] = True
            result["port_count"] = 0
        else:
            # host is up and reportable ports were found
            result["is_up"] = nmap_report.hosts[0].is_up()
            result["port_count"] = len(nmap_report.hosts[0].get_ports())
            result["ports"] = self.parse_ports(nmap_report)
        return result

    def parse_ports(self, nmap_report: NmapReport):
        return nmap_report.hosts[0].get_ports()

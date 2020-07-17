from natlas.plugins.plugin import NatlasPlugin

from natlas import utils


class WebScreenshot(NatlasPlugin):

    __plugin__ = "web_screenshot"
    __author__ = "Natlas Core Team"
    __website__ = "https://github.com/natlas/natlas"
    __description__ = "Enables web screenshots based on identified open http ports"
    __requires__ = ["nmap"]

    def __init__(self, plugin_config):
        print(f"{self.__plugin__} Loaded")
        self.target = plugin_config["target"]
        self.config = plugin_config["config"][self.__plugin__]
        self.command = self.build_command()
        self.scan_id = plugin_config["scan_id"]
        self.scan_dir = utils.get_scan_dir(self.scan_id)

    def build_command(self):
        print(f"Building command for {self.__plugin__}")
        return []

    def run(self):
        print(f"Running {self.__plugin__}")

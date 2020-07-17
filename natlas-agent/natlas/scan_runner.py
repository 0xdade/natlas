from config import Config
from natlas.plugins import PluginLoader
from natlas import ScanResult


class ScanRunner:
    def __init__(self, scan_config: dict, natlas_config: Config):
        self.pl = PluginLoader(scan_config)
        self.result = ScanResult(scan_config, natlas_config)

    def run(self):
        self.result.start_scan()
        for plug in self.pl.next_plugin():
            self.result.add_plugin(plug.__plugin__, plug.run(self.result))
        self.result.stop_scan()

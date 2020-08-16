from config import Config
from natlas import PluginLoader, ScanResult


class ScanRunner:
    def __init__(
        self, plugin_loader: PluginLoader, scan_config: dict, natlas_config: Config
    ):
        self.config = scan_config
        self.pl = plugin_loader
        self.result = ScanResult(scan_config, natlas_config)

    def next_plugin(self):
        for plug in self.pl.get_plugins():
            if plug.__plugin__ in self.config["plugins"]:
                yield plug()

    def run(self):
        self.result.start_scan()
        for plug in self.next_plugin():
            plug.init_scan(self.config)
            self.result.add_plugin(plug.__plugin__, plug.run(self.result))
        self.result.stop_scan()
        return self.result

from natlas.scan_result import ScanResult


class NatlasPlugin:

    __plugin__ = ""
    __author__ = ""
    __website__ = ""
    __description__ = ""
    __requires__ = []

    def __init__(self):
        pass

    def __str__(self):
        return f"<Plugin {self.__plugin__}>"

    def init_scan(self, plugin_config: dict):
        raise NotImplementedError

    def run(self, result: ScanResult):
        raise NotImplementedError

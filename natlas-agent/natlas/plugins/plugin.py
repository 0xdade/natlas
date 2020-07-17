from natlas.scan_result import ScanResult


class NatlasPlugin:

    __plugin__ = ""
    __author__ = ""
    __website__ = ""
    __description__ = ""
    __requires__ = []

    def __init__(self, plugin_config):
        raise NotImplementedError

    def run(self, result: ScanResult):
        raise NotImplementedError

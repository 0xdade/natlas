from natlas.plugins.plugin import NatlasPlugin


class WebScreenshot(NatlasPlugin):

    __plugin__ = "web_screenshot"
    __author__ = "Natlas Core Team"
    __website__ = "https://github.com/natlas/natlas"
    __description__ = "Enables web screenshots based on identified open http ports"
    __requires__ = ["nmap"]

    def __init__(self, config=None):
        print(f"{self.__name__} Loaded")
        self.config = config
        self.command = self.build_command()
        self.run()

    def build_command(self):
        raise NotImplementedError

    def run(self):
        raise NotImplementedError

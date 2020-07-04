from natlas.plugins.plugin import NatlasPlugin


class Masscan(NatlasPlugin):

    __plugin__ = "masscan"
    __author__ = "Natlas Core Team"
    __website__ = "https://github.com/natlas/natlas"
    __description__ = "Enables a quick scan of all ports"
    __requires__ = []

    def __init__(self, config=None):
        print(f"{self.__name__} Loaded")
        self.config = config
        self.command = self.build_command()
        self.run()

    def build_command(self):
        raise NotImplementedError

    def run(self):
        raise NotImplementedError

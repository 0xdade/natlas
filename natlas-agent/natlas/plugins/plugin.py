class NatlasPlugin:

    __plugin__ = ""
    __author__ = ""
    __website__ = ""
    __description__ = ""
    __requires__ = []

    def activate(self):
        raise NotImplementedError

    def deactivate(self):
        raise NotImplementedError

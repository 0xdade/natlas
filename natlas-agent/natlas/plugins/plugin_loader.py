import os
import pkgutil
from importlib import import_module
from functools import reduce
from natlas.plugins.plugin import NatlasPlugin


class PluginLoader:
    def __init__(self, additional_plugins=None):
        this_dir = os.path.dirname(__file__)
        core_plugins_dir = os.path.join(this_dir, "core")
        self.loaded_modules = []
        self.available_plugins = []
        self.dependency_graph = {}
        for pkg in pkgutil.iter_modules([core_plugins_dir]):
            imported = import_module("." + pkg.name, package="natlas.plugins.core")
            self.loaded_modules.append(imported)
        for plugin in NatlasPlugin.__subclasses__():
            self.available_plugins.append(plugin.__plugin__)
            self.dependency_graph[plugin.__plugin__] = set(plugin.__requires__)
        self.dependency_graph = PluginLoader.toposort2(self.dependency_graph)
        print("Execution order:\n" + "\n".join(self.dependency_graph))

    def toposort2(data):
        """
            Topological sort a graph
            https://www.rosettacode.org/wiki/Topological_sort#Python
        """
        for k, v in data.items():
            v.discard(k)  # Ignore self dependencies
        extra_items_in_deps = reduce(set.union, data.values()) - set(data.keys())
        data.update({item: set() for item in extra_items_in_deps})
        while True:
            ordered = {item for item, dep in data.items() if not dep}
            if not ordered:
                break
            yield " ".join(sorted(ordered))
            data = {
                item: (dep - ordered)
                for item, dep in data.items()
                if item not in ordered
            }
        assert not data, "A cyclic dependency exists amongst %r" % data

import os
import pkgutil
from importlib import import_module
from functools import reduce
from typing import Generator
from natlas.plugins.plugin import NatlasPlugin
from natlas import logging


class PluginLoader:
    def __init__(self, scan_config: dict):
        this_dir = os.path.dirname(__file__)
        plugins = [os.path.join(this_dir, "core")]
        self.config = scan_config
        self.loaded_modules = []
        self.available_plugins = {}
        self.dependency_graph = {}
        self.execution_order = []
        self.logger = logging.get_logger("PluginLoader")
        for pkg in pkgutil.iter_modules(plugins):
            imported = import_module("." + pkg.name, package="natlas.plugins.core")
            self.loaded_modules.append(imported)
        for plugin in NatlasPlugin.__subclasses__():
            if plugin.__plugin__ in self.config["plugins"]:
                self.available_plugins[plugin.__plugin__] = plugin
                self.dependency_graph[plugin.__plugin__] = set(plugin.__requires__)
        deps = [i for i in PluginLoader.sort_graph(self.dependency_graph)]
        for d in deps:
            d = d.split()
            self.execution_order.extend(d)
        self.logger.info(f'Execution order: {" -> ".join(self.execution_order)}')

    def next_plugin(self) -> Generator:
        for plug in self.execution_order:
            yield self.available_plugins[plug](self.config)

    def sort_graph(data: dict) -> Generator:
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

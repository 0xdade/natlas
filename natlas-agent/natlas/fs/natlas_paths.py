import os
from pathlib import Path

from config import Config

conf = Config()
common_dirs = {"data": os.path.abspath(conf.data_dir)}
common_dirs["conf"] = os.path.join(common_dirs["data"], "conf")
common_dirs["logs"] = os.path.join(common_dirs["data"], "logs")
common_dirs["scans"] = os.path.join(common_dirs["data"], "scans")
common_dirs["fails"] = os.path.join(common_dirs["scans"], "failures")

plugin_dirs = {}


def initialize_paths():
    for _, dirname in common_dirs.items():
        Path(dirname).mkdir(parents=True, exist_ok=True)


def get_scan_dir(scan_id: str):
    """
        All data related to a specific scan goes into this directory
    """
    path = os.path.join(common_dirs["scans"], f"natlas.{scan_id}")
    Path(path).mkdir(parents=True, exist_ok=True)
    return path


def get_conf_plugin_dir(plugin_name: str):
    """
        Plugin configuration data that persists between scans goes into this directory
    """
    if plugin_name in plugin_dirs:
        return plugin_dirs[plugin_name]

    plugin_dir = os.path.join(common_dirs["conf"], plugin_name)
    Path(plugin_dir).mkdir(parents=True, exist_ok=True)
    plugin_dirs[plugin_name] = plugin_dir
    return plugin_dirs[plugin_name]


def get_scan_plugin_dir(scan_id: str, plugin_name: str):
    """
        Plugin output data belonging to a scan goes into this directory
    """
    path = os.path.join(get_scan_dir(scan_id), plugin_name)
    Path(path).mkdir(parents=True, exist_ok=True)
    return path

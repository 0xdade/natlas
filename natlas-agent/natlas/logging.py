import logging
import time
import sys
import os
from logging.handlers import RotatingFileHandler
from config import Config

FORMATTER = logging.Formatter("%(asctime)s — %(name)s — %(levelname)s — %(message)s")
logging.Formatter.converter = time.gmtime  # Always log in GMT
conf = Config()


def get_console_handler():
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(FORMATTER)
    return console_handler


def get_file_handler():
    from natlas.fs import natlas_paths

    log_dir = natlas_paths.common_dirs["logs"]
    log_file = os.path.join(log_dir, "agent.log")
    file_handler = RotatingFileHandler(log_file, maxBytes=1024 * 1024, backupCount=5)
    file_handler.setFormatter(FORMATTER)
    return file_handler


def get_logger(name):
    logger = logging.getLogger(name)
    warn_log_level = False
    if conf.log_level not in ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG"]:
        warn_log_level = conf.log_level
        conf.log_level = "INFO"
    logger.setLevel(getattr(logging, conf.log_level))
    logger.addHandler(get_console_handler())
    if conf.log_to_file:
        logger.addHandler(get_file_handler())
    logger.propagate = False
    if warn_log_level:
        logger.warn(f"Invalid Log Level '{warn_log_level}' - falling back to 'INFO'")
    return logger


def get_plugin_logger(name):
    return get_logger(f"Plugin::{name}")

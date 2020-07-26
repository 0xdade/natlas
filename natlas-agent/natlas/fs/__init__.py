from natlas import logging

logger = logging.get_logger("Filesystem")

from . import natlas_paths, cleanup

__all__ = ["natlas_paths", "cleanup"]

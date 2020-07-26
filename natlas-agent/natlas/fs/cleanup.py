import os
import shutil

from natlas.fs import logger
from . import natlas_paths


def cleanup_files(scan_id, failed=False, saveFails=False):
    logger.info(f"Cleaning up files for {scan_id}")
    if saveFails and failed:
        __save_files(scan_id)
    else:
        __delete_files(scan_id)


def __delete_files(scan_id):
    scan_dir = natlas_paths.get_scan_dir(scan_id)
    if os.path.isdir(scan_dir):
        shutil.rmtree(scan_dir)


def __save_files(scan_id):
    failroot = natlas_paths.common_dirs["fails"]
    scan_dir = natlas_paths.get_scan_dir(scan_id)
    if os.path.isdir(scan_dir):
        src = scan_dir
        dst = failroot
        shutil.move(src, dst)

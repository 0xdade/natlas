from __future__ import annotations

import logging
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)


@dataclass
class ScanOutput:
    nmap: str  # standard text output (.nmap)
    xml: str  # XML output (.xml)
    gnmap: str  # grepable output (.gnmap)


def run(target: str, scan_id: uuid.UUID) -> ScanOutput:
    """Run nmap against target and return all three output formats.

    Uses a temporary directory so output files are cleaned up automatically.
    Raises subprocess.CalledProcessError if nmap exits non-zero.
    """
    cmd = [
        "nmap",
        "-sV",  # service/version detection
        "-sC",  # default NSE scripts
        "-T4",  # aggressive timing
        "-oA",
        "",  # placeholder; filled in below once tmpdir is known
        target,
    ]

    with tempfile.TemporaryDirectory() as tmpdir:
        base = str(Path(tmpdir) / f"scan_{scan_id}")
        cmd[-2] = base

        log.debug("Running: %s", " ".join(cmd))
        started = time.monotonic()

        result = subprocess.run(cmd, capture_output=True, text=True, check=False)

        elapsed = time.monotonic() - started
        log.debug("nmap stdout:\n%s", result.stdout.strip())

        if result.stderr.strip():
            log.debug("nmap stderr:\n%s", result.stderr.strip())

        if result.returncode != 0:
            log.warning(
                "nmap exited %d for %s after %.1fs",
                result.returncode,
                target,
                elapsed,
            )
            if result.stderr.strip():
                log.warning("nmap stderr:\n%s", result.stderr.strip())
            result.check_returncode()

        nmap_path = Path(f"{base}.nmap")
        xml_path = Path(f"{base}.xml")
        gnmap_path = Path(f"{base}.gnmap")

        log.debug(
            "Output file sizes — .nmap: %d bytes, .xml: %d bytes, .gnmap: %d bytes",
            nmap_path.stat().st_size,
            xml_path.stat().st_size,
            gnmap_path.stat().st_size,
        )

        nmap = nmap_path.read_text()
        xml = xml_path.read_text()
        gnmap = gnmap_path.read_text()

    log.info("Scan of %s completed in %.1fs", target, elapsed)
    return ScanOutput(nmap=nmap, xml=xml, gnmap=gnmap)

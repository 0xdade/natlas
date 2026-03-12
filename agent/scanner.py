from __future__ import annotations

import logging
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from agent import config

log = logging.getLogger(__name__)


@dataclass
class ScanOutput:
    nmap: str  # standard text output (.nmap)
    xml: str  # XML output (.xml)
    gnmap: str  # grepable output (.gnmap)


def _masscan(target: str, tmpdir: str) -> list[tuple[str, str]]:
    """Run masscan against all ports and return (protocol, port) pairs.

    masscan list output format (lines starting with '#' are comments):
        open tcp 443 93.184.216.34 1741234567
        open tcp 80  93.184.216.34 1741234568
    """
    out_path = Path(tmpdir) / "masscan.txt"
    cmd = [
        "masscan",
        target,
        "-p",
        "0-65535",
        "--rate",
        "500",  # packets per second; conservative for internet hosts
        "--wait",
        "5",  # seconds to wait for last replies after scan completes
        "-oL",
        str(out_path),
    ]

    log.debug("Running masscan: %s", " ".join(cmd))
    started = time.monotonic()
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    elapsed = time.monotonic() - started

    if result.stderr.strip():
        log.debug("masscan stderr:\n%s", result.stderr.strip())

    if result.returncode != 0:
        log.warning(
            "masscan exited %d for %s after %.1fs", result.returncode, target, elapsed
        )
        if result.stderr.strip():
            log.warning("masscan stderr:\n%s", result.stderr.strip())
        result.check_returncode()

    ports: list[tuple[str, str]] = []
    for line in out_path.read_text().splitlines():
        if line.startswith("#") or not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "open":
            ports.append((parts[1], parts[2]))  # (protocol, port)

    log.info(
        "masscan found %d open port(s) on %s in %.1fs",
        len(ports),
        target,
        elapsed,
    )
    return ports


def _build_port_spec(ports: list[tuple[str, str]]) -> str:
    """Convert (protocol, port) pairs to an nmap -p argument string.

    e.g. [('tcp','80'),('tcp','443'),('udp','53')] -> 'T:80,T:443,U:53'
    """
    tcp = sorted({port for proto, port in ports if proto == "tcp"}, key=int)
    udp = sorted({port for proto, port in ports if proto == "udp"}, key=int)
    parts: list[str] = []
    if tcp:
        parts.append("T:" + ",".join(tcp))
    if udp:
        parts.append("U:" + ",".join(udp))
    return ",".join(parts)


def _nmap(target: str, base: str, extra_args: list[str] | None = None) -> ScanOutput:
    """Run nmap and return all three output formats."""
    cmd = [
        "nmap",
        *(extra_args or []),
        "-sV",  # service/version detection
        "-sC",  # default NSE scripts
        "-d" if config.NATLAS_DEBUG else "",  # debug output (includes full command)
        "-oA",
        base,
        target,
    ]

    log.debug("Running nmap: %s", " ".join(cmd))
    started = time.monotonic()
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    elapsed = time.monotonic() - started

    log.debug("nmap stdout:\n%s", result.stdout.strip())
    if result.stderr.strip():
        log.debug("nmap stderr:\n%s", result.stderr.strip())

    if result.returncode != 0:
        log.warning(
            "nmap exited %d for %s after %.1fs", result.returncode, target, elapsed
        )
        if result.stderr.strip():
            log.warning("nmap stderr:\n%s", result.stderr.strip())
        result.check_returncode()

    nmap_path = Path(f"{base}.nmap")
    xml_path = Path(f"{base}.xml")
    gnmap_path = Path(f"{base}.gnmap")

    log.debug(
        "Output sizes — .nmap: %d bytes, .xml: %d bytes, .gnmap: %d bytes",
        nmap_path.stat().st_size,
        xml_path.stat().st_size,
        gnmap_path.stat().st_size,
    )

    log.info("nmap fingerprint of %s completed in %.1fs", target, elapsed)
    return ScanOutput(
        nmap=nmap_path.read_text(),
        xml=xml_path.read_text(),
        gnmap=gnmap_path.read_text(),
    )


def run(target: str, scan_id: uuid.UUID) -> ScanOutput:
    """Scan a target and return nmap output in all three formats.

    When NATLAS_USE_MASSCAN=1: masscan performs fast SYN discovery across all
    65535 ports first, then nmap fingerprints only the confirmed open ports.
    If masscan finds nothing, an empty ScanOutput is returned without running nmap.

    Otherwise: nmap handles the full scan directly (default).
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        base = str(Path(tmpdir) / f"scan_{scan_id}")

        if config.USE_MASSCAN:
            log.info("Using masscan pre-flight for %s", target)
            discovered = _masscan(target, tmpdir)
            if not discovered:
                return ScanOutput(nmap="", xml="", gnmap="")
            port_spec = _build_port_spec(discovered)
            return _nmap(target, base, extra_args=["-Pn", "-p", port_spec])

        return _nmap(target, base)

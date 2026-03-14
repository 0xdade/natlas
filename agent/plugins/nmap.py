from __future__ import annotations

import logging
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from agent import config
from agent.context import ScanContext
from agent.plugins import Plugin

log = logging.getLogger(__name__)


def _count_open_ports(xml: str) -> int:
    try:
        root = ET.fromstring(xml)
        return sum(
            1
            for port in root.findall("host/ports/port")
            if (s := port.find("state")) is not None and s.get("state") == "open"
        )
    except ET.ParseError:
        return -1


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


class NmapPlugin(Plugin):
    name = "nmap"
    depends_on = ["masscan"]

    def run(self, ctx: ScanContext) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            base = str(Path(tmpdir) / f"scan_{ctx.scan_id}")

            extra_args: list[str] = []
            if ctx.masscan.discovered_ports:
                extra_args = [
                    "-Pn",
                    "-p",
                    _build_port_spec(ctx.masscan.discovered_ports),
                ]

            cmd = [
                "nmap",
                *extra_args,
                "-sV",
                "-sC",
                *(["-d"] if config.DEBUG else []),
                "-oA",
                base,
                ctx.target,
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
                    "nmap exited %d for %s after %.1fs",
                    result.returncode,
                    ctx.target,
                    elapsed,
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

            ctx.nmap.text = nmap_path.read_text()
            ctx.nmap.xml = xml_path.read_text()
            ctx.nmap.gnmap = gnmap_path.read_text()
            ctx.nmap.open_port_count = _count_open_ports(ctx.nmap.xml)

            log.info(
                "nmap fingerprint of %s completed in %.1fs (%d open port(s))",
                ctx.target,
                elapsed,
                ctx.nmap.open_port_count,
            )

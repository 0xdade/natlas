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


def _port_args(config_ports: str, discovered: list[tuple[str, str]]) -> list[str]:
    """Return the nmap port-selection arguments.

    Masscan-discovered ports take priority.  Otherwise the config value is used:
    'top-N' maps to --top-ports N; anything else is passed verbatim as -p <spec>.
    """
    if discovered:
        return ["-Pn", "-p", _build_port_spec(discovered)]
    if config_ports.startswith("top-"):
        return ["--top-ports", config_ports[4:]]
    return ["-p", config_ports]


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

            nmap_cfg = ctx.nmap_config
            port_args = _port_args(nmap_cfg.ports, ctx.masscan.discovered_ports)

            hostnames = [
                d.name for d in ctx.dns_names if d.record_type in ("A", "AAAA")
            ]

            # Build the --script argument: natlas scripts (when hostnames present)
            # combined with any scripts requested by the scan config.
            script_names: list[str] = list(nmap_cfg.scripts)
            script_args: list[str] = []
            if hostnames:
                script_names = ["natlas-ssl-cert", "natlas-http-title", *script_names]
                script_args = [
                    "--script-args",
                    "natlas.hostnames=" + "|".join(hostnames),
                ]

            timing_args = [f"-T{nmap_cfg.timing_template}"]
            rate_args = (
                ["--max-rate", str(nmap_cfg.max_rate)] if nmap_cfg.max_rate else []
            )
            script_flag = ["--script", ",".join(script_names)] if script_names else []

            cmd = [
                "nmap",
                *port_args,
                *timing_args,
                *rate_args,
                *script_flag,
                *script_args,
                "-sV",
                "-sT",
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

from __future__ import annotations

import dataclasses
import json
import logging
import shutil
import subprocess
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from agent.context import ScanContext, WhatWebResult
from agent.plugins import Plugin

log = logging.getLogger(__name__)


def _web_urls(ctx: ScanContext) -> list[str]:
    """Build the list of URLs WhatWeb should probe.

    HTTP and HTTPS ports are identified from the nmap XML service data.
    Each port is scanned once by IP, then once per A/AAAA DNS name so that
    virtual-hosting / SNI differences are covered.
    """
    if not ctx.nmap.xml:
        return []

    try:
        root = ET.fromstring(ctx.nmap.xml)
    except ET.ParseError:
        return []

    http_ports: list[str] = []
    https_ports: list[str] = []

    for host in root.findall("host"):
        for port_elem in host.findall("ports/port"):
            state = port_elem.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port_elem.find("service")
            if svc is None:
                continue
            portid = port_elem.get("portid", "")
            name = svc.get("name", "").lower()
            tunnel = svc.get("tunnel", "").lower()

            if tunnel == "ssl" or name in ("https", "https-alt"):
                https_ports.append(portid)
            elif name.startswith("http"):
                http_ports.append(portid)

    if not http_ports and not https_ports:
        return []

    # Scan by raw IP first, then by each DNS hostname (sends correct Host header
    # for virtual-hosting detection without depending on external DNS resolution).
    targets = [ctx.target] + [
        d.name for d in ctx.dns_names if d.record_type in ("A", "AAAA")
    ]

    urls: list[str] = []
    for target in targets:
        for port in http_ports:
            urls.append(f"http://{target}:{port}/")
        for port in https_ports:
            urls.append(f"https://{target}:{port}/")
    return urls


class WhatWebPlugin(Plugin):
    name = "whatweb"
    depends_on = ["nmap"]

    def enabled(self) -> bool:
        return shutil.which("whatweb") is not None

    def run(self, ctx: ScanContext) -> None:
        urls = _web_urls(ctx)
        if not urls:
            log.debug("No web services found for %s, skipping WhatWeb", ctx.target)
            return

        with tempfile.TemporaryDirectory() as tmpdir:
            out_file = Path(tmpdir) / "whatweb.json"

            ww_cfg = ctx.whatweb_config
            cmd = [
                "whatweb",
                f"--log-json={out_file}",
                "--no-errors",
                f"--aggression={ww_cfg.aggression}",
                f"--read-timeout={ww_cfg.timeout}",
                *urls,
            ]

            log.debug("Running WhatWeb: %s", " ".join(cmd))
            started = time.monotonic()
            result = subprocess.run(cmd, capture_output=True, text=True, check=False)
            elapsed = time.monotonic() - started

            if result.returncode != 0:
                log.warning(
                    "WhatWeb exited %d for %s after %.1fs",
                    result.returncode,
                    ctx.target,
                    elapsed,
                )

            if not out_file.exists():
                log.debug("WhatWeb produced no output for %s", ctx.target)
                return

            for _line in out_file.read_text().splitlines():
                line = _line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    log.debug("WhatWeb: skipping unparseable line: %.80s", line)
                    continue
                ctx.whatweb.results.append(
                    WhatWebResult(
                        url=entry.get("target", ""),
                        http_status=entry.get("http_status", 0),
                        plugins=entry.get("plugins", {}),
                    )
                )

            log.info(
                "WhatWeb scan of %s completed in %.1fs (%d result(s))",
                ctx.target,
                elapsed,
                len(ctx.whatweb.results),
            )


def serialize(ctx: ScanContext) -> str:
    """Serialise WhatWeb results to a JSON string for submission."""
    return json.dumps([dataclasses.asdict(r) for r in ctx.whatweb.results])

from __future__ import annotations

import logging
import subprocess
import tempfile
import time
from pathlib import Path

from agent import config
from agent.plugins import Plugin, ScanContext

log = logging.getLogger(__name__)


class MasscanPlugin(Plugin):
    name = "masscan"

    def enabled(self) -> bool:
        return config.USE_MASSCAN

    def run(self, ctx: ScanContext) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            out_path = Path(tmpdir) / "masscan.txt"
            cmd = [
                "masscan",
                ctx.target,
                "-p",
                "0-65535",
                "--rate",
                "500",
                "--wait",
                "5",
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
                    "masscan exited %d for %s after %.1fs",
                    result.returncode,
                    ctx.target,
                    elapsed,
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
                    ports.append((parts[1], parts[2]))

            log.info(
                "masscan found %d open port(s) on %s in %.1fs",
                len(ports),
                ctx.target,
                elapsed,
            )

            if not ports:
                log.info(
                    "masscan found no open ports on %s — aborting pipeline",
                    ctx.target,
                )
                ctx.abort = True
                return

            ctx.masscan.discovered_ports = ports

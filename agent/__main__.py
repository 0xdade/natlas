from __future__ import annotations

import logging
import time
import uuid
from datetime import datetime, timezone

from agent import config
from agent.client import ServerClient
from agent.context import DNSName, NmapConfig, ScanContext, WhatWebConfig
from agent.runner import run as scan

logging.basicConfig(
    level=logging.DEBUG if config.DEBUG else logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
log = logging.getLogger(__name__)


def main() -> None:
    if not config.AGENT_TOKEN:
        log.error("NATLAS_AGENT_TOKEN is not set — cannot authenticate with server")
        raise SystemExit(1)

    log.info("Agent starting, server: %s", config.SERVER_ADDRESS)

    with ServerClient() as client:
        while True:
            try:
                task = client.claim()
            except Exception:
                log.exception(
                    "Failed to claim task, retrying in %ss", config.POLL_INTERVAL
                )
                time.sleep(config.POLL_INTERVAL)
                continue

            if task is None:
                log.debug("No work available, sleeping %ss", config.POLL_INTERVAL)
                time.sleep(config.POLL_INTERVAL)
                continue

            raw_nmap_cfg = task.get("nmap_config") or {}
            raw_ww_cfg = task.get("whatweb_config") or {}

            ctx = ScanContext(
                target=task["target"],
                scan_id=uuid.UUID(task["scan_id"]),
                task_id=uuid.UUID(task["task_id"]),
                dns_names=[DNSName(**d) for d in task.get("dns_names", [])],
                enabled_plugins=task.get("enabled_plugins", []),
                nmap_config=NmapConfig(
                    ports=raw_nmap_cfg.get("ports", "top-100"),
                    timing_template=raw_nmap_cfg.get("timing_template", 4),
                    max_rate=raw_nmap_cfg.get("max_rate"),
                    scripts=raw_nmap_cfg.get("scripts", []),
                ),
                whatweb_config=WhatWebConfig(
                    aggression=raw_ww_cfg.get("aggression", 1),
                    timeout=raw_ww_cfg.get("timeout", 30),
                ),
                scan_start=datetime.now(timezone.utc),
            )

            log.info("Claimed task %s: scanning %s", ctx.task_id, ctx.target)

            try:
                ctx = scan(ctx)
            except Exception:
                log.exception("Scan failed for %s (task %s)", ctx.target, ctx.task_id)
                try:
                    client.fail(ctx.task_id)
                except Exception:
                    log.exception("Failed to report task %s as failed", ctx.task_id)
                continue

            log.info(
                "Scan complete for %s (task %s): %d open port(s)",
                ctx.target,
                ctx.task_id,
                ctx.nmap.open_port_count,
            )

            try:
                client.submit(ctx)
                log.info("Submitted results for %s (task %s)", ctx.target, ctx.task_id)
            except Exception:
                log.exception("Failed to submit results for task %s", ctx.task_id)


if __name__ == "__main__":
    main()

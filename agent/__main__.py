from __future__ import annotations

import logging
import time
from datetime import datetime, timezone

from natlas_protocol.agents import ClaimResponse

from agent import config
from agent.client import ServerClient
from agent.context import ScanContext
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

            claim = ClaimResponse.model_validate(task)
            ctx = ScanContext(
                target=claim.target,
                scan_id=claim.scan_id,
                task_id=claim.task_id,
                dns_names=claim.dns_names,
                enabled_plugins=claim.enabled_plugins,
                masscan_config=claim.masscan_config,
                nmap_config=claim.nmap_config,
                whatweb_config=claim.whatweb_config,
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

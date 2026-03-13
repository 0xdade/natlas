from __future__ import annotations

import logging
import time
import uuid

from agent import config
from agent.client import ServerClient
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

            task_id: int = task["task_id"]
            scan_id: uuid.UUID = uuid.UUID(task["scan_id"])
            target: str = task["target"]

            log.info("Claimed task %s: scanning %s", task_id, target)

            try:
                ctx = scan(target, scan_id, task_id)
            except Exception:
                log.exception("Scan failed for %s (task %s)", target, task_id)
                try:
                    client.fail(task_id)
                except Exception:
                    log.exception("Failed to report task %s as failed", task_id)
                continue

            log.info(
                "Scan complete for %s (task %s): %d open port(s)",
                target,
                task_id,
                ctx.nmap.open_port_count,
            )

            try:
                client.submit(ctx)
                log.info("Submitted results for %s (task %s)", target, task_id)
            except Exception:
                log.exception("Failed to submit results for task %s", task_id)


if __name__ == "__main__":
    main()

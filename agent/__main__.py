from __future__ import annotations

import logging
import os
import time
import uuid
import xml.etree.ElementTree as ET

from agent import config
from agent.client import ServerClient
from agent.scanner import run as scan

log_level = logging.DEBUG if os.environ.get("NATLAS_DEBUG") == "1" else logging.INFO
logging.basicConfig(
    level=log_level,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
log = logging.getLogger(__name__)


def _count_open_ports(raw_xml: str) -> int:
    try:
        root = ET.fromstring(raw_xml)
        return sum(
            1
            for port in root.findall("host/ports/port")
            if (s := port.find("state")) is not None and s.get("state") == "open"
        )
    except ET.ParseError:
        return -1


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
                output = scan(target, scan_id)
            except Exception:
                log.exception("Scan failed for %s (task %s)", target, task_id)
                try:
                    client.fail(task_id=task_id)
                except Exception:
                    log.exception("Failed to report task %s as failed", task_id)
                continue

            port_count = _count_open_ports(output.xml)
            log.info(
                "Scan complete for %s (task %s): %d open port(s)",
                target,
                task_id,
                port_count,
            )

            try:
                client.submit(
                    task_id=task_id,
                    scan_id=scan_id,
                    data={"ip": target, "is_up": True, "port_count": port_count},
                    raw_nmap=output.nmap,
                    raw_xml=output.xml,
                    raw_gnmap=output.gnmap,
                )
                log.info("Submitted results for %s (task %s)", target, task_id)
            except Exception:
                log.exception("Failed to submit results for task %s", task_id)


if __name__ == "__main__":
    main()

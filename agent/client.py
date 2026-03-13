from __future__ import annotations

import httpx

from agent import config
from agent.plugins import ScanContext


class ServerClient:
    """HTTP client for the natlas server agent API."""

    def __init__(self) -> None:
        self._http = httpx.Client(
            base_url=config.SERVER_ADDRESS,
            headers={"Authorization": f"Bearer {config.AGENT_TOKEN}"},
            timeout=30,
        )

    def claim(self) -> dict | None:
        """Claim the next pending scan task.

        Returns the task dict on success, or None when the queue is empty.
        """
        resp = self._http.post("/api/agents/claim/")
        if resp.status_code == 204:
            return None
        resp.raise_for_status()
        return resp.json()

    def submit(self, ctx: ScanContext) -> None:
        """Submit scan results for a claimed task."""
        resp = self._http.post(
            "/api/agents/submit/",
            json={
                "task_id": ctx.task_id,
                "scan_id": str(ctx.scan_id),
                "raw_nmap": ctx.nmap.text,
                "raw_xml": ctx.nmap.xml,
                "raw_gnmap": ctx.nmap.gnmap,
                "scan_start": ctx.scan_start.isoformat(),
                "scan_stop": ctx.scan_stop.isoformat(),
            },
        )
        resp.raise_for_status()

    def fail(self, task_id: int) -> None:
        """Mark a claimed task as failed."""
        resp = self._http.post("/api/agents/fail/", json={"task_id": task_id})
        resp.raise_for_status()

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> ServerClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

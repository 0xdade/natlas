from __future__ import annotations

import uuid

import httpx

from agent import config


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

    def submit(  # noqa: PLR0913 (we'll come back to this)
        self,
        *,
        task_id: int,
        scan_id: uuid.UUID,
        data: dict,
        raw_nmap: str,
        raw_xml: str,
        raw_gnmap: str,
    ) -> None:
        """Submit scan results for a claimed task."""
        resp = self._http.post(
            "/api/agents/submit/",
            json={
                "task_id": task_id,
                "scan_id": str(scan_id),
                "data": data,
                "raw_nmap": raw_nmap,
                "raw_xml": raw_xml,
                "raw_gnmap": raw_gnmap,
            },
        )
        resp.raise_for_status()

    def fail(self, *, task_id: int) -> None:
        """Mark a claimed task as failed."""
        resp = self._http.post("/api/agents/fail/", json={"task_id": task_id})
        resp.raise_for_status()

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> ServerClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

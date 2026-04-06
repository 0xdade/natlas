from __future__ import annotations

import uuid

import httpx
from natlas_protocol.agents import FailTask, SubmitResult

from agent import config
from agent.context import ScanContext
from agent.plugins.whatweb import serialize as serialize_whatweb


class ServerClient:
    """HTTP client for the natlas server agent API."""

    def __init__(self) -> None:
        self._http = httpx.Client(
            base_url=config.SERVER_ADDRESS,
            headers={"Authorization": f"Bearer {config.AGENT_TOKEN}"},
            timeout=30,
        )

    def claim(self) -> dict | None:  # type: ignore[type-arg]
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
        payload = SubmitResult(
            task_id=ctx.task_id,
            scan_id=ctx.scan_id,
            raw_nmap=ctx.nmap.text,
            raw_xml=ctx.nmap.xml,
            raw_gnmap=ctx.nmap.gnmap,
            raw_whatweb=serialize_whatweb(ctx),
            scan_start=ctx.scan_start,
            scan_stop=ctx.scan_stop,
        )
        resp = self._http.post(
            "/api/agents/submit/",
            json=payload.model_dump(mode="json"),
        )
        resp.raise_for_status()

    def fail(self, task_id: uuid.UUID) -> None:
        """Mark a claimed task as failed."""
        resp = self._http.post(
            "/api/agents/fail/",
            json=FailTask(task_id=task_id).model_dump(mode="json"),
        )
        resp.raise_for_status()

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> ServerClient:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()

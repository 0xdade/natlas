from __future__ import annotations

import uuid
from typing import Any

from ninja import Schema


class ClaimResponseSchema(Schema):
    """Returned when an agent successfully claims a task."""

    task_id: int
    scan_id: uuid.UUID
    target: str


class SubmitResultSchema(Schema):
    """Body for a scan result submission."""

    task_id: int
    scan_id: uuid.UUID
    data: dict[str, Any]
    raw_nmap: str = ""
    raw_xml: str = ""
    raw_gnmap: str = ""


class SubmitAckSchema(Schema):
    scan_id: uuid.UUID


class FailTaskSchema(Schema):
    task_id: int

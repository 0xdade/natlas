from __future__ import annotations

import uuid
from datetime import datetime

from ninja import Schema


class DNSNameSchema(Schema):
    name: str
    record_type: str
    value: str


class ClaimResponseSchema(Schema):
    """Returned when an agent successfully claims a task."""

    task_id: uuid.UUID
    scan_id: uuid.UUID
    target: str
    dns_names: list[DNSNameSchema]
    enabled_plugins: list[str]


class SubmitResultSchema(Schema):
    """Body for a scan result submission."""

    task_id: uuid.UUID
    scan_id: uuid.UUID
    raw_nmap: str = ""
    raw_xml: str = ""
    raw_gnmap: str = ""
    raw_whatweb: str = ""
    scan_start: datetime
    scan_stop: datetime


class SubmitAckSchema(Schema):
    scan_id: uuid.UUID


class FailTaskSchema(Schema):
    task_id: uuid.UUID

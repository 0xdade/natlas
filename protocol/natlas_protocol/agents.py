from __future__ import annotations

import uuid
from datetime import datetime

from pydantic import BaseModel

from natlas_protocol.scan_config import (
    MasscanConfig,
    NmapConfig,
    NucleiConfig,
    ScreenshotConfig,
    WhatWebConfig,
)


class DNSName(BaseModel):
    name: str
    record_type: str
    value: str


class ClaimResponse(BaseModel):
    """Returned by the server when an agent successfully claims a task."""

    task_id: uuid.UUID
    scan_id: uuid.UUID
    target: str
    dns_names: list[DNSName]
    enabled_plugins: list[str]
    masscan_config: MasscanConfig
    nmap_config: NmapConfig
    nuclei_config: NucleiConfig
    screenshot_config: ScreenshotConfig
    whatweb_config: WhatWebConfig


class SubmitResult(BaseModel):
    """Body sent by the agent when submitting scan results."""

    task_id: uuid.UUID
    scan_id: uuid.UUID
    raw_nmap: str = ""
    raw_xml: str = ""
    raw_gnmap: str = ""
    raw_whatweb: str = ""
    scan_start: datetime
    scan_stop: datetime


class SubmitAck(BaseModel):
    scan_id: uuid.UUID


class FailTask(BaseModel):
    task_id: uuid.UUID

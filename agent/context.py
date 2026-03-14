from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class DNSName:
    name: str
    record_type: str
    value: str


@dataclass
class MasscanContext:
    discovered_ports: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class NmapContext:
    text: str = ""
    xml: str = ""
    gnmap: str = ""
    open_port_count: int = 0


@dataclass
class ScanContext:
    """Shared state that flows through and accumulates across plugins."""

    target: str
    scan_id: uuid.UUID
    task_id: uuid.UUID
    dns_names: list[DNSName] = field(default_factory=list)
    scan_start: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    scan_stop: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Set to True by a plugin to abort the rest of the pipeline.
    abort: bool = False

    masscan: MasscanContext = field(default_factory=MasscanContext)
    nmap: NmapContext = field(default_factory=NmapContext)

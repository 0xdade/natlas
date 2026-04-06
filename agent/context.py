from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from natlas_protocol.agents import DNSName
from natlas_protocol.scan_config import MasscanConfig, NmapConfig, WhatWebConfig


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
class WhatWebResult:
    url: str
    http_status: int
    plugins: dict  # type: ignore[type-arg]  # plugin name → WhatWeb detection data


@dataclass
class WhatWebContext:
    results: list[WhatWebResult] = field(default_factory=list)


@dataclass
class ScanContext:
    """Shared state that flows through and accumulates across plugins."""

    target: str
    scan_id: uuid.UUID
    task_id: uuid.UUID
    dns_names: list[DNSName] = field(default_factory=list)
    enabled_plugins: list[str] = field(default_factory=list)
    masscan_config: MasscanConfig = field(default_factory=MasscanConfig)
    nmap_config: NmapConfig = field(default_factory=NmapConfig)
    whatweb_config: WhatWebConfig = field(default_factory=WhatWebConfig)
    scan_start: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    scan_stop: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Set to True by a plugin to abort the rest of the pipeline.
    abort: bool = False

    masscan: MasscanContext = field(default_factory=MasscanContext)
    nmap: NmapContext = field(default_factory=NmapContext)
    whatweb: WhatWebContext = field(default_factory=WhatWebContext)

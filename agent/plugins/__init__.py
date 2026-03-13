from __future__ import annotations

import typing
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone


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
    task_id: int
    scan_start: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    scan_stop: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Set to True by a plugin to abort the rest of the pipeline.
    abort: bool = False

    masscan: MasscanContext = field(default_factory=MasscanContext)
    nmap: NmapContext = field(default_factory=NmapContext)


class Plugin(ABC):
    """Base class for all scan pipeline plugins.

    Subclasses must define the ``name`` class variable and implement ``run()``.
    Override ``enabled()`` to gate the plugin on a config flag.
    Override ``depends_on`` to declare ordering constraints against other plugins.
    """

    name: typing.ClassVar[str]
    depends_on: typing.ClassVar[list[str]] = []

    def enabled(self) -> bool:
        """Return True if this plugin should be included in the pipeline."""
        return True

    @abstractmethod
    def run(self, ctx: ScanContext) -> None:
        """Execute the plugin, mutating ctx in place.

        Set ctx.abort = True to stop the pipeline after this plugin returns.
        """

from __future__ import annotations

import typing
from abc import ABC, abstractmethod

from agent.context import ScanContext


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

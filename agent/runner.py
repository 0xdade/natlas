from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone

from agent.plugins import Plugin, ScanContext
from agent.plugins.masscan import MasscanPlugin
from agent.plugins.nmap import NmapPlugin

log = logging.getLogger(__name__)


class PluginRunner:
    """Resolves enabled plugins into an ordered pipeline and executes them."""

    def __init__(self) -> None:
        self._plugins: list[Plugin] = [
            MasscanPlugin(),
            NmapPlugin(),
        ]

    def _enabled(self) -> list[Plugin]:
        return [p for p in self._plugins if p.enabled()]

    def _sorted(self, plugins: list[Plugin]) -> list[Plugin]:
        """Topological sort respecting depends_on, ignoring disabled plugins."""
        enabled_names = {p.name for p in plugins}
        by_name = {p.name: p for p in plugins}
        result: list[Plugin] = []
        visited: set[str] = set()

        def visit(name: str) -> None:
            if name in visited:
                return
            visited.add(name)
            for dep in by_name[name].depends_on:
                if dep in enabled_names:
                    visit(dep)
            result.append(by_name[name])

        for plugin in plugins:
            visit(plugin.name)

        return result

    def run(self, target: str, scan_id: uuid.UUID, task_id: int) -> ScanContext:
        ctx = ScanContext(
            target=target,
            scan_id=scan_id,
            task_id=task_id,
            scan_start=datetime.now(timezone.utc),
        )

        plugins = self._sorted(self._enabled())
        log.info(
            "Scan pipeline for %s: %s",
            target,
            " → ".join(p.name for p in plugins) if plugins else "(empty)",
        )

        for plugin in plugins:
            plugin.run(ctx)
            if ctx.abort:
                log.info("Pipeline aborted after plugin: %s", plugin.name)
                break

        ctx.scan_stop = datetime.now(timezone.utc)
        return ctx


def run(target: str, scan_id: uuid.UUID, task_id: int) -> ScanContext:
    return PluginRunner().run(target, scan_id, task_id)

from __future__ import annotations

import logging
from datetime import datetime, timezone

from agent.context import ScanContext
from agent.plugins import Plugin
from agent.plugins.masscan import MasscanPlugin
from agent.plugins.nmap import NmapPlugin
from agent.plugins.whatweb import WhatWebPlugin

log = logging.getLogger(__name__)


class PluginRunner:
    """Resolves enabled plugins into an ordered pipeline and executes them."""

    def __init__(self) -> None:
        self._plugins: list[Plugin] = [
            MasscanPlugin(),
            NmapPlugin(),
            WhatWebPlugin(),
        ]

    def _enabled(self, server_plugins: list[str]) -> list[Plugin]:
        return [p for p in self._plugins if p.name in server_plugins and p.enabled()]

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

    def run(self, ctx: ScanContext) -> ScanContext:
        plugins = self._sorted(self._enabled(ctx.enabled_plugins))
        log.info(
            "Scan pipeline for %s: %s",
            ctx.target,
            " → ".join(p.name for p in plugins) if plugins else "(empty)",
        )

        for plugin in plugins:
            plugin.run(ctx)
            if ctx.abort:
                log.info("Pipeline aborted after plugin: %s", plugin.name)
                break

        ctx.scan_stop = datetime.now(timezone.utc)
        return ctx


def run(ctx: ScanContext) -> ScanContext:
    return PluginRunner().run(ctx)

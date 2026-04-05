from __future__ import annotations

import typing

import uuid6
from django.contrib.postgres.fields import ArrayField
from django.contrib.postgres.indexes import GinIndex
from django.contrib.postgres.search import SearchVector
from django.db import models
from django.utils import timezone
from netfields import InetAddressField

from apps.natlas.models.agent import Agent


class ScanResult(models.Model):
    """Append-only scan history. One row per completed scan.

    Query by id for a direct fetch, or by (target, scanned_at) for
    the history of a specific host.
    """

    id = models.UUIDField(primary_key=True, default=uuid6.uuid7, editable=False)
    target = InetAddressField(store_prefix_length=False, db_index=True)
    agent = models.ForeignKey(
        Agent,
        on_delete=models.SET_NULL,
        null=True,
        related_name="scan_results",
    )
    scanned_at = models.DateTimeField(default=timezone.now, db_index=True)
    scan_start = models.DateTimeField(db_index=True)
    scan_stop = models.DateTimeField(db_index=True)
    raw_data = models.JSONField()

    raw_nmap = models.TextField(blank=True, default="")
    tags = ArrayField(models.CharField(max_length=128), default=list, blank=True)

    @property
    def port_count(self) -> int:
        # Use annotation (open_port_count) when available to avoid N+1 on list views.
        if (n := getattr(self, "open_port_count", None)) is not None:
            return n  # type: ignore[return-value]
        return self.ports.filter(state="open").count()  # type: ignore[attr-defined]

    @property
    def open_ports(self) -> list:
        # Filter from prefetch cache when available; falls back to a query.
        return sorted(
            [p for p in self.ports.all() if p.state == "open"],  # type: ignore[attr-defined]
            key=lambda p: p.port_number,
        )

    @property
    def is_up(self) -> bool:
        if (n := getattr(self, "open_port_count", None)) is not None:
            return n > 0  # type: ignore[operator]
        return self.ports.filter(state="open").exists()  # type: ignore[attr-defined]

    class Meta:
        indexes: typing.ClassVar = [
            models.Index(fields=["target", "scanned_at"]),
            GinIndex(
                SearchVector("raw_nmap", config="english"),
                name="scanresult_raw_nmap_fts_idx",
            ),
        ]

from __future__ import annotations

import typing

import uuid6
from django.contrib.postgres.indexes import GinIndex
from django.contrib.postgres.search import SearchVector
from django.db import models
from django.utils import timezone
from netfields import InetAddressField

from apps.natlas.models.agent import Agent


class ScanData(models.Model):
    """Shared fields between ScanResult and LatestScanResult.

    scan_id is the stable identifier for a single scan run. The same UUID
    appears in both tables, so a LatestScanResult can be traced directly
    to its ScanResult row in the history table.
    """

    scan_id = models.UUIDField(default=uuid6.uuid7)
    target = InetAddressField(store_prefix_length=False, db_index=True)
    agent = models.ForeignKey(
        Agent,
        on_delete=models.SET_NULL,
        null=True,
        related_name="%(class)s_set",
    )
    scanned_at = models.DateTimeField(default=timezone.now, db_index=True)
    scan_start = models.DateTimeField(null=True, db_index=True)
    scan_stop = models.DateTimeField(null=True, db_index=True)
    raw_data = models.JSONField()

    class Meta:
        abstract = True


class ScanResult(ScanData):
    """Append-only scan history. One row per completed scan.

    Query by scan_id for a direct fetch, or by (target, scanned_at) for
    the history of a specific host.
    """

    raw_nmap = models.TextField(blank=True, default="")

    class Meta:
        constraints: typing.ClassVar = [
            models.UniqueConstraint(
                fields=["scan_id"],
                name="unique_scan_result_scan_id",
            ),
        ]
        indexes: typing.ClassVar = [
            models.Index(fields=["target", "scanned_at"]),
            GinIndex(
                SearchVector("raw_nmap", config="english"),
                name="scanresult_raw_nmap_fts_idx",
            ),
        ]


class LatestScanResult(ScanData):
    """One row per host, always reflecting the most recent scan.

    Written via UPSERT (INSERT ... ON CONFLICT target DO UPDATE) on every
    agent submission. scan_id matches the corresponding ScanResult row so
    callers can jump directly to the full history entry.
    """

    scan_result = models.ForeignKey(
        "ScanResult",
        on_delete=models.SET_NULL,
        null=True,
        related_name="latest",
    )

    class Meta:
        constraints: typing.ClassVar = [
            models.UniqueConstraint(
                fields=["target"],
                name="unique_latest_scan_result_target",
            ),
            models.UniqueConstraint(
                fields=["scan_id"],
                name="unique_latest_scan_result_scan_id",
            ),
        ]

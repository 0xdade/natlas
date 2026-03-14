from __future__ import annotations

import typing

from django.db import models

from apps.core.models import TimeStampedModel


class ScanCycle(TimeStampedModel):
    """One complete pseudo-random pass through the effective scannable address space.

    The effective scope is computed at cycle start by taking the union of all
    non-blocked ScopeItems and subtracting every blocked ScopeItem that
    overlaps them. This produces a set of non-overlapping CIDRs representing
    exactly the addresses that should be scanned.

    That computed CIDR set is stored in scope_snapshot and used for the
    lifetime of the cycle, so mid-cycle scope changes (new ranges, new blocks)
    take effect only when the next cycle starts. To pick up changes
    immediately, mark the active cycle as interrupted — Celery beat will
    open a fresh one on its next tick.

    Celery beat drip-feeds ScanTasks each tick by advancing the LCG and
    mapping the resulting index to an IP via scope_snapshot. Overlapping
    entries are impossible because blocked ranges have already been removed,
    so every index maps to exactly one unique IP.

    LCG formula: next = (lcg_a * lcg_current + lcg_b) % lcg_m
    lcg_m is a prime >= total_ips. Values >= total_ips are skipped.
    """

    class Status(models.TextChoices):
        ACTIVE = "active", "Active"
        COMPLETE = "complete", "Complete"
        INTERRUPTED = "interrupted", "Interrupted"

    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.ACTIVE,
        db_index=True,
    )
    completed_at = models.DateTimeField(null=True, blank=True)

    # Computed effective scope at cycle start: allowed CIDRs with all blocked
    # ranges subtracted out. Each entry: {"cidr": "10.0.0.0/9", "size": 8388608}
    # Order is preserved for deterministic index → IP mapping.
    scope_snapshot = models.JSONField()

    total_ips = models.PositiveBigIntegerField()
    ips_queued = models.PositiveBigIntegerField(default=0)

    # LCG state
    lcg_m = models.BigIntegerField()
    lcg_a = models.BigIntegerField()
    lcg_b = models.BigIntegerField()
    lcg_current = models.BigIntegerField()

    class Meta:
        constraints: typing.ClassVar = [
            models.UniqueConstraint(
                fields=["status"],
                condition=models.Q(status="active"),
                name="unique_active_scan_cycle",
            ),
        ]

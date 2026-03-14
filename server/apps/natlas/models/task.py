from __future__ import annotations

import typing

import uuid6
from django.db import models
from netfields import InetAddressField

from apps.core.models import TimeStampedModel
from apps.natlas.models.agent import Agent
from apps.natlas.models.scan import ScanResult


class ScanTask(TimeStampedModel):
    """Work queue entry representing a single host to be scanned.

    Celery beat enqueues tasks for every IP in scope on each scan cycle.
    Agents claim tasks atomically via SELECT FOR UPDATE SKIP LOCKED and
    transition them through: pending → claimed → completed | failed.

    The unique constraint on (target) for active statuses ensures no two
    agents can simultaneously work the same host.
    """

    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        CLAIMED = "claimed", "Claimed"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"

    id = models.UUIDField(primary_key=True, default=uuid6.uuid7, editable=False)
    cycle = models.ForeignKey(
        "ScanCycle",
        on_delete=models.CASCADE,
        related_name="tasks",
    )
    target = InetAddressField(store_prefix_length=False)
    status = models.CharField(
        max_length=16,
        choices=Status.choices,
        default=Status.PENDING,
    )
    agent = models.ForeignKey(
        Agent,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scan_tasks",
    )
    claimed_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    claim_count = models.PositiveSmallIntegerField(default=0)
    scan_result = models.OneToOneField(
        ScanResult,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="scan_task",
    )

    class Meta:
        constraints: typing.ClassVar = [
            models.UniqueConstraint(
                fields=["target"],
                condition=models.Q(status__in=["pending", "claimed"]),
                name="unique_active_scan_task_per_target",
            ),
        ]
        indexes: typing.ClassVar = [
            # Partial index covering only pending rows — this is what the
            # agent claim query scans, so it stays small as tasks complete.
            models.Index(
                fields=["status"],
                condition=models.Q(status="pending"),
                name="idx_scan_task_pending",
            ),
        ]

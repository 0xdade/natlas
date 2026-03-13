from __future__ import annotations

import datetime
import uuid

import uuid6
from celery import shared_task
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.db import transaction
from django.utils.timezone import now

from apps.natlas.models.agent import Agent
from apps.natlas.models.cycle import ScanCycle
from apps.natlas.models.scan import LatestScanResult, ScanResult
from apps.natlas.models.task import ScanTask
from apps.natlas.services.cycle import advance_scan_cycle, create_scan_cycle
from apps.natlas.tests.factories import build_realistic_scan, generate_raw_nmap

# Fixed UUID for the mock dev agent so it is stable across restarts.
_MOCK_AGENT_ID = uuid.UUID("00000000-0000-0000-0000-000000000001")


@shared_task(ignore_result=True)
def tick_scan_cycle() -> None:
    """Maintain a steady buffer of pending ScanTasks.

    Called periodically by Celery beat. On each tick:
      1. Count pending tasks. If already at or above the target, do nothing.
      2. Ensure an active ScanCycle exists. If the last cycle is COMPLETE but
         tasks haven't drained below the fill threshold yet, wait. Otherwise
         create a fresh cycle from the current effective scope.
      3. Advance the active cycle to fill the deficit up to:
           min(total_ips * _FILL_RATIO, _MAX_PENDING)

    COMPLETE means all IPs in the cycle have been handed to the task queue,
    not that all scans have finished. A new cycle is only opened once pending
    tasks drain below the fill threshold, preventing back-to-back cycles from
    queueing the same IPs while agents are still working.
    """
    pending = ScanTask.objects.filter(status=ScanTask.Status.PENDING).count()

    cycle = ScanCycle.objects.filter(status=ScanCycle.Status.ACTIVE).first()

    if cycle is None:
        # Don't open a new cycle until pending has drained below the fill
        # threshold. Use the last cycle's total_ips as the scope size proxy.
        last_cycle = ScanCycle.objects.order_by("-created_at").first()
        if last_cycle and pending >= int(
            last_cycle.total_ips * settings.NATLAS_SCAN_FILL_RATIO
        ):
            return
        cycle = create_scan_cycle()
        if cycle is None:
            return  # No scope configured — nothing to do.

    target = min(
        int(cycle.total_ips * settings.NATLAS_SCAN_FILL_RATIO),
        settings.NATLAS_SCAN_MAX_PENDING,
    )
    needed = target - pending
    if needed > 0:
        advance_scan_cycle(cycle, batch_size=needed)


@shared_task(ignore_result=True)
def reap_stale_tasks() -> None:
    """Reset or fail abandoned ScanTasks.

    A task is considered abandoned when it has been in the CLAIMED state
    for longer than _CLAIM_TIMEOUT_MINUTES with no update. This covers the
    case where an agent crashes or loses connectivity mid-scan.

    Tasks below the retry limit are reset to PENDING so another agent can
    claim them. Tasks at or above the limit are marked FAILED to prevent
    a broken target from cycling forever.
    """
    cutoff = now() - datetime.timedelta(
        minutes=settings.NATLAS_SCAN_CLAIM_TIMEOUT_MINUTES
    )
    stale = ScanTask.objects.filter(
        status=ScanTask.Status.CLAIMED,
        claimed_at__lt=cutoff,
    )

    stale.filter(claim_count__lt=settings.NATLAS_SCAN_MAX_CLAIM_ATTEMPTS).update(
        status=ScanTask.Status.PENDING,
        agent=None,
        claimed_at=None,
    )
    stale.filter(claim_count__gte=settings.NATLAS_SCAN_MAX_CLAIM_ATTEMPTS).update(
        status=ScanTask.Status.FAILED,
        completed_at=now(),
    )


@shared_task(ignore_result=True)
def mock_agent_tick() -> None:
    """Development-only mock agent. Only runs when DEBUG=True.

    Behaves like a real agent: claims one pending ScanTask per invocation
    and immediately submits synthetic scan data. Useful for exercising the
    full task→result pipeline locally without a real nmap agent running.

    A dedicated Agent row (fixed UUID) is created on first run and reused
    on subsequent runs so results are consistently attributed.
    """
    if not settings.DEBUG:
        return

    agent, _ = Agent.objects.get_or_create(
        agent_id=_MOCK_AGENT_ID,
        defaults={
            "friendly_name": "Mock Dev Agent",
            "is_active": True,
            "token_hash": make_password(Agent.generate_token()),
        },
    )

    completed = now()

    with transaction.atomic():
        task = (
            ScanTask.objects.select_for_update(skip_locked=True)
            .filter(status=ScanTask.Status.PENDING)
            .first()
        )
        if task is None:
            return

        task.status = ScanTask.Status.CLAIMED
        task.agent = agent
        task.claimed_at = completed
        task.claim_count += 1
        task.save(
            update_fields=["status", "agent", "claimed_at", "claim_count", "updated_at"]
        )

        scan_id = uuid6.uuid7()

        scan_result = ScanResult.objects.create(
            scan_id=scan_id,
            target=task.target,
            agent=agent,
            scanned_at=completed,
            raw_data={},
        )

        ports = build_realistic_scan(scan_result)
        raw_nmap = generate_raw_nmap(str(task.target), ports)
        ScanResult.objects.filter(pk=scan_result.pk).update(raw_nmap=raw_nmap)

        LatestScanResult.objects.update_or_create(
            target=task.target,
            defaults={
                "scan_id": scan_id,
                "agent": agent,
                "scanned_at": completed,
                "raw_data": {},
                "scan_result": scan_result,
            },
        )
        task.status = ScanTask.Status.COMPLETED
        task.completed_at = completed
        task.scan_result = scan_result
        task.save(update_fields=["status", "completed_at", "scan_result", "updated_at"])

    Agent.objects.filter(pk=agent.pk).update(last_seen=completed)

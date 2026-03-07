from __future__ import annotations

import datetime

from django.db.models import Count, Q
from django.http import HttpRequest
from django.utils.timezone import now
from ninja import Router

from apps.natlas.models.agent import Agent
from apps.natlas.models.cycle import ScanCycle
from apps.natlas.models.task import ScanTask
from apps.natlas.schemas.status import (
    ActiveCycleSchema,
    AgentStatsSchema,
    CycleTaskStatsSchema,
    LastCycleSchema,
    StatusSchema,
)

router = Router()


def _task_stats(cycle: ScanCycle) -> CycleTaskStatsSchema:
    counts: dict[str, int] = {s.value: 0 for s in ScanTask.Status}
    for row in cycle.tasks.values("status").annotate(n=Count("id")):
        counts[row["status"]] = row["n"]

    pending = counts[ScanTask.Status.PENDING]
    claimed = counts[ScanTask.Status.CLAIMED]
    completed = counts[ScanTask.Status.COMPLETED]
    failed = counts[ScanTask.Status.FAILED]

    return CycleTaskStatsSchema(
        pending=pending,
        claimed=claimed,
        completed=completed,
        failed=failed,
        outstanding=pending + claimed,
    )


def _eta(
    completed: int, total: int, started_at: datetime.datetime
) -> datetime.datetime | None:
    """Estimate completion time given a count of completed units and a start time."""
    if completed <= 0:
        return None
    elapsed = (now() - started_at).total_seconds()
    if elapsed <= 0:
        return None
    remaining = total - completed
    if remaining <= 0:
        return now()
    rate = completed / elapsed  # units per second
    return now() + datetime.timedelta(seconds=remaining / rate)


RECENTLY_SEEN_MINUTES = 15


def _agent_stats() -> AgentStatsSchema:
    cutoff = now() - datetime.timedelta(minutes=RECENTLY_SEEN_MINUTES)
    agg = Agent.objects.aggregate(
        total=Count("agent_id"),
        active=Count("agent_id", filter=Q(is_active=True)),
        recently_seen=Count("agent_id", filter=Q(last_seen__gte=cutoff)),
    )
    return AgentStatsSchema(
        total=agg["total"],
        active=agg["active"],
        recently_seen=agg["recently_seen"],
    )


@router.get("/status/", response=StatusSchema)
def get_status(request: HttpRequest) -> StatusSchema:
    active = ScanCycle.objects.filter(status=ScanCycle.Status.ACTIVE).first()

    active_schema = None
    if active:
        task_stats = _task_stats(active)
        progress_pct = (
            round(active.ips_queued / active.total_ips * 100, 2)
            if active.total_ips
            else 0.0
        )
        active_schema = ActiveCycleSchema(
            id=active.pk,
            total_ips=active.total_ips,
            ips_queued=active.ips_queued,
            progress_pct=progress_pct,
            started_at=active.created_at,
            tasks=task_stats,
            eta_queue_complete=_eta(
                active.ips_queued, active.total_ips, active.created_at
            ),
            eta_scan_complete=_eta(
                task_stats.completed, active.total_ips, active.created_at
            ),
        )

    last = (
        ScanCycle.objects.filter(status=ScanCycle.Status.COMPLETE)
        .order_by("-completed_at")
        .first()
    )
    last_schema = None
    if last is not None and last.completed_at is not None:
        last_schema = LastCycleSchema(
            id=last.pk,
            total_ips=last.total_ips,
            started_at=last.created_at,
            completed_at=last.completed_at,
            duration_seconds=(last.completed_at - last.created_at).total_seconds(),
        )

    return StatusSchema(
        agents=_agent_stats(),
        active_cycle=active_schema,
        last_completed_cycle=last_schema,
    )

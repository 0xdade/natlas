from __future__ import annotations

import datetime

from ninja import Schema


class AgentStatsSchema(Schema):
    total: int
    active: int  # is_active=True
    recently_seen: int  # checked in within the last 15 minutes


class CycleTaskStatsSchema(Schema):
    pending: int
    claimed: int
    completed: int
    failed: int
    outstanding: int  # pending + claimed


class ActiveCycleSchema(Schema):
    id: int
    total_ips: int
    ips_queued: int
    progress_pct: float
    started_at: datetime.datetime
    tasks: CycleTaskStatsSchema
    # None when rate cannot yet be estimated (no data points)
    eta_queue_complete: datetime.datetime | None
    eta_scan_complete: datetime.datetime | None


class LastCycleSchema(Schema):
    id: int
    total_ips: int
    started_at: datetime.datetime
    completed_at: datetime.datetime
    duration_seconds: float


class StatusSchema(Schema):
    agents: AgentStatsSchema
    active_cycle: ActiveCycleSchema | None
    last_completed_cycle: LastCycleSchema | None

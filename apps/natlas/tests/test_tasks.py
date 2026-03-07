"""Tests for apps.natlas.tasks.

Deterministic LCG used throughout: same /30 fixture as test_cycle.py.
  scope    : 10.0.0.0/30  (4 IPs: .0, .1, .2, .3)
  total_ips: 4
  lcg_m    : 5  (next prime >= 4)
"""

from __future__ import annotations

import datetime

import pytest
from django.utils.timezone import now

from apps.natlas.models.cycle import ScanCycle
from apps.natlas.models.scope import ScopeItem
from apps.natlas.models.task import ScanTask
from apps.natlas.tasks import reap_stale_tasks, tick_scan_cycle

CIDR_30 = "10.0.0.0/30"  # 4 IPs: 10.0.0.0 - 10.0.0.3


def _make_cycle(**kwargs) -> ScanCycle:
    defaults = {
        "scope_snapshot": [{"cidr": CIDR_30, "size": 4}],
        "total_ips": 4,
        "lcg_m": 5,
        "lcg_a": 1,
        "lcg_b": 3,
        "lcg_current": 0,
        "ips_queued": 0,
        "status": ScanCycle.Status.ACTIVE,
    }
    defaults.update(kwargs)
    return ScanCycle.objects.create(**defaults)


# ---------------------------------------------------------------------------
# tick_scan_cycle
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestTickScanCycle:
    def test_no_op_when_no_scope(self):
        tick_scan_cycle()
        assert ScanTask.objects.count() == 0
        assert ScanCycle.objects.count() == 0

    def test_creates_cycle_and_tasks_when_scope_exists(self, settings):
        settings.NATLAS_SCAN_FILL_RATIO = 0.5
        settings.NATLAS_SCAN_MAX_PENDING = 1000
        ScopeItem.objects.create(target=CIDR_30, is_blocked=False)
        tick_scan_cycle()
        # fill_ratio=0.5 queues 2 of 4 IPs, leaving the cycle ACTIVE
        assert ScanCycle.objects.filter(status=ScanCycle.Status.ACTIVE).exists()
        assert ScanTask.objects.filter(status=ScanTask.Status.PENDING).count() > 0

    def test_max_pending_cap_limits_tasks(self, settings):
        settings.NATLAS_SCAN_FILL_RATIO = 1.0
        settings.NATLAS_SCAN_MAX_PENDING = 2
        ScopeItem.objects.create(target=CIDR_30, is_blocked=False)  # 4 IPs
        tick_scan_cycle()
        assert ScanTask.objects.filter(status=ScanTask.Status.PENDING).count() == 2

    def test_fill_ratio_limits_tasks(self, settings):
        settings.NATLAS_SCAN_FILL_RATIO = 0.5
        settings.NATLAS_SCAN_MAX_PENDING = 1000
        ScopeItem.objects.create(target=CIDR_30, is_blocked=False)  # 4 IPs → target = 2
        tick_scan_cycle()
        assert ScanTask.objects.filter(status=ScanTask.Status.PENDING).count() == 2

    def test_does_not_create_cycle_when_above_threshold(self, settings):
        settings.NATLAS_SCAN_FILL_RATIO = 0.5
        settings.NATLAS_SCAN_MAX_PENDING = 1000
        _make_cycle(status=ScanCycle.Status.COMPLETE)
        # 3 pending >= int(4 * 0.5) = 2, so no new cycle should be created
        for i in range(3):
            ScanTask.objects.create(
                target=f"10.0.0.{i}", status=ScanTask.Status.PENDING
            )
        tick_scan_cycle()
        assert not ScanCycle.objects.filter(status=ScanCycle.Status.ACTIVE).exists()

    def test_creates_new_cycle_when_below_threshold(self, settings):
        settings.NATLAS_SCAN_FILL_RATIO = 0.5
        settings.NATLAS_SCAN_MAX_PENDING = 1000
        _make_cycle(status=ScanCycle.Status.COMPLETE)
        # 1 pending < int(4 * 0.5) = 2, so a new cycle should be created
        ScanTask.objects.create(target="10.0.0.0", status=ScanTask.Status.PENDING)
        ScopeItem.objects.create(target=CIDR_30, is_blocked=False)
        tick_scan_cycle()
        assert ScanCycle.objects.filter(status=ScanCycle.Status.ACTIVE).exists()

    def test_does_not_exceed_target_on_existing_active_cycle(self, settings):
        settings.NATLAS_SCAN_FILL_RATIO = 0.5
        settings.NATLAS_SCAN_MAX_PENDING = 1000
        _make_cycle()  # ACTIVE, 4 IPs → target = 2
        tick_scan_cycle()
        assert ScanTask.objects.filter(status=ScanTask.Status.PENDING).count() == 2

    def test_no_op_when_pending_already_at_target(self, settings):
        settings.NATLAS_SCAN_FILL_RATIO = 0.5
        settings.NATLAS_SCAN_MAX_PENDING = 1000
        cycle = _make_cycle()
        # Pre-fill to the target count
        for i in range(2):
            ScanTask.objects.create(
                target=f"10.0.0.{i}", status=ScanTask.Status.PENDING
            )
        tick_scan_cycle()
        # Cycle should not have advanced
        cycle.refresh_from_db()
        assert cycle.ips_queued == 0


# ---------------------------------------------------------------------------
# reap_stale_tasks
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestReapStaleTasks:
    def _stale_claimed_at(self, settings) -> datetime.datetime:
        return now() - datetime.timedelta(
            minutes=settings.NATLAS_SCAN_CLAIM_TIMEOUT_MINUTES + 1
        )

    def test_resets_stale_task_below_retry_limit(self, settings):
        settings.NATLAS_SCAN_MAX_CLAIM_ATTEMPTS = 3
        ScanTask.objects.create(
            target="10.0.0.1",
            status=ScanTask.Status.CLAIMED,
            claimed_at=self._stale_claimed_at(settings),
            claim_count=1,
        )
        reap_stale_tasks()
        task = ScanTask.objects.get()
        assert task.status == ScanTask.Status.PENDING
        assert task.claimed_at is None
        assert task.agent is None

    def test_fails_stale_task_at_retry_limit(self, settings):
        settings.NATLAS_SCAN_MAX_CLAIM_ATTEMPTS = 3
        ScanTask.objects.create(
            target="10.0.0.1",
            status=ScanTask.Status.CLAIMED,
            claimed_at=self._stale_claimed_at(settings),
            claim_count=3,
        )
        reap_stale_tasks()
        task = ScanTask.objects.get()
        assert task.status == ScanTask.Status.FAILED
        assert task.completed_at is not None

    def test_ignores_fresh_claimed_task(self):
        ScanTask.objects.create(
            target="10.0.0.1",
            status=ScanTask.Status.CLAIMED,
            claimed_at=now(),
            claim_count=1,
        )
        reap_stale_tasks()
        task = ScanTask.objects.get()
        assert task.status == ScanTask.Status.CLAIMED

    def test_ignores_pending_task(self):
        ScanTask.objects.create(target="10.0.0.1", status=ScanTask.Status.PENDING)
        reap_stale_tasks()
        assert ScanTask.objects.get().status == ScanTask.Status.PENDING

    def test_resets_and_fails_in_same_pass(self, settings):
        settings.NATLAS_SCAN_MAX_CLAIM_ATTEMPTS = 3
        stale_at = self._stale_claimed_at(settings)
        ScanTask.objects.create(
            target="10.0.0.1",
            status=ScanTask.Status.CLAIMED,
            claimed_at=stale_at,
            claim_count=1,
        )
        ScanTask.objects.create(
            target="10.0.0.2",
            status=ScanTask.Status.CLAIMED,
            claimed_at=stale_at,
            claim_count=3,
        )
        reap_stale_tasks()
        assert ScanTask.objects.get(target="10.0.0.1").status == ScanTask.Status.PENDING
        assert ScanTask.objects.get(target="10.0.0.2").status == ScanTask.Status.FAILED

"""Tests for apps.natlas.services.cycle.

Deterministic LCG used throughout the DB tests:
  scope    : 10.0.0.0/30  (4 IPs: .0, .1, .2, .3)
  total_ips: 4
  lcg_m    : 5  (next prime >= 4)
  lcg_a    : 1
  lcg_b    : 3
  lcg_current: 0  (starting position)

Sequence of values produced by (current + 3) % 5 starting from 0:
  3 → 1 → 4 (skip, >= 4) → 2 → 0
Resulting IPs: 10.0.0.3, 10.0.0.1, 10.0.0.2, 10.0.0.0
"""

from __future__ import annotations

import ipaddress

import pytest

from apps.natlas.models.cycle import ScanCycle
from apps.natlas.models.scope import ScopeItem
from apps.natlas.models.task import ScanTask
from apps.natlas.services.cycle import (
    _index_to_ip,
    _is_prime,
    _next_prime,
    advance_scan_cycle,
    compute_effective_scope,
    create_scan_cycle,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CIDR_30 = "10.0.0.0/30"  # 4 IPs: 10.0.0.0 - 10.0.0.3
CIDR_24 = "192.168.1.0/24"  # 256 IPs


def _make_cycle(**kwargs) -> ScanCycle:
    """Create a ScanCycle with the deterministic /30 LCG configuration."""
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


def _net(cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    return ipaddress.ip_network(cidr)


# ---------------------------------------------------------------------------
# _is_prime
# ---------------------------------------------------------------------------


class TestIsPrime:
    def test_small_primes(self):
        for p in (2, 3, 5, 7, 11, 13, 97):
            assert _is_prime(p), f"{p} should be prime"

    def test_small_composites(self):
        for n in (0, 1, 4, 6, 8, 9, 25, 100):
            assert not _is_prime(n), f"{n} should not be prime"

    def test_large_prime(self):
        # 7th Mersenne prime
        assert _is_prime(524287)

    def test_large_composite(self):
        assert not _is_prime(524288)  # 2^19

    def test_two_is_prime(self):
        assert _is_prime(2)

    def test_negative(self):
        assert not _is_prime(-7)


# ---------------------------------------------------------------------------
# _next_prime
# ---------------------------------------------------------------------------


class TestNextPrime:
    def test_at_prime_returns_same(self):
        assert _next_prime(5) == 5
        assert _next_prime(7) == 7

    def test_above_prime_returns_next(self):
        assert _next_prime(6) == 7
        assert _next_prime(8) == 11

    def test_small_values(self):
        assert _next_prime(0) == 2
        assert _next_prime(1) == 2
        assert _next_prime(2) == 2

    def test_large_value(self):
        # Next prime after 100 is 101
        assert _next_prime(100) == 101


# ---------------------------------------------------------------------------
# compute_effective_scope
# ---------------------------------------------------------------------------


class TestComputeEffectiveScope:
    def test_empty_inputs(self):
        assert compute_effective_scope([], []) == []

    def test_no_blocked_returns_allowed(self):
        allowed = [_net("10.0.0.0/24"), _net("192.168.0.0/24")]
        result = compute_effective_scope(allowed, [])
        assert {str(n) for n in result} == {"10.0.0.0/24", "192.168.0.0/24"}

    def test_blocked_outside_allowed_unchanged(self):
        allowed = [_net("10.0.0.0/24")]
        blocked = [_net("192.168.0.0/24")]
        result = compute_effective_scope(allowed, blocked)
        assert result == [_net("10.0.0.0/24")]

    def test_blocked_equals_allowed_empty_result(self):
        allowed = [_net("10.0.0.0/24")]
        blocked = [_net("10.0.0.0/24")]
        assert compute_effective_scope(allowed, blocked) == []

    def test_blocked_inside_allowed_splits(self):
        # Block the upper half of a /24 → remainder is the lower /25
        allowed = [_net("10.0.0.0/24")]
        blocked = [_net("10.0.0.128/25")]
        result = compute_effective_scope(allowed, blocked)
        total = sum(n.num_addresses for n in result)
        assert total == 128
        # Every result network must be within 10.0.0.0/24
        for net in result:
            assert net.subnet_of(_net("10.0.0.0/24"))  # type: ignore[arg-type]
        # No result network may overlap the blocked range
        for net in result:
            assert not net.overlaps(_net("10.0.0.128/25"))

    def test_multiple_blocked_ranges(self):
        allowed = [_net("10.0.0.0/24")]
        blocked = [_net("10.0.0.0/25"), _net("10.0.0.128/26")]
        result = compute_effective_scope(allowed, blocked)
        total = sum(n.num_addresses for n in result)
        # 256 - 128 - 64 = 64 IPs remaining
        assert total == 64

    def test_blocked_larger_than_allowed(self):
        # Blocking a /8 removes the entire /24 inside it
        allowed = [_net("10.1.0.0/24")]
        blocked = [_net("10.0.0.0/8")]
        assert compute_effective_scope(allowed, blocked) == []

    def test_no_overlaps_in_result(self):
        allowed = [_net("10.0.0.0/22")]
        blocked = [_net("10.0.1.0/24")]
        result = compute_effective_scope(allowed, blocked)
        # Verify no two result CIDRs overlap
        for i, a in enumerate(result):
            for b in result[i + 1 :]:
                assert not a.overlaps(b)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# _index_to_ip
# ---------------------------------------------------------------------------


class TestIndexToIp:
    def _snapshot(self, *cidrs: str) -> list[dict]:
        return [
            {"cidr": c, "size": ipaddress.ip_network(c).num_addresses} for c in cidrs
        ]

    def test_single_cidr_first_ip(self):
        snap = self._snapshot("10.0.0.0/24")
        assert _index_to_ip(0, snap) == "10.0.0.0"

    def test_single_cidr_last_ip(self):
        snap = self._snapshot("10.0.0.0/24")
        assert _index_to_ip(255, snap) == "10.0.0.255"

    def test_single_cidr_middle_ip(self):
        snap = self._snapshot("10.0.0.0/24")
        assert _index_to_ip(100, snap) == "10.0.0.100"

    def test_two_cidrs_first_cidr(self):
        snap = self._snapshot("10.0.0.0/30", "192.168.1.0/24")
        assert _index_to_ip(0, snap) == "10.0.0.0"
        assert _index_to_ip(3, snap) == "10.0.0.3"

    def test_two_cidrs_boundary(self):
        snap = self._snapshot("10.0.0.0/30", "192.168.1.0/24")
        # Index 4 is the first IP of the second CIDR
        assert _index_to_ip(4, snap) == "192.168.1.0"

    def test_two_cidrs_second_cidr(self):
        snap = self._snapshot("10.0.0.0/30", "192.168.1.0/24")
        assert _index_to_ip(4 + 255, snap) == "192.168.1.255"

    def test_out_of_range_raises(self):
        snap = self._snapshot("10.0.0.0/30")
        with pytest.raises(ValueError):
            _index_to_ip(4, snap)


# ---------------------------------------------------------------------------
# create_scan_cycle
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestCreateScanCycle:
    def test_no_scope_returns_none(self):
        assert create_scan_cycle() is None

    def test_all_blocked_returns_none(self):
        ScopeItem.objects.create(target="10.0.0.0/24", is_blocked=True)
        assert create_scan_cycle() is None

    def test_creates_active_cycle(self):
        ScopeItem.objects.create(target=CIDR_30, is_blocked=False)
        cycle = create_scan_cycle()
        assert cycle is not None
        assert cycle.status == ScanCycle.Status.ACTIVE
        assert cycle.completed_at is None

    def test_total_ips_matches_scope(self):
        ScopeItem.objects.create(target=CIDR_30, is_blocked=False)
        cycle = create_scan_cycle()
        assert cycle is not None
        assert cycle.total_ips == 4

    def test_blocked_subnet_excluded_from_total(self):
        # /24 = 256, blocked /25 = 128, effective = 128
        ScopeItem.objects.create(target="10.0.0.0/24", is_blocked=False)
        ScopeItem.objects.create(target="10.0.0.128/25", is_blocked=True)
        cycle = create_scan_cycle()
        assert cycle is not None
        assert cycle.total_ips == 128

    def test_lcg_modulus_is_prime_and_gte_total_ips(self):
        ScopeItem.objects.create(target=CIDR_30, is_blocked=False)
        cycle = create_scan_cycle()
        assert cycle is not None
        assert cycle.lcg_m >= cycle.total_ips
        assert _is_prime(cycle.lcg_m)

    def test_lcg_step_in_valid_range(self):
        ScopeItem.objects.create(target=CIDR_30, is_blocked=False)
        cycle = create_scan_cycle()
        assert cycle is not None
        assert 1 <= cycle.lcg_b < cycle.lcg_m

    def test_lcg_start_in_valid_range(self):
        ScopeItem.objects.create(target=CIDR_30, is_blocked=False)
        cycle = create_scan_cycle()
        assert cycle is not None
        assert 0 <= cycle.lcg_current < cycle.lcg_m

    def test_ips_queued_starts_at_zero(self):
        ScopeItem.objects.create(target=CIDR_30, is_blocked=False)
        cycle = create_scan_cycle()
        assert cycle is not None
        assert cycle.ips_queued == 0


# ---------------------------------------------------------------------------
# advance_scan_cycle
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestAdvanceScanCycle:
    def test_returns_count_of_generated_tasks(self):
        cycle = _make_cycle()
        count = advance_scan_cycle(cycle, batch_size=2)
        assert count == 2

    def test_creates_scan_task_objects(self):
        cycle = _make_cycle()
        advance_scan_cycle(cycle, batch_size=2)
        assert ScanTask.objects.count() == 2

    def test_generated_ips_within_scope(self):
        cycle = _make_cycle()
        advance_scan_cycle(cycle, batch_size=4)
        network = ipaddress.ip_network(CIDR_30)
        for task in ScanTask.objects.all():
            assert ipaddress.ip_address(str(task.target)) in network

    def test_all_ips_generated_across_batches(self):
        cycle = _make_cycle()
        advance_scan_cycle(cycle, batch_size=2)
        advance_scan_cycle(cycle, batch_size=2)
        ips = {str(t.target) for t in ScanTask.objects.all()}
        assert ips == {"10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.3"}

    def test_tasks_linked_to_cycle(self):
        cycle = _make_cycle()
        advance_scan_cycle(cycle, batch_size=2)
        assert ScanTask.objects.filter(cycle=cycle).count() == 2

    def test_no_duplicate_tasks(self):
        cycle = _make_cycle()
        advance_scan_cycle(cycle, batch_size=4)
        ips = [str(t.target) for t in ScanTask.objects.all()]
        assert len(ips) == len(set(ips))

    def test_cycle_marked_complete_when_exhausted(self):
        cycle = _make_cycle()
        advance_scan_cycle(cycle, batch_size=10)
        cycle.refresh_from_db()
        assert cycle.status == ScanCycle.Status.COMPLETE
        assert cycle.completed_at is not None

    def test_ips_queued_updated(self):
        cycle = _make_cycle()
        advance_scan_cycle(cycle, batch_size=2)
        cycle.refresh_from_db()
        assert cycle.ips_queued == 2

    def test_lcg_current_updated(self):
        cycle = _make_cycle()
        advance_scan_cycle(cycle, batch_size=2)
        cycle.refresh_from_db()
        # After 2 valid IPs (3 LCG steps: values 3, 1, then skip 4, then 2),
        # current should have advanced from 0.
        assert cycle.lcg_current != 0

    def test_inactive_cycle_returns_zero(self):
        cycle = _make_cycle(status=ScanCycle.Status.COMPLETE)
        count = advance_scan_cycle(cycle)
        assert count == 0
        assert ScanTask.objects.count() == 0

    def test_interrupted_cycle_returns_zero(self):
        cycle = _make_cycle(status=ScanCycle.Status.INTERRUPTED)
        count = advance_scan_cycle(cycle)
        assert count == 0

    def test_already_complete_returns_zero(self):
        cycle = _make_cycle(ips_queued=4, status=ScanCycle.Status.COMPLETE)
        count = advance_scan_cycle(cycle)
        assert count == 0

    def test_existing_pending_task_not_duplicated(self):
        # Pre-create a pending task for one of the IPs in the cycle.
        ScanTask.objects.create(target="10.0.0.3", status=ScanTask.Status.PENDING)
        cycle = _make_cycle()
        advance_scan_cycle(cycle, batch_size=4)
        # Still only 4 tasks total — the conflict was ignored silently.
        assert ScanTask.objects.count() == 4

    def test_partial_advance_does_not_complete(self):
        cycle = _make_cycle()
        advance_scan_cycle(cycle, batch_size=2)
        cycle.refresh_from_db()
        assert cycle.status == ScanCycle.Status.ACTIVE

    def test_full_single_batch_generates_exact_count(self):
        cycle = _make_cycle()
        count = advance_scan_cycle(cycle, batch_size=10)
        # Only 4 IPs in scope regardless of batch_size
        assert count == 4
        assert ScanTask.objects.count() == 4


# ---------------------------------------------------------------------------
# create_scan_cycle — consistent order
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestCreateScanCycleConsistentOrder:
    def test_reuses_lcg_when_scope_unchanged(self, settings):
        settings.NATLAS_SCAN_CONSISTENT_ORDER = True
        # Prior completed cycle with the same lcg_m as CIDR_30 produces (5)
        _make_cycle(status=ScanCycle.Status.COMPLETE, lcg_b=3, lcg_current=2)
        ScopeItem.objects.create(target=CIDR_30, is_blocked=False)
        cycle = create_scan_cycle()
        assert cycle is not None
        assert cycle.lcg_b == 3
        assert cycle.lcg_current == 2

    def test_randomizes_when_scope_size_changes(self, settings):
        settings.NATLAS_SCAN_CONSISTENT_ORDER = True
        # Prior cycle had lcg_m=7 (different scope size); new scope gives lcg_m=5
        _make_cycle(status=ScanCycle.Status.COMPLETE, lcg_m=7, lcg_b=3, lcg_current=2)
        ScopeItem.objects.create(target=CIDR_30, is_blocked=False)
        cycle = create_scan_cycle()
        assert cycle is not None
        assert cycle.lcg_m == 5
        assert 1 <= cycle.lcg_b < cycle.lcg_m
        assert 0 <= cycle.lcg_current < cycle.lcg_m

    def test_randomizes_when_no_prior_cycle(self, settings):
        settings.NATLAS_SCAN_CONSISTENT_ORDER = True
        ScopeItem.objects.create(target=CIDR_30, is_blocked=False)
        cycle = create_scan_cycle()
        assert cycle is not None
        assert 1 <= cycle.lcg_b < cycle.lcg_m
        assert 0 <= cycle.lcg_current < cycle.lcg_m

    def test_second_cycle_continues_from_first(self, settings):
        settings.NATLAS_SCAN_CONSISTENT_ORDER = True
        ScopeItem.objects.create(target=CIDR_30, is_blocked=False)
        cycle1 = create_scan_cycle()
        assert cycle1 is not None
        advance_scan_cycle(cycle1, batch_size=4)
        cycle1.refresh_from_db()
        assert cycle1.status == ScanCycle.Status.COMPLETE

        cycle2 = create_scan_cycle()
        assert cycle2 is not None
        assert cycle2.lcg_b == cycle1.lcg_b
        assert cycle2.lcg_current == cycle1.lcg_current

    def test_default_order_randomizes_each_cycle(self, settings):
        settings.NATLAS_SCAN_CONSISTENT_ORDER = False
        ScopeItem.objects.create(target=CIDR_30, is_blocked=False)
        # With lcg_m=5 there are 4 possible step values. Running 10 cycles makes
        # the probability of all sharing the same step astronomically low (~1/4^9).
        seen_steps: set[int] = set()
        for _ in range(10):
            cycle = create_scan_cycle()
            assert cycle is not None
            seen_steps.add(cycle.lcg_b)
            ScanCycle.objects.filter(pk=cycle.pk).update(
                status=ScanCycle.Status.COMPLETE
            )
        assert len(seen_steps) > 1

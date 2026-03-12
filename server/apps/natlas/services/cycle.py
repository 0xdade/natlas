from __future__ import annotations

import ipaddress
import secrets

from django.conf import settings
from django.db import transaction
from django.utils.timezone import now

from apps.natlas.models.cycle import ScanCycle
from apps.natlas.models.scope import ScopeItem
from apps.natlas.models.task import ScanTask

_Network = ipaddress.IPv4Network | ipaddress.IPv6Network


# ---------------------------------------------------------------------------
# Primality
# ---------------------------------------------------------------------------


def _is_prime(n: int) -> bool:
    """Deterministic Miller-Rabin primality test.

    The witness set {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37} is proven
    sufficient for all n < 3.3 * 10^24, which covers any realistic scope size.
    """
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False

    # Write n-1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if a >= n:
            continue
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _next_prime(n: int) -> int:
    """Return the smallest prime >= n."""
    if n <= 2:
        return 2
    candidate = n if n % 2 != 0 else n + 1
    while not _is_prime(candidate):
        candidate += 2
    return candidate


# ---------------------------------------------------------------------------
# Effective scope computation
# ---------------------------------------------------------------------------


def compute_effective_scope(
    allowed: list[_Network],
    blocked: list[_Network],
) -> list[_Network]:
    """Subtract all blocked CIDRs from the allowed CIDRs.

    Returns a list of non-overlapping networks representing the addresses
    that are in scope and not explicitly blocked.
    """
    effective: list[_Network] = list(allowed)
    for blocked_net in blocked:
        remaining: list[_Network] = []
        for net in effective:
            if not net.overlaps(blocked_net):
                remaining.append(net)
            elif not net.subnet_of(blocked_net):  # type: ignore[arg-type]
                # Partial overlap: subtract the blocked portion.
                remaining.extend(net.address_exclude(blocked_net))
            # else: net is entirely within blocked_net — drop it.
        effective = remaining
    return effective


# ---------------------------------------------------------------------------
# Index → IP mapping
# ---------------------------------------------------------------------------


def _index_to_ip(index: int, scope_snapshot: list[dict[str, object]]) -> str:
    """Map a zero-based index into the effective scope to a concrete IP address.

    Walks the scope_snapshot in order, subtracting each entry's size until the
    remainder lands within the current CIDR, then offsets into that network.
    """
    offset = index
    for entry in scope_snapshot:
        size = int(entry["size"])  # type: ignore[arg-type]
        if offset < size:
            network = ipaddress.ip_network(str(entry["cidr"]))
            return str(network.network_address + offset)
        offset -= size
    raise ValueError(f"Index {index} is out of range for the scope snapshot")


# ---------------------------------------------------------------------------
# Cycle advancement
# ---------------------------------------------------------------------------


@transaction.atomic
def advance_scan_cycle(cycle: ScanCycle, batch_size: int = 500) -> int:
    """Advance the LCG and enqueue up to batch_size ScanTasks.

    Re-fetches the cycle with a row lock to prevent concurrent advances.
    LCG values >= total_ips fall in the prime-extended range and are skipped;
    only values that map to a real IP are counted toward batch_size.

    Tasks that conflict with an existing pending/claimed task for the same
    target are silently ignored (bulk_create ignore_conflicts=True).

    Returns the number of tasks enqueued, or 0 if the cycle is not active.
    Marks the cycle as complete when ips_queued reaches total_ips.
    """
    cycle = ScanCycle.objects.select_for_update().get(pk=cycle.pk)

    if cycle.status != ScanCycle.Status.ACTIVE:
        return 0

    remaining = cycle.total_ips - cycle.ips_queued
    if remaining <= 0:
        return 0

    to_generate = min(batch_size, remaining)
    tasks: list[ScanTask] = []
    current = cycle.lcg_current
    generated = 0

    # Upper bound on loop iterations: at most lcg_m steps before the LCG
    # wraps fully. In practice the skipped values (>= total_ips) are few
    # since lcg_m is the next prime above total_ips.
    for _ in range(cycle.lcg_m):
        if generated >= to_generate:
            break
        current = (current + cycle.lcg_b) % cycle.lcg_m
        if current >= cycle.total_ips:
            continue
        tasks.append(
            ScanTask(target=_index_to_ip(current, cycle.scope_snapshot), cycle=cycle)
        )
        generated += 1

    if tasks:
        ScanTask.objects.bulk_create(tasks, ignore_conflicts=True)

    new_ips_queued = cycle.ips_queued + generated
    is_complete = new_ips_queued >= cycle.total_ips

    ScanCycle.objects.filter(pk=cycle.pk).update(
        lcg_current=current,
        ips_queued=new_ips_queued,
        status=ScanCycle.Status.COMPLETE if is_complete else cycle.status,
        completed_at=now() if is_complete else None,
    )

    return generated


# ---------------------------------------------------------------------------
# Cycle creation
# ---------------------------------------------------------------------------


def create_scan_cycle() -> ScanCycle | None:
    """Compute the current effective scope and create a new ScanCycle.

    Returns None if the effective scope is empty (nothing to scan).
    Should only be called when no active cycle exists.

    The LCG is a skip cipher: next = (current + b) % m
    where m is a prime >= total_ips, guaranteeing every index is visited
    exactly once before the sequence repeats.
    """
    allowed = [
        ipaddress.ip_network(str(item.target))
        for item in ScopeItem.objects.filter(is_blocked=False)
    ]
    blocked = [
        ipaddress.ip_network(str(item.target))
        for item in ScopeItem.objects.filter(is_blocked=True)
    ]

    effective = compute_effective_scope(allowed, blocked)
    if not effective:
        return None

    scope_snapshot = [
        {"cidr": str(net), "size": net.num_addresses} for net in effective
    ]
    total_ips = sum(entry["size"] for entry in scope_snapshot)

    lcg_m = _next_prime(total_ips)

    if settings.NATLAS_SCAN_CONSISTENT_ORDER:
        # Reuse the previous cycle's step if the scope size is unchanged so
        # each cycle continues the same traversal order, giving more predictable
        # intervals between scans of the same host. Fall back to random when
        # lcg_m differs (scope changed) or there is no prior cycle.
        last_cycle = ScanCycle.objects.order_by("-created_at").first()
        if last_cycle is not None and last_cycle.lcg_m == lcg_m:
            lcg_b = last_cycle.lcg_b
            lcg_current = last_cycle.lcg_current
        else:
            lcg_b = secrets.randbelow(lcg_m - 1) + 1
            lcg_current = secrets.randbelow(lcg_m)
    else:
        lcg_b = (
            secrets.randbelow(lcg_m - 1) + 1
        )  # 1 <= b < m  (coprime to m since m is prime)
        lcg_current = secrets.randbelow(lcg_m)  # random starting position

    return ScanCycle.objects.create(
        scope_snapshot=scope_snapshot,
        total_ips=total_ips,
        lcg_m=lcg_m,
        lcg_a=1,  # skip cipher: a=1, full period guaranteed
        lcg_b=lcg_b,
        lcg_current=lcg_current,
        ips_queued=0,
    )

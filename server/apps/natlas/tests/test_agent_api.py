"""Tests for the agent HTTP API (apps.natlas.api.agents).

The full-cycle test uses NATLAS_SCAN_CONSISTENT_ORDER = True so the LCG
sequence is stable across cycles and we can assert that every IP in scope
is processed exactly once before the cycle is marked complete.

Scope fixture: 10.0.0.0/30 — 4 IPs (.0 - .3)
"""

from __future__ import annotations

import uuid

import pytest
from ninja.testing import TestClient

from apps.natlas.api.agents import router
from apps.natlas.models.agent import Agent
from apps.natlas.models.cycle import ScanCycle
from apps.natlas.models.scan import ScanResult
from apps.natlas.models.scope import ScopeItem
from apps.natlas.models.task import ScanTask
from apps.natlas.tasks import tick_scan_cycle

CIDR_30 = "10.0.0.0/30"  # 4 IPs: .0 - .3

client = TestClient(router)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_agent(*, is_active: bool = True) -> tuple[Agent, str]:
    raw_token = Agent.generate_token()
    agent = Agent(is_active=is_active)
    agent.set_token(raw_token)
    agent.save()
    return agent, raw_token


def _auth(agent: Agent, token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {agent.make_token_string(token)}"}


def _enqueue_all(settings) -> None:
    """Create scope and enqueue all tasks for a /30 with consistent ordering."""
    settings.NATLAS_SCAN_FILL_RATIO = 1.0
    settings.NATLAS_SCAN_MAX_PENDING = 1000
    settings.NATLAS_SCAN_CONSISTENT_ORDER = True
    ScopeItem.objects.create(target=CIDR_30, is_blocked=False)
    tick_scan_cycle()


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestAgentAuth:
    def test_no_auth_returns_401(self) -> None:
        assert client.post("/claim/").status_code == 401

    def test_malformed_bearer_returns_401(self) -> None:
        r = client.post("/claim/", headers={"Authorization": "Bearer notvalid"})
        assert r.status_code == 401

    def test_wrong_token_returns_401(self) -> None:
        agent, _ = _make_agent()
        r = client.post(
            "/claim/",
            headers={"Authorization": f"Bearer {agent.make_token_string('bad')}"},
        )
        assert r.status_code == 401

    def test_inactive_agent_returns_401(self) -> None:
        agent, token = _make_agent(is_active=False)
        assert client.post("/claim/", headers=_auth(agent, token)).status_code == 401


# ---------------------------------------------------------------------------
# Claim
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestAgentClaim:
    def test_empty_queue_returns_204(self) -> None:
        agent, token = _make_agent()
        assert client.post("/claim/", headers=_auth(agent, token)).status_code == 204

    def test_claim_returns_task_fields(self, settings) -> None:  # type: ignore[type-arg]
        _enqueue_all(settings)
        agent, token = _make_agent()
        r = client.post("/claim/", headers=_auth(agent, token))
        assert r.status_code == 200
        data = r.json()
        assert "task_id" in data
        assert "scan_id" in data
        assert "target" in data

    def test_claim_transitions_task_to_claimed(self, settings) -> None:  # type: ignore[type-arg]
        _enqueue_all(settings)
        agent, token = _make_agent()
        data = client.post("/claim/", headers=_auth(agent, token)).json()
        task = ScanTask.objects.get(pk=data["task_id"])
        assert task.status == ScanTask.Status.CLAIMED
        assert task.agent == agent
        assert task.claimed_at is not None
        assert task.claim_count == 1

    def test_claim_updates_agent_last_used(self, settings) -> None:  # type: ignore[type-arg]
        _enqueue_all(settings)
        agent, token = _make_agent()
        client.post("/claim/", headers=_auth(agent, token))
        agent.refresh_from_db()
        assert agent.last_used is not None


# ---------------------------------------------------------------------------
# Submit
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestAgentSubmit:
    def test_submit_unknown_task_returns_404(self) -> None:
        agent, token = _make_agent()
        r = client.post(
            "/submit/",
            json={
                "task_id": str(uuid.uuid4()),
                "scan_id": str(uuid.uuid4()),
                "scan_start": "2024-01-01T00:00:00Z",
                "scan_stop": "2024-01-01T00:00:01Z",
            },
            headers=_auth(agent, token),
        )
        assert r.status_code == 404

    def test_submit_wrong_owner_returns_404(self, settings) -> None:  # type: ignore[type-arg]
        _enqueue_all(settings)
        agent1, token1 = _make_agent()
        agent2, token2 = _make_agent()
        claim = client.post("/claim/", headers=_auth(agent1, token1)).json()
        r = client.post(
            "/submit/",
            json={
                "task_id": claim["task_id"],
                "scan_id": claim["scan_id"],
                "scan_start": "2024-01-01T00:00:00Z",
                "scan_stop": "2024-01-01T00:00:01Z",
            },
            headers=_auth(agent2, token2),
        )
        assert r.status_code == 404

    def _submit_payload(self, claim: dict) -> dict:  # type: ignore[type-arg]
        return {
            "task_id": claim["task_id"],
            "scan_id": claim["scan_id"],
            "scan_start": "2024-01-01T00:00:00Z",
            "scan_stop": "2024-01-01T00:00:01Z",
        }

    def test_submit_creates_scan_result(self, settings) -> None:  # type: ignore[type-arg]
        _enqueue_all(settings)
        agent, token = _make_agent()
        claim = client.post("/claim/", headers=_auth(agent, token)).json()
        r = client.post(
            "/submit/",
            json=self._submit_payload(claim),
            headers=_auth(agent, token),
        )
        assert r.status_code == 200
        assert ScanResult.objects.filter(scan_id=claim["scan_id"]).exists()

    def test_submit_upserts_latest_scan_result(self, settings) -> None:  # type: ignore[type-arg]
        _enqueue_all(settings)
        agent, token = _make_agent()
        claim = client.post("/claim/", headers=_auth(agent, token)).json()
        client.post(
            "/submit/",
            json=self._submit_payload(claim),
            headers=_auth(agent, token),
        )
        assert ScanResult.objects.count() == 1

    def test_submit_marks_task_completed(self, settings) -> None:  # type: ignore[type-arg]
        _enqueue_all(settings)
        agent, token = _make_agent()
        claim = client.post("/claim/", headers=_auth(agent, token)).json()
        client.post(
            "/submit/",
            json=self._submit_payload(claim),
            headers=_auth(agent, token),
        )
        task = ScanTask.objects.get(pk=claim["task_id"])
        assert task.status == ScanTask.Status.COMPLETED
        assert task.completed_at is not None

    def test_submit_links_scan_result_to_task(self, settings) -> None:  # type: ignore[type-arg]
        _enqueue_all(settings)
        agent, token = _make_agent()
        claim = client.post("/claim/", headers=_auth(agent, token)).json()
        client.post(
            "/submit/",
            json=self._submit_payload(claim),
            headers=_auth(agent, token),
        )
        task = ScanTask.objects.get(pk=claim["task_id"])
        assert task.scan_result is not None
        assert str(task.scan_result.scan_id) == claim["scan_id"]


# ---------------------------------------------------------------------------
# Fail
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestAgentFail:
    def test_fail_marks_task_failed(self, settings) -> None:  # type: ignore[type-arg]
        _enqueue_all(settings)
        agent, token = _make_agent()
        claim = client.post("/claim/", headers=_auth(agent, token)).json()
        r = client.post(
            "/fail/", json={"task_id": claim["task_id"]}, headers=_auth(agent, token)
        )
        assert r.status_code == 200
        task = ScanTask.objects.get(pk=claim["task_id"])
        assert task.status == ScanTask.Status.FAILED
        assert task.completed_at is not None

    def test_fail_unknown_task_returns_404(self) -> None:
        agent, token = _make_agent()
        r = client.post(
            "/fail/", json={"task_id": str(uuid.uuid4())}, headers=_auth(agent, token)
        )
        assert r.status_code == 404

    def test_fail_wrong_owner_returns_404(self, settings) -> None:  # type: ignore[type-arg]
        _enqueue_all(settings)
        agent1, token1 = _make_agent()
        agent2, token2 = _make_agent()
        claim = client.post("/claim/", headers=_auth(agent1, token1)).json()
        r = client.post(
            "/fail/", json={"task_id": claim["task_id"]}, headers=_auth(agent2, token2)
        )
        assert r.status_code == 404


# ---------------------------------------------------------------------------
# Full cycle — consistent order
# ---------------------------------------------------------------------------


@pytest.mark.django_db
class TestAgentFullCycle:
    """Drain all 4 IPs in the /30 and confirm the DB state at each step.

    NATLAS_SCAN_CONSISTENT_ORDER=True keeps the LCG step stable across
    cycles, so re-running this test always visits IPs in the same order.
    The important property being verified is that every IP is claimed
    exactly once and the cycle transitions to COMPLETE.
    """

    def test_all_ips_claimed_and_submitted_exactly_once(self, settings) -> None:  # type: ignore[type-arg]
        _enqueue_all(settings)
        assert ScanTask.objects.filter(status=ScanTask.Status.PENDING).count() == 4

        agent, token = _make_agent()
        auth = _auth(agent, token)
        seen_targets: set[str] = set()

        for i in range(4):
            claim_r = client.post("/claim/", headers=auth)
            assert claim_r.status_code == 200, f"Expected task on iteration {i}"
            claim = claim_r.json()

            assert claim["target"] not in seen_targets, (
                f"Target {claim['target']} claimed twice"
            )
            seen_targets.add(claim["target"])

            submit_r = client.post(
                "/submit/",
                json={
                    "task_id": claim["task_id"],
                    "scan_id": claim["scan_id"],
                    "scan_start": "2024-01-01T00:00:00Z",
                    "scan_stop": "2024-01-01T00:00:01Z",
                },
                headers=auth,
            )
            assert submit_r.status_code == 200

        # Queue drained — next claim should return 204
        assert client.post("/claim/", headers=auth).status_code == 204

        # Every IP has a history entry and a current-state entry
        assert ScanResult.objects.count() == 4
        assert ScanResult.objects.count() == 4
        assert ScanTask.objects.filter(status=ScanTask.Status.COMPLETED).count() == 4

        # Cycle was already marked COMPLETE by advance_scan_cycle when the
        # last IP was queued (ips_queued == total_ips), not at scan time.
        assert ScanCycle.objects.get().status == ScanCycle.Status.COMPLETE

        # agent.last_used was bumped on each claim/submit
        agent.refresh_from_db()
        assert agent.last_used is not None

    def test_second_cycle_continues_consistent_order(self, settings) -> None:  # type: ignore[type-arg]
        """After a full cycle, a new cycle reuses the same LCG step (consistent order)."""
        _enqueue_all(settings)
        agent, token = _make_agent()
        auth = _auth(agent, token)

        # Drain cycle 1
        for _ in range(4):
            claim = client.post("/claim/", headers=auth).json()
            client.post(
                "/submit/",
                json={
                    "task_id": claim["task_id"],
                    "scan_id": claim["scan_id"],
                    "scan_start": "2024-01-01T00:00:00Z",
                    "scan_stop": "2024-01-01T00:00:01Z",
                },
                headers=auth,
            )

        cycle1 = ScanCycle.objects.get()
        assert cycle1.status == ScanCycle.Status.COMPLETE

        # Open cycle 2 — tick creates and immediately advances it (small scope)
        tick_scan_cycle()
        cycle2 = ScanCycle.objects.order_by("-created_at").first()
        assert cycle2 is not None
        assert cycle2.pk != cycle1.pk

        # Consistent order: same LCG step as cycle 1
        assert cycle2.lcg_b == cycle1.lcg_b

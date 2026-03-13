from __future__ import annotations

import uuid6
from django.db import transaction
from django.http import HttpRequest
from django.utils.timezone import now
from ninja import Router

from apps.natlas.api.auth import AgentAuth
from apps.natlas.models.agent import Agent
from apps.natlas.models.port import Port, Script
from apps.natlas.models.scan import LatestScanResult, ScanResult
from apps.natlas.models.task import ScanTask
from apps.natlas.schemas.agents import (
    ClaimResponseSchema,
    FailTaskSchema,
    SubmitAckSchema,
    SubmitResultSchema,
)
from apps.natlas.services.nmap_parser import parse_xml

router = Router(auth=AgentAuth())


@router.post("/claim/", response={200: ClaimResponseSchema, 204: None})
def claim_task(request: HttpRequest) -> tuple[int, ClaimResponseSchema | None]:
    """Atomically claim the next pending scan task.

    Returns 200 + task details on success, 204 when the queue is empty.
    """
    agent: Agent = request.auth  # type: ignore[assignment]

    with transaction.atomic():
        task = (
            ScanTask.objects.select_for_update(skip_locked=True)
            .filter(status=ScanTask.Status.PENDING)
            .first()
        )
        if task is None:
            return 204, None

        scan_id = uuid6.uuid7()
        task.status = ScanTask.Status.CLAIMED
        task.agent = agent
        task.claimed_at = now()
        task.claim_count += 1
        task.save(
            update_fields=["status", "agent", "claimed_at", "claim_count", "updated_at"]
        )

    Agent.objects.filter(pk=agent.pk).update(last_seen=now())

    return 200, ClaimResponseSchema(
        task_id=task.pk,
        scan_id=scan_id,
        target=str(task.target),
    )


@router.post("/submit/", response={200: SubmitAckSchema, 404: dict})
def submit_result(
    request: HttpRequest, payload: SubmitResultSchema
) -> tuple[int, SubmitAckSchema | dict]:
    """Submit scan results and mark the task complete.

    Creates a ScanResult history row and upserts LatestScanResult for the host.
    """
    agent: Agent = request.auth  # type: ignore[assignment]

    with transaction.atomic():
        task = (
            ScanTask.objects.select_for_update()
            .filter(pk=payload.task_id, agent=agent, status=ScanTask.Status.CLAIMED)
            .first()
        )
        if task is None:
            return 404, {"detail": "Task not found or not owned by this agent"}

        completed = now()
        raw_data = {"raw_xml": payload.raw_xml, "raw_gnmap": payload.raw_gnmap}
        scan_result = ScanResult.objects.create(
            scan_id=payload.scan_id,
            target=task.target,
            agent=agent,
            scanned_at=completed,
            scan_start=payload.scan_start,
            scan_stop=payload.scan_stop,
            raw_data=raw_data,
            raw_nmap=payload.raw_nmap,
        )

        for p in parse_xml(payload.raw_xml):
            port = Port.objects.create(
                scan_result=scan_result,
                port_number=p.port_number,
                protocol=p.protocol,
                state=p.state,
                service_name=p.service_name,
                service_product=p.service_product,
                service_version=p.service_version,
                service_extra=p.service_extra,
            )
            for s in p.scripts:
                Script.objects.create(port=port, name=s.name, output=s.output)

        LatestScanResult.objects.update_or_create(
            target=task.target,
            defaults={
                "scan_id": payload.scan_id,
                "agent": agent,
                "scanned_at": completed,
                "scan_start": payload.scan_start,
                "scan_stop": payload.scan_stop,
                "raw_data": raw_data,
                "scan_result": scan_result,
            },
        )
        task.status = ScanTask.Status.COMPLETED
        task.completed_at = completed
        task.scan_result = scan_result
        task.save(update_fields=["status", "completed_at", "scan_result", "updated_at"])

    Agent.objects.filter(pk=agent.pk).update(last_seen=now())

    return 200, SubmitAckSchema(scan_id=payload.scan_id)


@router.post("/fail/", response={200: dict, 404: dict})
def fail_task(request: HttpRequest, payload: FailTaskSchema) -> tuple[int, dict]:
    """Mark a claimed task as failed so it can be reclaimed later."""
    agent: Agent = request.auth  # type: ignore[assignment]

    with transaction.atomic():
        task = (
            ScanTask.objects.select_for_update()
            .filter(pk=payload.task_id, agent=agent, status=ScanTask.Status.CLAIMED)
            .first()
        )
        if task is None:
            return 404, {"detail": "Task not found or not owned by this agent"}

        task.status = ScanTask.Status.FAILED
        task.completed_at = now()
        task.save(update_fields=["status", "completed_at", "updated_at"])

    return 200, {"detail": "Task marked as failed"}

from __future__ import annotations

import uuid
from urllib.parse import urlparse

import uuid6
from django.db import transaction
from django.http import HttpRequest
from django.utils.timezone import now
from ninja import Router

from apps.natlas.api.auth import AgentAuth
from apps.natlas.models.agent import Agent
from apps.natlas.models.dns import DNSRecord
from apps.natlas.models.port import Port, Script
from apps.natlas.models.scan import ScanResult
from apps.natlas.models.screenshot import Screenshot
from apps.natlas.models.ssl_certificate import SSLCertificate
from apps.natlas.models.task import ScanTask
from apps.natlas.schemas.agents import (
    ClaimResponseSchema,
    DNSNameSchema,
    FailTaskSchema,
    SubmitAckSchema,
    SubmitResultSchema,
)
from apps.natlas.schemas.scan_config import (
    MasscanConfig,
    NmapConfig,
    NucleiConfig,
    ScreenshotConfig,
    WhatWebConfig,
)
from apps.natlas.services import storage
from apps.natlas.services.nmap_parser import parse_xml
from apps.natlas.services.scope import get_tags_for_target

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

    dns_names = [
        DNSNameSchema(name=r.name, record_type=r.record_type, value=r.value)
        for r in DNSRecord.objects.filter(resolved_ip=task.target)
    ]

    config = agent.scan_config

    return 200, ClaimResponseSchema(
        task_id=task.pk,
        scan_id=scan_id,
        target=str(task.target),
        dns_names=dns_names,
        enabled_plugins=config.enabled_plugins,
        masscan_config=MasscanConfig.model_validate(config.masscan_config),
        nmap_config=NmapConfig.model_validate(config.nmap_config),
        nuclei_config=NucleiConfig.model_validate(config.nuclei_config),
        screenshot_config=ScreenshotConfig.model_validate(config.screenshot_config),
        whatweb_config=WhatWebConfig.model_validate(config.whatweb_config),
    )


@router.post("/submit/", response={200: SubmitAckSchema, 404: dict})
def submit_result(
    request: HttpRequest, payload: SubmitResultSchema
) -> tuple[int, SubmitAckSchema | dict]:
    """Submit scan results and mark the task complete."""
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
        scan_result = ScanResult.objects.create(
            id=payload.scan_id,
            target=task.target,
            agent=agent,
            scanned_at=completed,
            scan_start=payload.scan_start,
            scan_stop=payload.scan_stop,
            raw_data=payload.model_dump(mode="json"),
            raw_nmap=payload.raw_nmap,
            tags=get_tags_for_target(task.target),
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
            for c in p.ssl_certificates:
                cert, _ = SSLCertificate.objects.get_or_create(
                    fingerprint_sha1=c.fingerprint_sha1,
                    defaults={
                        "subject_cn": c.subject_cn,
                        "subject": c.subject,
                        "issuer_cn": c.issuer_cn,
                        "issuer": c.issuer,
                        "not_valid_before": c.not_valid_before,
                        "not_valid_after": c.not_valid_after,
                        "public_key_type": c.public_key_type,
                        "public_key_bits": c.public_key_bits,
                        "subject_alt_names": c.subject_alt_names,
                        "pem": c.pem,
                    },
                )
                cert.ports.add(port)

        task.status = ScanTask.Status.COMPLETED
        task.completed_at = completed
        task.scan_result = scan_result
        task.save(update_fields=["status", "completed_at", "scan_result", "updated_at"])

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


@router.post("/screenshots/", response={200: dict, 404: dict})
def upload_screenshot(
    request: HttpRequest,
    scan_id: uuid.UUID,
    port: int,
    scheme: str,
    url: str,
) -> tuple[int, dict]:
    """Accept a raw PNG screenshot from the agent and store it in S3."""
    agent: Agent = request.auth  # type: ignore[assignment]

    scan_result = ScanResult.objects.filter(id=scan_id, agent=agent).first()
    if scan_result is None:
        return 404, {"detail": "Scan result not found"}

    host = urlparse(url).hostname or "unknown"
    data: bytes = request.body
    s3_key = f"screenshots/{scan_id}/{scheme}-{port}-{host}.png"
    storage.upload(s3_key, data, content_type="image/png")

    Screenshot.objects.create(
        scan_result=scan_result,
        port=port,
        scheme=scheme,
        url=url,
        s3_key=s3_key,
    )

    return 200, {"detail": "OK"}

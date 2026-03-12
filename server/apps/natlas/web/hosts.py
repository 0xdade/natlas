from __future__ import annotations

import json
import uuid
from typing import Any

from django.core.paginator import Page, Paginator
from django.db.models import Exists, OuterRef
from django.http import HttpRequest
from django.shortcuts import get_object_or_404
from djangoql.exceptions import DjangoQLError
from djangoql.queryset import apply_search
from djangoql.serializers import DjangoQLSchemaSerializer
from ninja import Router

from apps.core.schemas import TemplateSchema
from apps.natlas.models.port import Port
from apps.natlas.models.scan import LatestScanResult, ScanResult
from apps.natlas.search import HostSearchSchema

_RESULTS_PER_PAGE = 25

router = Router()


class HostsResponseSchema(TemplateSchema):
    template_name: str = "natlas/hosts.html"
    results: Page[LatestScanResult]
    q: str
    error: str | None
    introspections: str

    class Config:
        arbitrary_types_allowed = True


@router.get("/hosts/", response={200: HostsResponseSchema})
def hosts(
    request: HttpRequest, q: str = "", page: int = 1
) -> tuple[int, HostsResponseSchema]:
    qs = (
        LatestScanResult.objects.filter(
            Exists(Port.objects.filter(scan_result=OuterRef("scan_result")))
        )
        .select_related("agent")
        .order_by("-scanned_at")
    )
    error: str | None = None

    if q:
        try:
            qs = apply_search(qs, q, HostSearchSchema)
        except DjangoQLError as e:
            error = str(e)
            qs = qs.none()

    # You may want to use SuggestionsAPISerializer and an additional API
    # endpoint (see in djangoql.views) for asynchronous suggestions loading
    introspections = DjangoQLSchemaSerializer().serialize(
        HostSearchSchema(LatestScanResult),
    )

    paginator = Paginator(qs, _RESULTS_PER_PAGE)
    results_page = paginator.get_page(page)

    return 200, HostsResponseSchema(
        results=results_page,
        q=q,
        error=error,
        introspections=json.dumps(introspections),
    )


class HostDetailResponseSchema(TemplateSchema):
    template_name: str = "natlas/host_detail.html"
    latest: Any
    history: Any

    class Config:
        arbitrary_types_allowed = True


@router.get("/hosts/{target}/", response={200: HostDetailResponseSchema})
def host_detail(
    request: HttpRequest, target: str
) -> tuple[int, HostDetailResponseSchema]:
    latest = get_object_or_404(
        LatestScanResult.objects.select_related(
            "agent", "scan_result"
        ).prefetch_related("scan_result__ports__scripts"),
        target=target,
    )
    history = list(
        ScanResult.objects.filter(target=target)
        .select_related("agent")
        .order_by("-scanned_at")
    )
    return 200, HostDetailResponseSchema(latest=latest, history=history)


class ScanDetailResponseSchema(TemplateSchema):
    template_name: str = "natlas/scan_detail.html"
    scan: Any
    target: str

    class Config:
        arbitrary_types_allowed = True


@router.get("/hosts/{target}/{scan_id}/", response={200: ScanDetailResponseSchema})
def scan_detail(
    request: HttpRequest, target: str, scan_id: uuid.UUID
) -> tuple[int, ScanDetailResponseSchema]:
    scan = get_object_or_404(
        ScanResult.objects.select_related("agent").prefetch_related("ports__scripts"),
        target=target,
        scan_id=scan_id,
    )
    return 200, ScanDetailResponseSchema(scan=scan, target=target)

from __future__ import annotations

import json
import uuid
from typing import Any, Literal

from django.core.paginator import Page, Paginator
from django.db.models import Count, Exists, OuterRef, Q, Subquery
from django.http import Http404, HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404
from djangoql.exceptions import DjangoQLError
from djangoql.queryset import apply_search
from djangoql.serializers import DjangoQLSchemaSerializer
from ninja import Router

from apps.core.schemas import TemplateSchema
from apps.natlas.models.port import Port
from apps.natlas.models.scan import ScanResult
from apps.natlas.search import HostSearchSchema

_RESULTS_PER_PAGE = 25

router = Router()


class HostsResponseSchema(TemplateSchema):
    template_name: str = "natlas/hosts.html"
    results: Page[ScanResult]
    q: str
    error: str | None
    introspections: str

    class Config:
        arbitrary_types_allowed = True


@router.get("/hosts/introspections/")
def hosts_introspections(request: HttpRequest) -> HttpResponse:
    data = DjangoQLSchemaSerializer().serialize(HostSearchSchema(ScanResult))
    return JsonResponse(data)


@router.get("/hosts/", response={200: HostsResponseSchema})
def hosts(
    request: HttpRequest, q: str = "", page: int = 1
) -> tuple[int, HostsResponseSchema]:
    # Step 1: most recent scan ID per target (no port filter).
    latest_ids = Subquery(
        ScanResult.objects.order_by("target", "-scanned_at")
        .distinct("target")
        .values("id")
    )

    # Step 2: filter those latest scans to only hosts with open ports, then search.
    has_open_port = Exists(
        Port.objects.filter(scan_result=OuterRef("pk"), state="open")
    )
    qs: Any = (
        ScanResult.objects.filter(id__in=latest_ids)
        .filter(has_open_port)
        .select_related("agent")
        .prefetch_related("ports")
        .annotate(open_port_count=Count("ports", filter=Q(ports__state="open")))
        .order_by("-scanned_at")
    )

    error: str | None = None
    if q:
        try:
            qs = apply_search(qs, q, HostSearchSchema)
        except DjangoQLError as e:
            error = str(e)
            qs = ScanResult.objects.none()

    introspections = DjangoQLSchemaSerializer().serialize(
        HostSearchSchema(ScanResult),
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
    history = list(
        ScanResult.objects.filter(target=target)
        .select_related("agent")
        .prefetch_related("ports__scripts")
        .order_by("-scanned_at")
    )
    if not history:
        raise Http404
    latest = history[0]
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
        id=scan_id,
    )
    return 200, ScanDetailResponseSchema(scan=scan, target=target)


_RAW_FORMATS: dict[str, str] = {
    "xml": "raw_xml",
    "gnmap": "raw_gnmap",
    "nmap": "raw_nmap",
}


@router.get("/hosts/{target}/{scan_id}/{fmt}/")
def scan_raw(
    request: HttpRequest,
    target: str,
    scan_id: uuid.UUID,
    fmt: Literal["xml", "gnmap", "nmap"],
) -> HttpResponse:
    scan = get_object_or_404(ScanResult, target=target, id=scan_id)

    # raw_nmap has a dedicated model field; xml and gnmap live in raw_data.
    if fmt == "nmap":
        content = scan.raw_nmap
    else:
        content = scan.raw_data.get(_RAW_FORMATS[fmt], "")

    if not content:
        raise Http404

    return HttpResponse(content, content_type="text/plain; charset=utf-8")

from __future__ import annotations

from datetime import timedelta

from django.db.models import Count, Exists, OuterRef
from django.http import HttpRequest
from django.utils.timezone import now
from ninja import Router, Schema

from apps.core.schemas import TemplateSchema
from apps.natlas.api.status import get_status
from apps.natlas.models.port import Port
from apps.natlas.models.scan import ScanResult
from apps.natlas.schemas.status import StatusSchema

router = Router()


class RecentStatsSchema(Schema):
    window_hours: int
    hosts_with_open_ports: int
    total_open_ports: int
    total_scans: int


def _get_recent_stats(hours: int) -> RecentStatsSchema:
    since = now() - timedelta(hours=hours)
    has_open_port = Exists(
        Port.objects.filter(scan_result=OuterRef("pk"), state="open")
    )

    agg = ScanResult.objects.filter(scanned_at__gte=since).aggregate(
        total_scans=Count("scan_id"),
        hosts_with_open_ports=Count("target", distinct=True, filter=has_open_port),
    )
    total_open_ports = Port.objects.filter(
        scan_result__scanned_at__gte=since, state="open"
    ).count()

    return RecentStatsSchema(
        window_hours=hours,
        hosts_with_open_ports=agg["hosts_with_open_ports"],
        total_open_ports=total_open_ports,
        total_scans=agg["total_scans"],
    )


class DashboardResponseSchema(TemplateSchema):
    template_name: str = "natlas/dashboard.html"
    status: StatusSchema
    recent_stats: list[RecentStatsSchema]


@router.get("/", response={200: DashboardResponseSchema})
def dashboard(request: HttpRequest) -> tuple[int, DashboardResponseSchema]:
    return 200, DashboardResponseSchema(
        status=get_status(request),
        recent_stats=[_get_recent_stats(h) for h in (1, 12, 24)],
    )

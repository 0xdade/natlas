from __future__ import annotations

from django.core.paginator import Paginator
from django.http import HttpRequest, HttpResponse
from django.shortcuts import render
from djangoql.exceptions import DjangoQLError

from apps.core.admin import IndexedFieldsSchema
from apps.natlas.models.scan import LatestScanResult

_RESULTS_PER_PAGE = 25


def hosts(request: HttpRequest) -> HttpResponse:
    q = request.GET.get("q", "").strip()
    qs = LatestScanResult.objects.select_related("agent").order_by("-scanned_at")
    error: str | None = None

    if q:
        try:
            qs = IndexedFieldsSchema(LatestScanResult).apply(qs, q)
        except DjangoQLError as e:
            error = str(e)
            qs = qs.none()

    paginator = Paginator(qs, _RESULTS_PER_PAGE)
    page = paginator.get_page(request.GET.get("page"))

    return render(
        request,
        "natlas/hosts.html",
        {
            "results": page,
            "q": q,
            "error": error,
        },
    )

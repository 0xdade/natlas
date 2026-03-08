from __future__ import annotations

from django.http import HttpRequest
from ninja import Router

from apps.core.schemas import TemplateSchema
from apps.natlas.api.status import get_status
from apps.natlas.schemas.status import StatusSchema

router = Router()


class DashboardResponseSchema(TemplateSchema):
    template_name: str = "natlas/dashboard.html"
    status: StatusSchema


@router.get("/", response={200: DashboardResponseSchema})
def dashboard(request: HttpRequest) -> tuple[int, DashboardResponseSchema]:
    return 200, DashboardResponseSchema(
        status=get_status(request),
    )

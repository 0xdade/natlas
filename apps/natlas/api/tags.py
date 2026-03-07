from __future__ import annotations

from ninja import Router

from apps.natlas.models import Tag
from apps.natlas.schemas.tags import TagSchema

router = Router()


@router.get("/", response=list[TagSchema])
def list_tags(request):  # type: ignore[type-arg]
    return Tag.objects.prefetch_related("scope_items").all()

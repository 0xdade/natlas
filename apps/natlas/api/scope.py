from __future__ import annotations

from ninja import Router

from apps.natlas.models import ScopeItem
from apps.natlas.schemas.scope import ScopeItemSchema

router = Router()


@router.get("/", response=list[ScopeItemSchema])
def list_scope_items(request):  # type: ignore[type-arg]
    return ScopeItem.objects.prefetch_related("tags").all()

from __future__ import annotations

from ninja import Schema

from apps.natlas.models import Tag
from apps.natlas.schemas.base import ScopeItemSummarySchema


class TagSchema(Schema):
    id: int
    name: str
    address_count: int
    scope_items: list[ScopeItemSummarySchema]

    @staticmethod
    def resolve_address_count(obj: Tag) -> int:
        return obj.address_count

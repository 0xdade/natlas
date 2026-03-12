from __future__ import annotations

from ninja import Schema

from apps.natlas.models import ScopeItem


class TagSummarySchema(Schema):
    id: int
    name: str


class ScopeItemSummarySchema(Schema):
    target: str
    is_blocked: bool
    address_count: int

    @staticmethod
    def resolve_target(obj: ScopeItem) -> str:
        return str(obj.target)

    @staticmethod
    def resolve_address_count(obj: ScopeItem) -> int:
        return obj.address_count

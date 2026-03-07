from __future__ import annotations

from apps.natlas.schemas.base import ScopeItemSummarySchema, TagSummarySchema


class ScopeItemSchema(ScopeItemSummarySchema):
    tags: list[TagSummarySchema]

from __future__ import annotations

from apps.natlas.models.scope import ScopeItem


def get_tags_for_target(target: object) -> list[str]:
    """Return the deduplicated tag names from all scope items that contain target."""
    scope_items = ScopeItem.objects.filter(
        target__net_contains_or_equals=target
    ).prefetch_related("tags")
    seen: set[str] = set()
    for si in scope_items:
        for tag in si.tags.all():
            seen.add(tag.name)
    return sorted(seen)

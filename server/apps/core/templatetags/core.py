from __future__ import annotations

import json

from django import template

register = template.Library()


@register.filter
def pprint_json(value: object) -> str:
    """Pretty-print a JSONField value (already a Python dict/list) as indented JSON."""
    try:
        return json.dumps(value, indent=2, default=str)
    except (TypeError, ValueError):
        return str(value)


@register.filter
def duration(seconds: object) -> str:
    """Convert a number of seconds into a human-readable duration string.

    Examples: "4d 3h 2m 1s", "1h 30m", "45s"
    """
    try:
        total = int(seconds)
    except (TypeError, ValueError):
        return "—"

    if total < 0:
        return "—"

    days, remainder = divmod(total, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, secs = divmod(remainder, 60)

    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if secs or not parts:
        parts.append(f"{secs}s")

    return " ".join(parts)

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

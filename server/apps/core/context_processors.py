from __future__ import annotations

from django.conf import settings
from django.http import HttpRequest


def version(request: HttpRequest) -> dict[str, str]:
    return {"git_version": settings.GIT_VERSION}

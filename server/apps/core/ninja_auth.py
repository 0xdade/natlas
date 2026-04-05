from __future__ import annotations

from django.http import HttpRequest


class SessionNotAuthenticated(Exception):
    pass


class WebSessionAuth:
    """
    Ninja auth class for the web NinjaAPI.

    Returns the authenticated user on success; raises SessionNotAuthenticated
    so the web NinjaAPI's exception handler can issue a login redirect rather
    than the default JSON 401.
    """

    openapi_security: list[dict[str, object]] = []

    def __call__(self, request: HttpRequest) -> object:
        if request.user.is_authenticated:
            return request.user
        raise SessionNotAuthenticated()

from __future__ import annotations

from django.http import HttpRequest
from ninja.security import HttpBearer

from apps.custom_auth.models import ServiceApiKey, UserApiKey
from apps.natlas.models.agent import Agent


class AgentAuth(HttpBearer):
    """Authenticate via `Authorization: Bearer {prefix}_{id}:{token}`."""

    def authenticate(self, request: HttpRequest, token: str) -> Agent | None:
        return Agent.authenticate(token)


class UserApiKeyAuth(HttpBearer):
    """Authenticate via `Authorization: Bearer {prefix}_{key_id}:{token}`."""

    def authenticate(self, request: HttpRequest, token: str) -> UserApiKey | None:
        return UserApiKey.authenticate(token)


class ServiceApiKeyAuth(HttpBearer):
    """Authenticate via `Authorization: Bearer {prefix}_{key_id}:{token}`."""

    def authenticate(self, request: HttpRequest, token: str) -> ServiceApiKey | None:
        return ServiceApiKey.authenticate(token)

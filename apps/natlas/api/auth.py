from __future__ import annotations

from django.http import HttpRequest
from ninja.security import HttpBearer

from apps.natlas.models.agent import Agent


class AgentAuth(HttpBearer):
    """Authenticate via `Authorization: Bearer <agent_id>:<token>`."""

    def authenticate(self, request: HttpRequest, token: str) -> Agent | None:
        try:
            agent_id, raw_token = token.split(":", 1)
        except ValueError:
            return None
        try:
            agent = Agent.objects.get(agent_id=agent_id)
        except Agent.DoesNotExist:
            return None
        if not agent.verify_auth(raw_token):
            return None
        return agent

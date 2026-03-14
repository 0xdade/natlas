from __future__ import annotations

from django.conf import settings

from apps.custom_auth.models import BaseApiKey


class Agent(BaseApiKey):
    """Represents an authenticated natlas agent instance."""

    def __str__(self) -> str:
        return self.name or str(self.id)

    @classmethod
    def get_prefix(cls) -> str:
        return str(getattr(settings, "AGENT_KEY_PREFIX", "agt"))

    def verify_auth(self, raw_token: str) -> bool:
        return self.is_active and self.check_token(raw_token)

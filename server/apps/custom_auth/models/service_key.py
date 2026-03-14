from __future__ import annotations

from django.conf import settings
from django.db import models

from apps.custom_auth.models.base import BaseApiKey


class ServiceApiKey(BaseApiKey):
    """A machine-to-machine API key not tied to any user account.

    Admins create these for system integrations (e.g. DNS importers,
    external orchestration tools). The raw token is shown once on creation
    and never stored in plaintext.

    The full token string presented to users is ``{prefix}_{id}:{raw_token}``.
    The prefix is read from ``settings.SERVICE_API_KEY_PREFIX`` (default ``"sak"``).
    """

    description = models.TextField(blank=True, default="")

    def __str__(self) -> str:
        return self.name

    @classmethod
    def get_prefix(cls) -> str:
        return str(getattr(settings, "SERVICE_API_KEY_PREFIX", "sak"))

    def verify_auth(self, raw_token: str) -> bool:
        return self.is_active and self.check_token(raw_token)

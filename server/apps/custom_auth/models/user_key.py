from __future__ import annotations

from typing import Self

from django.conf import settings
from django.db import models

from apps.custom_auth.models.base import BaseApiKey
from apps.custom_auth.models.user import User


class UserApiKey(BaseApiKey):
    """A user-owned API key for programmatic access to the API.

    Each key belongs to exactly one user. Deleting the user cascades to
    all their keys. The raw token is shown once on creation and never
    stored in plaintext.

    The full token string presented to users is ``{prefix}_{id}:{raw_token}``.
    The prefix is read from ``settings.USER_API_KEY_PREFIX`` (default ``"uak"``).
    """

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="api_keys")

    def __str__(self) -> str:
        return f"{self.name} ({self.user})"

    @classmethod
    def get_prefix(cls) -> str:
        return str(getattr(settings, "USER_API_KEY_PREFIX", "uak"))

    @classmethod
    def _fetch(cls, raw_id: str) -> Self:
        return cls.objects.select_related("user").get(id=raw_id)

    def verify_auth(self, raw_token: str) -> bool:
        return self.is_active and self.user.is_active and self.check_token(raw_token)

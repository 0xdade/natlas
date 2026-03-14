from __future__ import annotations

import secrets
from typing import Self

import uuid6
from django.contrib.auth.hashers import check_password, make_password
from django.db import models
from django.utils.timezone import now

from apps.core.models import TimeStampedModel


class BaseApiKey(TimeStampedModel):
    """Abstract base for token-based API keys.

    Subclasses must implement ``get_prefix()`` and ``verify_auth()``.
    Override ``_fetch()`` to add ``select_related`` when needed.

    Token format presented to users: ``{prefix}_{id}:{raw_token}``
    """

    id = models.UUIDField(primary_key=True, default=uuid6.uuid7, editable=False)
    name = models.CharField(max_length=128, blank=True, default="")
    token_hash = models.CharField(max_length=256)
    is_active = models.BooleanField(default=True, db_index=True)
    last_used = models.DateTimeField(null=True, blank=True)

    TOKEN_LENGTH = 32

    class Meta:
        abstract = True

    def __str__(self) -> str:
        return self.name or str(self.id)

    @classmethod
    def get_prefix(cls) -> str:
        raise NotImplementedError

    @classmethod
    def generate_token(cls) -> str:
        return secrets.token_urlsafe(cls.TOKEN_LENGTH)

    def set_token(self, raw_token: str) -> None:
        self.token_hash = make_password(raw_token)

    def check_token(self, raw_token: str) -> bool:
        return check_password(raw_token, self.token_hash)

    def make_token_string(self, raw_token: str) -> str:
        return f"{self.get_prefix()}_{self.id}:{raw_token}"

    def verify_auth(self, raw_token: str) -> bool:
        raise NotImplementedError

    @classmethod
    def _fetch(cls, raw_id: str) -> Self:
        """Fetch the key by id. Override to add select_related."""
        return cls.objects.get(id=raw_id)

    @classmethod
    def authenticate(cls, token_string: str) -> Self | None:
        try:
            prefix, rest = token_string.split("_", 1)
            raw_id, raw_token = rest.split(":", 1)
        except ValueError:
            return None
        if prefix != cls.get_prefix():
            return None
        try:
            key = cls._fetch(raw_id)
        except cls.DoesNotExist:
            return None
        if not key.verify_auth(raw_token):
            return None
        cls.objects.filter(pk=key.pk).update(last_used=now())
        return key

import secrets

import uuid6
from django.contrib.auth.hashers import check_password, make_password
from django.db import models

from apps.core.models import TimeStampedModel


class Agent(TimeStampedModel):
    agent_id = models.UUIDField(primary_key=True, default=uuid6.uuid7, editable=False)
    token_hash = models.CharField(max_length=256)
    friendly_name = models.CharField(max_length=128, blank=True, default="")
    last_seen = models.DateTimeField(null=True, blank=True)
    is_active = models.BooleanField(default=True, db_index=True)

    TOKEN_LENGTH = 32

    def __str__(self) -> str:
        return self.friendly_name or str(self.agent_id)

    @staticmethod
    def generate_token() -> str:
        return secrets.token_urlsafe(Agent.TOKEN_LENGTH)

    def set_token(self, raw_token: str) -> None:
        self.token_hash = make_password(raw_token)

    def check_token(self, raw_token: str) -> bool:
        return check_password(raw_token, self.token_hash)

    def verify_auth(self, raw_token: str) -> bool:
        return self.is_active and self.check_token(raw_token)

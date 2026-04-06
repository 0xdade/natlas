from __future__ import annotations

import typing

from django.contrib.postgres.fields import ArrayField
from django.db import models
from django.db.models import Q


class ScanConfig(models.Model):
    class Tier(models.TextChoices):
        SYSTEM_DEFAULT = "system_default", "System Default"
        USER_DEFAULT = "user_default", "User Default"
        NAMED = "named", "Named"

    class Plugin(models.TextChoices):
        MASSCAN = "masscan", "Masscan"
        NMAP = "nmap", "Nmap"
        NUCLEI = "nuclei", "Nuclei"
        SCREENSHOTS = "screenshots", "Screenshots"
        WHATWEB = "whatweb", "WhatWeb"

    name = models.CharField(max_length=255)
    description = models.TextField(blank=True, default="")
    tier = models.CharField(
        max_length=32, choices=Tier.choices, default=Tier.NAMED, db_index=True
    )

    enabled_plugins = ArrayField(
        models.CharField(max_length=64),
        default=list,
        blank=True,
        help_text="List of plugin names to run. Each plugin must be explicitly enabled.",
    )

    # Per-plugin configuration. Validated against the corresponding Pydantic
    # schema in apps.natlas.schemas.scan_config. Missing keys fall back to
    # the Pydantic model's defaults when the config is served to the agent.
    masscan_config = models.JSONField(default=dict, blank=True)
    nmap_config = models.JSONField(default=dict, blank=True)
    nuclei_config = models.JSONField(default=dict, blank=True)
    screenshot_config = models.JSONField(default=dict, blank=True)
    whatweb_config = models.JSONField(default=dict, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints: typing.ClassVar = [
            # Enforce at most one system default and one user default at the DB level.
            models.UniqueConstraint(
                fields=["tier"],
                condition=Q(tier="system_default"),
                name="unique_system_default",
            ),
            models.UniqueConstraint(
                fields=["tier"],
                condition=Q(tier="user_default"),
                name="unique_user_default",
            ),
        ]

    def save(self, *args: object, **kwargs: object) -> None:
        if self.pk and self.tier == self.Tier.SYSTEM_DEFAULT:
            raise ValueError(
                "The system default scan config is immutable. "
                "Use a data migration to update it across Natlas versions."
            )
        super().save(*args, **kwargs)

    def __str__(self) -> str:
        return f"{self.name} ({self.get_tier_display()})"

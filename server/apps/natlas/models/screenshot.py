from __future__ import annotations

import uuid6
from django.db import models

from apps.natlas.models.scan import ScanResult


class Screenshot(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid6.uuid7, editable=False)
    scan_result = models.ForeignKey(
        ScanResult, on_delete=models.CASCADE, related_name="screenshots"
    )
    port = models.IntegerField()
    scheme = models.CharField(max_length=8)  # "http" or "https"
    url = models.CharField(max_length=2048)
    s3_key = models.CharField(max_length=512)
    taken_at = models.DateTimeField(auto_now_add=True)


def __str__(self) -> str:
    return f"{self.url} ({self.scan_result_id})"

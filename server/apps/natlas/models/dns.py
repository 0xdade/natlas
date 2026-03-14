from __future__ import annotations

import typing

from django.db import models
from netfields import InetAddressField


class DNSRecord(models.Model):
    class RecordType(models.TextChoices):
        A = "A", "A"
        AAAA = "AAAA", "AAAA"
        CNAME = "CNAME", "CNAME"
        PTR = "PTR", "PTR"
        MX = "MX", "MX"
        NS = "NS", "NS"
        TXT = "TXT", "TXT"

    name = models.CharField(max_length=253, db_index=True)
    record_type = models.CharField(max_length=5, choices=RecordType.choices)
    value = models.CharField(max_length=253)
    # The ultimate IP this record resolves to. Populated for all types where
    # resolution is possible; None for records that don't resolve to an IP
    # (e.g. NS, TXT). This is the primary lookup field: given an IP, find all
    # DNS names that point to it.
    resolved_ip = InetAddressField(
        store_prefix_length=False, null=True, blank=True, db_index=True
    )
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        constraints: typing.ClassVar = [
            models.UniqueConstraint(
                fields=["name", "record_type", "value"],
                name="unique_dns_record",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.name} {self.record_type} {self.value}"

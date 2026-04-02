from __future__ import annotations

import typing

from django.contrib.postgres.indexes import OpClass
from django.db import models
from django.db.models.expressions import RawSQL
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

    name = models.CharField(max_length=253)
    record_type = models.CharField(max_length=5, choices=RecordType.choices)
    value = models.CharField(max_length=253)
    # The ultimate IP this record resolves to. Populated for all types where
    # resolution is possible; None for records that don't resolve to an IP
    # (e.g. NS, TXT). This is the primary lookup field: given an IP, find all
    # DNS names that point to it.
    resolved_ip = InetAddressField(
        store_prefix_length=False, null=True, blank=True, db_index=True
    )

    # Dot-label-reversed form of `name`, e.g. "www.example.com" → "com.example.www".
    # Maintained automatically by PostgreSQL as a stored generated column.
    # Use name_reversed__startswith="com.example." to find strict subdomains of
    # example.com, or startswith="com.example" (no trailing dot) to also match
    # the apex record itself.
    name_reversed = models.GeneratedField(
        expression=RawSQL(
            "reverse_labels(name)",
            params=[],
            output_field=models.CharField(max_length=253),
        ),
        output_field=models.CharField(max_length=253),
        db_persist=True,
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
        indexes: typing.ClassVar = [
            # Prefix queries on name: e.g. LIKE 'www.%' to find all records
            # whose leftmost label is "www".
            models.Index(
                OpClass("name", name="varchar_pattern_ops"),
                name="dnsrecord_name_prefix_idx",
            ),
            # Prefix queries on the reversed form: e.g. name_reversed LIKE
            # 'com.example.%' efficiently finds all subdomains of example.com.
            models.Index(
                OpClass("name_reversed", name="varchar_pattern_ops"),
                name="dnsrecord_name_rev_prefix_idx",
            ),
        ]

    def __str__(self) -> str:
        return f"{self.name} {self.record_type} {self.value}"

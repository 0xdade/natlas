from __future__ import annotations

import typing

from django.db import models

from apps.natlas.models.scan import ScanResult


class Port(models.Model):
    class Protocol(models.TextChoices):
        TCP = "tcp", "TCP"
        UDP = "udp", "UDP"

    scan_result = models.ForeignKey(
        ScanResult, on_delete=models.CASCADE, related_name="ports"
    )
    port_number = models.IntegerField(db_index=True)
    protocol = models.CharField(max_length=3, choices=Protocol.choices)
    state = models.CharField(max_length=10)
    service_name = models.CharField(max_length=64, blank=True)
    service_product = models.CharField(max_length=256, blank=True)
    service_version = models.CharField(max_length=256, blank=True)
    service_extra = models.CharField(max_length=256, blank=True)

    class Meta:
        constraints: typing.ClassVar = [
            models.UniqueConstraint(
                fields=["scan_result", "port_number", "protocol"],
                name="unique_port_per_scan",
            )
        ]
        indexes: typing.ClassVar = [
            models.Index(fields=["port_number"]),
            models.Index(fields=["service_name"]),
        ]


class Script(models.Model):
    port = models.ForeignKey(Port, on_delete=models.CASCADE, related_name="scripts")
    name = models.CharField(max_length=64, db_index=True)
    output = models.TextField()

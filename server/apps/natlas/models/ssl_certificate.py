from __future__ import annotations

import typing

from django.contrib.postgres.fields import ArrayField
from django.contrib.postgres.indexes import GinIndex
from django.db import models
from django.utils import timezone

from apps.natlas.models.port import Port


class SSLCertificate(models.Model):
    """A unique TLS/SSL certificate observed during scanning.

    Certificates are deduplicated by their SHA-1 fingerprint — the same cert
    appearing on many ports or many hosts is stored once and linked via the
    ports M2M. A single port may link to multiple certs (SNI / multi-cert
    vhosts); a single cert may appear on many ports and hosts.
    """

    # Primary deduplication key. Nmap stores this in the <elem key="sha1"> as
    # compact lowercase hex: 20 bytes * 2 chars = 40 chars, no separators.
    fingerprint_sha1 = models.CharField(max_length=40, unique=True)

    # Subject
    subject_cn = models.CharField(max_length=256, blank=True, default="")
    subject = models.JSONField(default=dict)

    # Issuer
    issuer_cn = models.CharField(max_length=256, blank=True, default="")
    issuer = models.JSONField(default=dict)

    # Validity window
    not_valid_before = models.DateTimeField(null=True, blank=True)
    not_valid_after = models.DateTimeField(null=True, blank=True)

    # Public key info
    public_key_type = models.CharField(max_length=32, blank=True, default="")
    public_key_bits = models.PositiveIntegerField(null=True, blank=True)

    # Subject Alternative Names — the full list of DNS names / IPs the cert covers.
    subject_alt_names: models.Field[list[str], list[str]] = ArrayField(
        models.CharField(max_length=253),
        default=list,
        blank=True,
    )

    # Raw PEM, populated when nmap includes it.
    pem = models.TextField(blank=True, default="")

    # Observation tracking
    first_seen = models.DateTimeField(auto_now_add=True)
    last_seen = models.DateTimeField(auto_now=True)

    # Link to ports where this cert has been observed.
    ports = models.ManyToManyField(Port, related_name="certificates", blank=True)

    class Meta:
        verbose_name = "SSL Certificate"
        verbose_name_plural = "SSL Certificates"
        indexes: typing.ClassVar = [
            models.Index(fields=["subject_cn"]),
            models.Index(fields=["not_valid_after"]),
            GinIndex(fields=["subject_alt_names"], name="sslcert_sans_gin_idx"),
        ]

    def __str__(self) -> str:
        return self.subject_cn or self.fingerprint_sha1

    @property
    def is_expired(self) -> bool:
        if self.not_valid_after is None:
            return False
        return self.not_valid_after < timezone.now()

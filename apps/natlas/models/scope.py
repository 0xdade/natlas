import typing

from django.db import models
from netfields import CidrAddressField, NetManager

from apps.core.models import TimeStampedModel


class Tag(TimeStampedModel):
    name = models.CharField(max_length=128, unique=True)

    class Meta:
        ordering: typing.ClassVar = ["name"]

    def __str__(self) -> str:
        return self.name

    @property
    def address_count(self) -> int:
        return sum(item.address_count for item in self.scope_items.all())


class ScopeItem(TimeStampedModel):
    target = CidrAddressField(unique=True)
    is_blocked = models.BooleanField(default=False, db_index=True)
    tags = models.ManyToManyField(Tag, blank=True, related_name="scope_items")

    objects = NetManager()

    class Meta:
        ordering: typing.ClassVar = ["target"]

    def __str__(self) -> str:
        return str(self.target)

    @property
    def address_count(self) -> int:
        return int(self.target.num_addresses)  # type: ignore[union-attr]

    @property
    def is_scope(self) -> bool:
        return not self.is_blocked

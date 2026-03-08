from __future__ import annotations

from django.db.models import Q
from djangoql.schema import DjangoQLSchema, IntField, StrField
from netfields import InetAddressField

from apps.natlas.models.scan import LatestScanResult


class PortNumberField(IntField):
    model = LatestScanResult
    name = "port"

    def get_lookup_name(self) -> str:
        return "scan_result__ports__port_number"


class ProtocolField(StrField):
    model = LatestScanResult
    name = "protocol"
    suggest_options = True

    def get_lookup_name(self) -> str:
        return "scan_result__ports__protocol"

    def get_options(self, search: str) -> list[str]:
        return [p for p in ("tcp", "udp") if search.lower() in p]


class ServiceField(StrField):
    model = LatestScanResult
    name = "service"

    def get_lookup_name(self) -> str:
        return "scan_result__ports__service_name"


class ProductField(StrField):
    model = LatestScanResult
    name = "product"

    def get_lookup_name(self) -> str:
        return "scan_result__ports__service_product"


class VersionField(StrField):
    model = LatestScanResult
    name = "version"

    def get_lookup_name(self) -> str:
        return "scan_result__ports__service_version"


class ScriptField(StrField):
    model = LatestScanResult
    name = "script"

    def get_lookup_name(self) -> str:
        return "scan_result__ports__scripts__name"


class NmapField(StrField):
    model = LatestScanResult
    name = "nmap"

    def get_lookup(self, path: list[str], operator: str, value: object) -> Q:
        invert = operator in ("!=", "!~", "not in", "not startswith", "not endswith")
        q = Q(scan_result__raw_nmap__search=value)
        return ~q if invert else q


class AgentField(StrField):
    model = LatestScanResult
    name = "agent"

    def get_lookup_name(self) -> str:
        return "agent__agent_id"


class HostSearchSchema(DjangoQLSchema):
    def get_fields(self, model: type) -> list:
        if model == LatestScanResult:
            return [
                "target",
                "scanned_at",
                PortNumberField(),
                ProtocolField(),
                ServiceField(),
                ProductField(),
                VersionField(),
                ScriptField(),
                AgentField(),
                NmapField(),
            ]
        return []

    def get_field_cls(self, field: object) -> type:
        if isinstance(field, InetAddressField):
            return StrField
        return super().get_field_cls(field)  # type: ignore[misc]

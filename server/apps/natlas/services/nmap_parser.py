from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class ParsedScript:
    name: str
    output: str


@dataclass
class ParsedSSLCertificate:
    fingerprint_sha1: str
    subject_cn: str
    subject: dict[str, str]
    issuer_cn: str
    issuer: dict[str, str]
    not_valid_before: datetime | None
    not_valid_after: datetime | None
    public_key_type: str
    public_key_bits: int | None
    subject_alt_names: list[str]
    pem: str


@dataclass
class ParsedPort:
    port_number: int
    protocol: str
    state: str
    service_name: str
    service_product: str
    service_version: str
    service_extra: str
    scripts: list[ParsedScript] = field(default_factory=list)
    ssl_certificates: list[ParsedSSLCertificate] = field(default_factory=list)


def _table_to_dict(table_elem: ET.Element) -> dict[str, str]:
    """Collect direct <elem key="..."> children of any element into a dict."""
    return {
        e.get("key", ""): (e.text or "").strip()
        for e in table_elem.findall("elem")
        if e.get("key")
    }


def _parse_sans(value: str) -> list[str]:
    """Parse a SAN extension value into a list of bare names/IPs.

    Nmap formats this as: ``DNS:example.com, DNS:www.example.com, IP Address:1.2.3.4``
    We strip the type prefix and return only the value portion.
    """
    result = []
    for _part in value.split(","):
        part = _part.strip()
        if ":" in part:
            _, _, name = part.partition(":")
            name = name.strip()
            if name:
                result.append(name)
    return result


def _parse_validity_dt(value: str) -> datetime | None:
    """Parse an ISO 8601 datetime string from nmap (no tz) as UTC."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _parse_cert_from_elem(
    cert_elem: ET.Element,
) -> ParsedSSLCertificate | None:
    """Build a ParsedSSLCertificate from an element that holds cert data.

    Expects ``cert_elem`` to have:
    - Direct ``<elem key="sha1">`` and ``<elem key="pem">`` children.
    - Keyed ``<table>`` children for subject, issuer, pubkey, validity,
      and extensions.

    Used for both the built-in ``ssl-cert`` script (where the element is
    ``<script>``) and our ``natlas-ssl-cert`` script (where it is a
    per-cert ``<table>`` child of ``<script>``).

    Returns None when sha1 is absent so a malformed entry never aborts.
    """
    elems = _table_to_dict(cert_elem)
    sha1 = elems.get("sha1", "")
    if not sha1:
        return None

    pem = elems.get("pem", "")
    subject: dict[str, str] = {}
    issuer: dict[str, str] = {}
    pub_type = ""
    pub_bits: int | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    sans: list[str] = []

    for table in cert_elem.findall("table"):
        key = table.get("key", "")
        if key == "subject":
            subject = _table_to_dict(table)
        elif key == "issuer":
            issuer = _table_to_dict(table)
        elif key == "pubkey":
            pubkey = _table_to_dict(table)
            pub_type = pubkey.get("type", "")
            bits_str = pubkey.get("bits", "")
            pub_bits = int(bits_str) if bits_str.isdigit() else None
        elif key == "validity":
            validity = _table_to_dict(table)
            not_before = _parse_validity_dt(validity.get("notBefore", ""))
            not_after = _parse_validity_dt(validity.get("notAfter", ""))
        elif key == "extensions":
            for ext_table in table.findall("table"):
                ext = _table_to_dict(ext_table)
                if "Subject Alternative Name" in ext.get("name", ""):
                    sans = _parse_sans(ext.get("value", ""))

    return ParsedSSLCertificate(
        fingerprint_sha1=sha1,
        subject_cn=subject.get("commonName", "") or elems.get("subject_cn", ""),
        subject=subject,
        issuer_cn=issuer.get("commonName", "") or elems.get("issuer_cn", ""),
        issuer=issuer,
        not_valid_before=not_before,
        not_valid_after=not_after,
        public_key_type=pub_type,
        public_key_bits=pub_bits,
        subject_alt_names=sans,
        pem=pem,
    )


def _parse_ssl_cert(script_elem: ET.Element) -> ParsedSSLCertificate | None:
    """Parse a <script id="ssl-cert"> element (built-in nmap script).

    sha1/pem are top-level <elem> children of <script>.
    """
    return _parse_cert_from_elem(script_elem)


def _parse_natlas_ssl_cert(script_elem: ET.Element) -> list[ParsedSSLCertificate]:
    """Parse a <script id="natlas-ssl-cert"> element (custom natlas script).

    Returns one cert per unique SNI probe; each is a direct <table> child
    of <script> with sha1/pem/sni as <elem> children inside that table.
    """
    certs = []
    for cert_table in script_elem.findall("table"):
        cert = _parse_cert_from_elem(cert_table)
        if cert is not None:
            certs.append(cert)
    return certs


def parse_xml(raw_xml: str) -> list[ParsedPort]:
    """Parse nmap XML output into structured port/script/certificate data.

    Only open ports are returned. Returns an empty list on parse failure
    so a malformed or empty result never aborts a submission.
    """
    if not raw_xml:
        return []

    try:
        root = ET.fromstring(raw_xml)
    except ET.ParseError:
        return []

    ports: list[ParsedPort] = []

    for host in root.findall("host"):
        for port_elem in host.findall("ports/port"):
            state_elem = port_elem.find("state")
            if state_elem is None or state_elem.get("state") != "open":
                continue

            svc = port_elem.find("service")
            parsed = ParsedPort(
                port_number=int(port_elem.get("portid", "0")),
                protocol=port_elem.get("protocol", "tcp"),
                state="open",
                service_name=svc.get("name", "") if svc is not None else "",
                service_product=svc.get("product", "") if svc is not None else "",
                service_version=svc.get("version", "") if svc is not None else "",
                service_extra=svc.get("extrainfo", "") if svc is not None else "",
            )

            for script_elem in port_elem.findall("script"):
                name = script_elem.get("id", "")
                output = script_elem.get("output", "")
                if name:
                    parsed.scripts.append(ParsedScript(name=name, output=output))
                if name == "ssl-cert":
                    cert = _parse_ssl_cert(script_elem)
                    if cert is not None:
                        parsed.ssl_certificates.append(cert)
                elif name == "natlas-ssl-cert":
                    parsed.ssl_certificates.extend(_parse_natlas_ssl_cert(script_elem))

            ports.append(parsed)

    return ports

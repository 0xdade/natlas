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
    """Collect direct <elem key="..."> children of a <table> into a dict."""
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


def _parse_ssl_cert(script_elem: ET.Element) -> ParsedSSLCertificate | None:
    """Extract structured certificate data from a <script id="ssl-cert"> element.

    Returns None if the element lacks a sha1 fingerprint (used as the
    deduplication key), so a malformed cert never aborts a submission.
    """
    # sha1 and pem are top-level <elem> children, not inside a <table>.
    sha1 = ""
    pem = ""
    for elem in script_elem.findall("elem"):
        key = elem.get("key", "")
        if key == "sha1":
            sha1 = (elem.text or "").strip()
        elif key == "pem":
            pem = (elem.text or "").strip()

    if not sha1:
        return None

    subject: dict[str, str] = {}
    issuer: dict[str, str] = {}
    pub_type = ""
    pub_bits: int | None = None
    not_before: datetime | None = None
    not_after: datetime | None = None
    sans: list[str] = []

    for table in script_elem.findall("table"):
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
            # Each extension is a nested <table> containing name/value <elem>s.
            for ext_table in table.findall("table"):
                ext = _table_to_dict(ext_table)
                if "Subject Alternative Name" in ext.get("name", ""):
                    sans = _parse_sans(ext.get("value", ""))

    return ParsedSSLCertificate(
        fingerprint_sha1=sha1,
        subject_cn=subject.get("commonName", ""),
        subject=subject,
        issuer_cn=issuer.get("commonName", ""),
        issuer=issuer,
        not_valid_before=not_before,
        not_valid_after=not_after,
        public_key_type=pub_type,
        public_key_bits=pub_bits,
        subject_alt_names=sans,
        pem=pem,
    )


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

            ports.append(parsed)

    return ports

from __future__ import annotations

import pathlib
from datetime import datetime, timezone

import pytest

from apps.natlas.services.nmap_parser import parse_xml

_FIXTURE_DIR = pathlib.Path(__file__).parent.parent / "fixtures" / "nmap-xml"

_NO_SHA1_XML = """\
<nmaprun>
  <host>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
        <script id="ssl-cert" output="Subject: commonName=example.com">
          <table key="subject"><elem key="commonName">example.com</elem></table>
        </script>
      </port>
    </ports>
  </host>
</nmaprun>
"""


@pytest.fixture
def scan_51_81_64_30() -> str:
    return (_FIXTURE_DIR / "20260315_51.81.64.30.xml").read_text()


# ---------------------------------------------------------------------------
# Fixture-based tests
# ---------------------------------------------------------------------------


def test_open_port_count(scan_51_81_64_30: str) -> None:
    ports = parse_xml(scan_51_81_64_30)
    # Closed ports (22, 179) must be excluded; open: 25,53,80,110,143,443,587,993,995
    assert len(ports) == 9


def test_technowizardry_cert_parsed(scan_51_81_64_30: str) -> None:
    ports = parse_xml(scan_51_81_64_30)
    port_25 = next(p for p in ports if p.port_number == 25)
    assert len(port_25.ssl_certificates) == 1
    c = port_25.ssl_certificates[0]

    assert c.fingerprint_sha1 == "70acb9aca84a22cda92fd8a4e97f18b94227bf78"
    assert c.subject_cn == "technowizardry.net"
    assert c.subject == {"commonName": "technowizardry.net"}
    assert c.issuer_cn == "R12"
    assert c.issuer == {
        "commonName": "R12",
        "countryName": "US",
        "organizationName": "Let's Encrypt",
    }
    assert c.public_key_type == "rsa"
    assert c.public_key_bits == 2048
    assert c.not_valid_before == datetime(2026, 3, 10, 13, 15, 18, tzinfo=timezone.utc)
    assert c.not_valid_after == datetime(2026, 6, 8, 13, 15, 17, tzinfo=timezone.utc)
    assert c.subject_alt_names == ["*.technowizardry.net", "technowizardry.net"]
    assert "BEGIN CERTIFICATE" in c.pem


def test_kubernetes_cert_parsed(scan_51_81_64_30: str) -> None:
    ports = parse_xml(scan_51_81_64_30)
    port_443 = next(p for p in ports if p.port_number == 443)
    assert len(port_443.ssl_certificates) == 1
    c = port_443.ssl_certificates[0]

    assert c.fingerprint_sha1 == "d2dc66ce731fea449435d27d808a195d935d08d6"
    assert c.subject_cn == "Kubernetes Ingress Controller Fake Certificate"
    assert c.not_valid_before == datetime(2026, 3, 15, 3, 43, 16, tzinfo=timezone.utc)
    assert c.not_valid_after == datetime(2027, 3, 15, 3, 43, 16, tzinfo=timezone.utc)
    assert c.subject_alt_names == ["ingress.local"]
    assert "BEGIN CERTIFICATE" in c.pem


def test_same_cert_on_multiple_ports(scan_51_81_64_30: str) -> None:
    ports = parse_xml(scan_51_81_64_30)
    techno_sha1 = "70acb9aca84a22cda92fd8a4e97f18b94227bf78"
    ports_with_techno = [
        p
        for p in ports
        if any(c.fingerprint_sha1 == techno_sha1 for c in p.ssl_certificates)
    ]
    assert {p.port_number for p in ports_with_techno} == {25, 110, 143, 587, 993, 995}


def test_ports_without_ssl_cert(scan_51_81_64_30: str) -> None:
    ports = parse_xml(scan_51_81_64_30)
    for port_number in (53, 80):
        p = next(p for p in ports if p.port_number == port_number)
        assert p.ssl_certificates == [], f"port {port_number} should have no certs"


# ---------------------------------------------------------------------------
# Edge-case tests (inline XML)
# ---------------------------------------------------------------------------


def test_ssl_cert_missing_sha1_skipped() -> None:
    ports = parse_xml(_NO_SHA1_XML)
    assert len(ports) == 1
    assert ports[0].ssl_certificates == []


@pytest.mark.parametrize("raw", ["", "not xml", "<broken>"])
def test_parse_xml_invalid_input(raw: str) -> None:
    assert parse_xml(raw) == []

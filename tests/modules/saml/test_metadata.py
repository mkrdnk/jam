"""Metadata round trips preserve roles, endpoints and signing requirements."""

import xml.etree.ElementTree as ET

import pytest

from jam.saml.metadata import (
    generate_idp_metadata,
    generate_sp_metadata,
    parse_metadata,
)
from jam.saml.xml import NS_MD, NS_DS


@pytest.mark.parametrize("role", ["idp", "sp"])
@pytest.mark.parametrize("signed", [False, True])
@pytest.mark.parametrize(
    "certificate",
    [None, "-----BEGIN CERTIFICATE-----\nQUJD\n-----END CERTIFICATE-----"],
)
def test_metadata_roundtrip(role, signed, certificate):
    if role == "idp":
        xml = generate_idp_metadata(
            "entity", "https://idp.test/sso", certificate, signed
        )
    else:
        xml = generate_sp_metadata(
            "entity", "https://sp.test/acs", certificate, signed
        )
    metadata = parse_metadata(xml)
    assert metadata.entity_id == "entity"
    assert metadata.role == role
    assert metadata.certificate == certificate
    if role == "idp":
        assert metadata.sso_url == "https://idp.test/sso"
        assert metadata.want_authn_requests_signed is signed
    else:
        assert metadata.acs_url == "https://sp.test/acs"
        assert metadata.authn_requests_signed is signed


@pytest.mark.parametrize("role", ["IDPSSODescriptor", "SPSSODescriptor"])
@pytest.mark.parametrize(
    "keyinfo",
    [
        "",
        "<md:KeyDescriptor/>",
        "<md:KeyDescriptor><ds:KeyInfo/></md:KeyDescriptor>",
        "<md:KeyDescriptor><ds:KeyInfo><ds:X509Data/></ds:KeyInfo></md:KeyDescriptor>",
        "<md:KeyDescriptor><ds:KeyInfo><ds:X509Data><ds:X509Certificate/></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>",
    ],
)
def test_incomplete_metadata_has_no_certificate_or_endpoint(role, keyinfo):
    xml = f'<md:EntityDescriptor xmlns:md="{NS_MD}" xmlns:ds="{NS_DS}"><md:{role}>{keyinfo}</md:{role}></md:EntityDescriptor>'
    metadata = parse_metadata(xml)
    assert metadata.certificate is None
    assert metadata.sso_url is None
    assert metadata.acs_url is None


def test_invalid_metadata():
    with pytest.raises(ValueError, match="Unknown SAML metadata"):
        parse_metadata(f'<EntityDescriptor xmlns="{NS_MD}"/>')
    with pytest.raises(ET.ParseError):
        parse_metadata("<invalid")

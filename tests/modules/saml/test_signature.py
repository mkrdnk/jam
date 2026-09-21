# -*- coding: utf-8 -*-

import xml.etree.ElementTree as ET

import pytest

from jam.saml.signature import (
    extract_public_key_from_keyinfo,
    load_private_key,
    load_public_key,
    sign_assertion,
    verify_assertion_signature,
)
from jam.saml.xml import (
    NS_SAML,
    make_element,
    register_namespaces,
    sub_element,
)
from jam.exceptions.saml import JamSAMLValidationError


@pytest.fixture()
def unsigned_assertion() -> ET.Element:
    register_namespaces()
    assertion = make_element("Assertion", NS_SAML)
    assertion.set("ID", "_test_assertion_123")
    assertion.set("IssueInstant", "2024-01-15T12:00:00Z")
    assertion.set("Version", "2.0")
    sub_element(assertion, "Issuer", NS_SAML, text="test-issuer")
    subject = make_element("Subject", NS_SAML)
    assertion.append(subject)
    sub_element(subject, "NameID", NS_SAML, text="user@test.com")
    return assertion


class TestSignAssertion:
    def test_sign_and_verify(self, unsigned_assertion, private_key_pem, public_key_pem):
        key = load_private_key(private_key_pem)
        sign_assertion(unsigned_assertion, key)

        sig = unsigned_assertion.find(
            "{http://www.w3.org/2000/09/xmldsig#}Signature"
        )
        assert sig is not None

        sv = sig.find("{http://www.w3.org/2000/09/xmldsig#}SignatureValue")
        assert sv is not None and sv.text

        pub = load_public_key(public_key_pem)
        result = verify_assertion_signature(unsigned_assertion, pub)
        assert result is True

    def test_load_public_key_from_private_key(self, private_key_pem):
        private_key = load_private_key(private_key_pem)
        public_key = load_public_key(private_key_pem)

        assert (
            public_key.public_numbers()
            == private_key.public_key().public_numbers()
        )

    def test_sign_with_cert_in_keyinfo(
        self, unsigned_assertion, private_key_pem, cert_pem
    ):
        key = load_private_key(private_key_pem)
        sign_assertion(unsigned_assertion, key, cert_pem=cert_pem)

        extracted = extract_public_key_from_keyinfo(
            unsigned_assertion.find(
                "{http://www.w3.org/2000/09/xmldsig#}Signature"
            )
        )
        assert extracted is not None

        result = verify_assertion_signature(
            unsigned_assertion, extracted
        )
        assert result is True

    def test_verify_without_key_extracts_from_keyinfo(
        self, unsigned_assertion, private_key_pem, cert_pem
    ):
        key = load_private_key(private_key_pem)
        sign_assertion(unsigned_assertion, key, cert_pem=cert_pem)
        result = verify_assertion_signature(unsigned_assertion)
        assert result is True

    def test_raises_on_missing_id(self, unsigned_assertion, private_key_pem):
        unsigned_assertion.set("ID", "")
        key = load_private_key(private_key_pem)
        with pytest.raises(JamSAMLValidationError):
            sign_assertion(unsigned_assertion, key)

    def test_raises_on_tampered_assertion(
        self, unsigned_assertion, private_key_pem, public_key_pem
    ):
        key = load_private_key(private_key_pem)
        sign_assertion(unsigned_assertion, key)

        issuer = unsigned_assertion.find(
            "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer"
        )
        if issuer is not None:
            issuer.text = "tampered-issuer"

        pub = load_public_key(public_key_pem)
        with pytest.raises(JamSAMLValidationError):
            verify_assertion_signature(unsigned_assertion, pub)

    def test_raises_on_no_signature(self, unsigned_assertion):
        with pytest.raises(JamSAMLValidationError):
            verify_assertion_signature(unsigned_assertion)

# -*- coding: utf-8 -*-

import pytest

from jam.saml import SAML


class TestEncryptAssertion:
    def test_encrypt_decrypt_roundtrip(self, key_pair, cert_pem):
        sp_private = key_pair["private"]
        sp_public = key_pair["public"]

        idp = SAML(
            role="idp",
            private_key=sp_private,
            certificate=cert_pem,
            encryption_key=sp_public,
            entity_id="https://idp.test",
        )
        sp = SAML(
            role="sp",
            private_key=sp_private,
            entity_id="https://sp.test",
            acs_url="https://sp.test/acs",
        )

        xml_str = idp.build_response(
            subject="user@test.com",
            attributes={"email": "user@test.com"},
            issuer="https://idp.test",
            audience="https://sp.test",
            destination="https://sp.test/acs",
            encrypt=True,
        )

        from jam.saml.binding import encode_post

        encoded = encode_post(xml_str)

        result = sp.parse_response(
            encoded,
            binding="post",
            audience="https://sp.test",
            issuer="https://idp.test",
            allow_unsolicited=True,
        )

        assert result.assertion is not None
        assert result.assertion.subject is not None
        assert result.assertion.subject.name_id == "user@test.com"
        assert result.assertion.attributes.get("email") == "user@test.com"

    def test_encrypted_output_contains_encrypted_assertion(self, key_pair):
        sp_private = key_pair["private"]
        sp_public = key_pair["public"]

        idp = SAML(
            role="idp",
            private_key=sp_private,
            encryption_key=sp_public,
        )

        xml_str = idp.build_response(
            subject="user@test.com",
            attributes={},
            issuer="https://idp.test",
            audience="https://sp.test",
            encrypt=True,
        )

        assert (
            "<saml:EncryptedAssertion" in xml_str
            or "EncryptedAssertion" in xml_str
        )
        assert (
            "<saml:Assertion" not in xml_str
            or "Assertion" not in xml_str.replace("Encrypted", "")
        )
        assert "EncryptionMethod" in xml_str

    def test_encrypted_without_encryption_key_raises(self, key_pair):
        idp = SAML(
            role="idp",
            private_key=key_pair["private"],
        )

        with pytest.raises(Exception):
            idp.build_response(
                subject="user@test.com",
                attributes={},
                issuer="https://idp.test",
                audience="https://sp.test",
                encrypt=True,
            )

    def test_decrypt_with_wrong_key_fails(self, key_pair):
        from jam.utils.rsa import generate_rsa_key_pair

        sp_private = key_pair["private"]
        sp_public = key_pair["public"]

        idp = SAML(
            role="idp",
            private_key=sp_private,
            encryption_key=sp_public,
        )

        xml_str = idp.build_response(
            subject="user@test.com",
            attributes={},
            issuer="https://idp.test",
            audience="https://sp.test",
            encrypt=True,
        )

        from jam.saml.binding import encode_post

        encoded = encode_post(xml_str)

        wrong_pair = generate_rsa_key_pair(2048)
        wrong_sp = SAML(
            role="sp",
            private_key=wrong_pair["private"],
        )

        with pytest.raises(Exception):
            wrong_sp.parse_response(
                encoded,
                binding="post",
                audience="https://sp.test",
                allow_unsolicited=True,
            )

    def test_encrypted_without_private_key_raises(self, key_pair):
        sp_private = key_pair["private"]
        sp_public = key_pair["public"]

        idp = SAML(
            role="idp",
            private_key=sp_private,
            encryption_key=sp_public,
        )

        xml_str = idp.build_response(
            subject="user@test.com",
            attributes={},
            issuer="https://idp.test",
            audience="https://sp.test",
            encrypt=True,
        )

        from jam.saml.binding import encode_post

        encoded = encode_post(xml_str)

        sp_no_key = SAML(
            role="sp",
        )

        with pytest.raises(Exception):
            sp_no_key.parse_response(
                encoded,
                binding="post",
                audience="https://sp.test",
                allow_unsolicited=True,
            )

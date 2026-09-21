# -*- coding: utf-8 -*-

import pytest

from jam.saml import SAML
from jam.exceptions.saml import (
    JamSAMLEmptyPrivateKey,
    JamSAMLExpired,
    JamSAMLInvalidAudience,
    JamSAMLInvalidIssuer,
    JamSAMLInvalidRecipient,
    JamSAMLNotYetValid,
    JamSAMLReplayDetected,
    JamSAMLSOAPError,
    JamSAMLValidationError,
)


class TestSAMLIdP:
    @pytest.fixture()
    def idp_saml(self, private_key_pem, cert_pem) -> SAML:
        return SAML(
            role="idp",
            private_key=private_key_pem,
            certificate=cert_pem,
            entity_id="https://idp.test",
            sso_url="https://idp.test/sso",
            default_exp=3600,
        )

    def test_build_response_returns_xml(self, idp_saml):
        xml_str = idp_saml.build_response(
            subject="user@test.com",
            attributes={"email": "user@test.com", "role": "admin"},
            issuer="https://idp.test",
            audience="https://sp.test",
        )
        assert xml_str.startswith("<")
        assert "samlp:Response" in xml_str or "Response" in xml_str
        assert "user@test.com" in xml_str

    def test_build_response_without_key_raises(self, key_pair):
        saml = SAML(
            role="idp",
            entity_id="https://idp.test",
        )
        with pytest.raises(JamSAMLEmptyPrivateKey):
            saml.build_response(
                subject="user",
                attributes={},
                issuer="https://idp.test",
                audience="https://sp.test",
            )

    def test_metadata_generation(self, idp_saml):
        meta = idp_saml.generate_metadata(
            entity_id="https://idp.test",
            sso_url="https://idp.test/sso",
        )
        assert "entityID" in meta
        assert "SingleSignOnService" in meta


class TestSAMLConfiguration:
    def test_config_meta_from_selected_dict(self):
        saml = SAML(
            config={
                "role": "idp",
                "entity_id": "https://idp.test",
                "default_exp": 600,
            }
        )

        assert saml.role == "idp"
        assert saml._entity_id == "https://idp.test"
        assert saml._default_exp == 600

    def test_config_meta_from_file(self, tmp_path):
        config = tmp_path / "jam.toml"
        config.write_text(
            """
[jam.saml]
role = "sp"
entity_id = "https://sp.test"
acs_url = "https://sp.test/acs"
""".strip()
        )

        saml = SAML(config=str(config))

        assert saml.role == "sp"
        assert saml._entity_id == "https://sp.test"
        assert saml._acs_url == "https://sp.test/acs"


class TestSAMLSP:
    @pytest.fixture()
    def sp_saml(self, public_key_pem) -> SAML:
        return SAML(
            role="sp",
            entity_id="https://sp.test",
            acs_url="https://sp.test/acs",
            idp_public_key=public_key_pem,
        )

    def test_prepare_authn_request_redirect(self, sp_saml):
        url = sp_saml.prepare_authn_request(
            "https://idp.test/sso",
            acs_url="https://sp.test/acs",
            binding="redirect",
        )
        assert url.startswith("https://idp.test/sso?")
        assert "SAMLRequest" in url

    def test_prepare_authn_request_post(self, sp_saml):
        result = sp_saml.prepare_authn_request(
            "https://idp.test/sso",
            acs_url="https://sp.test/acs",
            binding="post",
        )
        assert isinstance(result, str)
        assert len(result) > 0

    def test_metadata_generation(self, sp_saml):
        meta = sp_saml.generate_metadata(
            entity_id="https://sp.test",
            acs_url="https://sp.test/acs",
        )
        assert "AssertionConsumerService" in meta

    def test_parse_authn_request_redirect(self, sp_saml):
        authn_xml = (
            '<?xml version="1.0"?>'
            '<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            ' xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"'
            ' ID="_req123" Version="2.0" IssueInstant="2024-01-15T12:00:00Z"'
            ' Destination="https://idp.test/sso"'
            ' AssertionConsumerServiceURL="https://sp.test/acs">'
            '<saml:Issuer>https://sp.test</saml:Issuer>'
            '</samlp:AuthnRequest>'
        )
        from urllib.parse import urlencode
        from jam.saml.binding import encode_redirect
        encoded = encode_redirect(authn_xml)
        query = urlencode({"SAMLRequest": encoded})
        req = sp_saml.parse_authn_request(
            query,
            binding="redirect",
        )
        assert req.id == "_req123"
        assert req.issuer == "https://sp.test"
        assert req.acs_url == "https://sp.test/acs"

    def test_invalid_binding_raises(self, sp_saml):
        with pytest.raises(Exception):
            sp_saml.parse_response("data", binding="invalid")


class TestSLO:
    def test_build_logout_request_post(self, key_pair):
        private_pem = key_pair["private"]
        idp = SAML(
            role="idp",
            private_key=private_pem,
            entity_id="https://idp.test",
        )
        result = idp.build_logout_request(
            name_id="user@test.com",
            issuer="https://idp.test",
            destination="https://sp.test/slo",
            session_index="_session_abc",
            binding="post",
        )
        assert isinstance(result, str)
        import base64
        decoded = base64.b64decode(result).decode("utf-8")
        assert "LogoutRequest" in decoded
        assert "user@test.com" in decoded
        assert "_session_abc" in decoded

    def test_build_logout_request_redirect(self, key_pair):
        private_pem = key_pair["private"]
        idp = SAML(
            role="idp",
            private_key=private_pem,
            entity_id="https://idp.test",
        )
        url = idp.build_logout_request(
            name_id="user@test.com",
            issuer="https://idp.test",
            destination="https://sp.test/slo",
            binding="redirect",
        )
        assert url.startswith("https://sp.test/slo?")
        assert "SAMLRequest" in url
        assert "SigAlg" in url
        assert "Signature" in url

    def test_build_logout_request_without_key_raises(self):
        idp = SAML(role="idp")
        with pytest.raises(JamSAMLEmptyPrivateKey):
            idp.build_logout_request(
                name_id="user",
                issuer="https://idp.test",
                destination="https://sp.test/slo",
            )

    def test_build_logout_response_post(self, key_pair):
        private_pem = key_pair["private"]
        sp = SAML(
            role="sp",
            private_key=private_pem,
            entity_id="https://sp.test",
        )
        result = sp.build_logout_response(
            in_response_to="_req_abc",
            issuer="https://sp.test",
            destination="https://idp.test/slo",
            binding="post",
        )
        import base64
        decoded = base64.b64decode(result).decode("utf-8")
        assert "LogoutResponse" in decoded
        assert "_req_abc" in decoded
        assert "Success" in decoded

    def test_build_logout_response_custom_status(self, key_pair):
        private_pem = key_pair["private"]
        sp = SAML(
            role="sp",
            private_key=private_pem,
            entity_id="https://sp.test",
        )
        from jam.saml.xml import STATUS_REQUESTER
        result = sp.build_logout_response(
            in_response_to="_req_abc",
            issuer="https://sp.test",
            destination="https://idp.test/slo",
            status_code=STATUS_REQUESTER,
            binding="post",
        )
        import base64
        decoded = base64.b64decode(result).decode("utf-8")
        assert STATUS_REQUESTER in decoded

    def test_parse_logout_request_post(self, key_pair):
        private_pem = key_pair["private"]
        public_pem = key_pair["public"]
        idp = SAML(
            role="idp",
            private_key=private_pem,
            entity_id="https://idp.test",
        )
        encoded = idp.build_logout_request(
            name_id="user@test.com",
            issuer="https://idp.test",
            destination="https://sp.test/slo",
            session_index="_sess1",
            binding="post",
        )
        sp = SAML(
            role="sp",
            idp_public_key=public_pem,
            entity_id="https://sp.test",
        )
        result = sp.parse_logout_request(encoded, binding="post")
        assert result.id is not None
        assert result.issuer == "https://idp.test"
        assert result.name_id == "user@test.com"
        assert result.session_index == "_sess1"
        assert result.destination == "https://sp.test/slo"

    def test_parse_logout_response_post(self, key_pair):
        private_pem = key_pair["private"]
        public_pem = key_pair["public"]
        sp = SAML(
            role="sp",
            private_key=private_pem,
            entity_id="https://sp.test",
        )
        encoded = sp.build_logout_response(
            in_response_to="_req_abc",
            issuer="https://sp.test",
            destination="https://idp.test/slo",
            binding="post",
        )
        idp = SAML(
            role="idp",
            sp_public_key=public_pem,
            entity_id="https://idp.test",
        )
        result = idp.parse_logout_response(encoded, binding="post")
        assert result.id is not None
        assert result.issuer == "https://sp.test"
        assert result.in_response_to == "_req_abc"
        assert result.status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"

    def test_parse_logout_response_with_issuer_validation(self, key_pair):
        private_pem = key_pair["private"]
        public_pem = key_pair["public"]
        sp = SAML(
            role="sp",
            private_key=private_pem,
            entity_id="https://sp.test",
        )
        encoded = sp.build_logout_response(
            in_response_to="_req_abc",
            issuer="https://sp.test",
            destination="https://idp.test/slo",
            binding="post",
        )
        idp = SAML(
            role="idp",
            sp_public_key=public_pem,
            entity_id="https://idp.test",
        )
        with pytest.raises(JamSAMLInvalidIssuer):
            idp.parse_logout_response(encoded, binding="post", issuer="https://evil.test")


class TestFullRoundtrip:
    @pytest.fixture()
    def idp(self, private_key_pem, cert_pem) -> SAML:
        return SAML(
            role="idp",
            private_key=private_key_pem,
            certificate=cert_pem,
            entity_id="https://idp.test",
            sso_url="https://idp.test/sso",
            default_exp=3600,
        )

    @pytest.fixture()
    def sp(self, public_key_pem) -> SAML:
        return SAML(
            role="sp",
            entity_id="https://sp.test",
            acs_url="https://sp.test/acs",
            idp_public_key=public_key_pem,
        )

    def test_idp_builds_sp_parses(self, idp, sp):
        xml_str = idp.build_response(
            subject="user@test.com",
            attributes={"email": "user@test.com"},
            issuer="https://idp.test",
            audience="https://sp.test",
            in_response_to="_req_abc",
        )

        from jam.saml.binding import encode_post
        encoded = encode_post(xml_str)

        result = sp.parse_response(
            encoded,
            binding="post",
            audience="https://sp.test",
            issuer="https://idp.test",
        )

        assert result.id is not None
        assert result.issuer == "https://idp.test"
        assert result.status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"
        assert result.in_response_to == "_req_abc"

        data = result.assertion
        assert data is not None
        assert data.subject is not None
        assert data.subject.name_id == "user@test.com"
        assert data.attributes.get("email") == "user@test.com"
        assert data.issuer == "https://idp.test"

    def test_idp_builds_sp_parses_redirect(self, idp, sp):
        xml_str = idp.build_response(
            subject="user2@test.com",
            attributes={"email": "user2@test.com"},
            issuer="https://idp.test",
            audience="https://sp.test",
        )

        from jam.saml.binding import encode_redirect
        encoded = encode_redirect(xml_str)

        result = sp.parse_response(
            encoded,
            binding="redirect",
            audience="https://sp.test",
            issuer="https://idp.test",
        )
        assert result.assertion is not None
        assert result.assertion.subject.name_id == "user2@test.com"

    def test_mismatched_audience_raises(self, idp, sp):
        xml_str = idp.build_response(
            subject="user@test.com",
            attributes={},
            issuer="https://idp.test",
            audience="https://other-sp.test",
        )
        from jam.saml.binding import encode_post
        encoded = encode_post(xml_str)

        with pytest.raises(JamSAMLInvalidAudience):
            sp.parse_response(
                encoded,
                binding="post",
                audience="https://sp.test",
            )

    def test_expired_assertion(self, private_key_pem, public_key_pem):
        idp_zero = SAML(
            role="idp",
            private_key=private_key_pem,
            default_exp=-60,
        )
        sp = SAML(
            role="sp",
            idp_public_key=public_key_pem,
            allowed_clock_skew=0,
        )
        xml_str = idp_zero.build_response(
            subject="user@test.com",
            attributes={},
            issuer="https://idp.test",
            audience="https://sp.test",
        )

        from jam.saml.binding import encode_post
        encoded = encode_post(xml_str)

        with pytest.raises(JamSAMLExpired):
            sp.parse_response(
                encoded,
                binding="post",
                audience="https://sp.test",
            )


class TestHardening:
    def test_clock_skew_tolerance(self, private_key_pem, public_key_pem):
        from datetime import datetime, timezone
        from jam.saml.xml import fmt_instant

        sp = SAML(
            role="sp",
            idp_public_key=public_key_pem,
            allowed_clock_skew=120,
        )
        idp = SAML(
            role="idp",
            private_key=private_key_pem,
        )

        future = fmt_instant(
            datetime.fromtimestamp(
                datetime.now(timezone.utc).timestamp() + 60,
                tz=timezone.utc,
            )
        )
        from jam.saml.xml import make_element, NS_SAMLP, NS_SAML, sub_element
        import xml.etree.ElementTree as ET
        from jam.saml.signature import sign_assertion

        response = make_element("Response", NS_SAMLP)
        response.set("ID", "_r1")
        response.set("Version", "2.0")
        response.set("IssueInstant", fmt_instant())
        sub_element(response, "Issuer", NS_SAML, text="https://idp.test")
        status = make_element("Status", NS_SAMLP)
        response.append(status)
        sub_element(status, "StatusCode", NS_SAMLP, attrib={"Value": "urn:oasis:names:tc:SAML:2.0:status:Success"})

        assertion = make_element("Assertion", NS_SAML)
        assertion.set("ID", "_a1")
        assertion.set("Version", "2.0")
        assertion.set("IssueInstant", fmt_instant())
        response.append(assertion)
        sub_element(assertion, "Issuer", NS_SAML, text="https://idp.test")

        subject = make_element("Subject", NS_SAML)
        assertion.append(subject)
        sub_element(subject, "NameID", NS_SAML, text="user@test.com")
        subj_conf = make_element("SubjectConfirmation", NS_SAML)
        subj_conf.set("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
        subject.append(subj_conf)
        sub_element(
            subj_conf, "SubjectConfirmationData", NS_SAML,
            attrib={"Recipient": "https://sp.test/acs", "NotOnOrAfter": fmt_instant()},
        )

        conditions = make_element("Conditions", NS_SAML)
        conditions.set("NotBefore", future)
        conditions.set("NotOnOrAfter", fmt_instant())
        assertion.append(conditions)
        aud_restriction = sub_element(conditions, "AudienceRestriction", NS_SAML)
        sub_element(aud_restriction, "Audience", NS_SAML, text="https://sp.test")

        sign_assertion(assertion, idp._private_key)

        xml_str = ET.tostring(response, encoding="unicode")
        from jam.saml.binding import encode_post
        encoded = encode_post(xml_str)

        result = sp.parse_response(
            encoded, binding="post",
            audience="https://sp.test", issuer="https://idp.test",
        )
        assert result.assertion is not None

    def test_clock_skew_rejects_outside(self, private_key_pem, public_key_pem):
        from datetime import datetime, timezone
        from jam.saml.xml import fmt_instant

        sp = SAML(
            role="sp",
            idp_public_key=public_key_pem,
            allowed_clock_skew=30,
        )
        idp = SAML(
            role="idp",
            private_key=private_key_pem,
        )

        far_future = fmt_instant(
            datetime.fromtimestamp(
                datetime.now(timezone.utc).timestamp() + 120,
                tz=timezone.utc,
            )
        )
        from jam.saml.xml import make_element, NS_SAMLP, NS_SAML, sub_element
        import xml.etree.ElementTree as ET
        from jam.saml.signature import sign_assertion

        response = make_element("Response", NS_SAMLP)
        response.set("ID", "_r2")
        response.set("Version", "2.0")
        response.set("IssueInstant", fmt_instant())
        sub_element(response, "Issuer", NS_SAML, text="https://idp.test")
        status = make_element("Status", NS_SAMLP)
        response.append(status)
        sub_element(status, "StatusCode", NS_SAMLP, attrib={"Value": "urn:oasis:names:tc:SAML:2.0:status:Success"})

        assertion = make_element("Assertion", NS_SAML)
        assertion.set("ID", "_a2")
        assertion.set("Version", "2.0")
        assertion.set("IssueInstant", fmt_instant())
        response.append(assertion)
        sub_element(assertion, "Issuer", NS_SAML, text="https://idp.test")

        subject = make_element("Subject", NS_SAML)
        assertion.append(subject)
        sub_element(subject, "NameID", NS_SAML, text="user@test.com")
        subj_conf = make_element("SubjectConfirmation", NS_SAML)
        subj_conf.set("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
        subject.append(subj_conf)
        sub_element(
            subj_conf, "SubjectConfirmationData", NS_SAML,
            attrib={"Recipient": "https://sp.test/acs", "NotOnOrAfter": fmt_instant()},
        )

        conditions = make_element("Conditions", NS_SAML)
        conditions.set("NotBefore", far_future)
        conditions.set("NotOnOrAfter", fmt_instant())
        assertion.append(conditions)
        aud_restriction = sub_element(conditions, "AudienceRestriction", NS_SAML)
        sub_element(aud_restriction, "Audience", NS_SAML, text="https://sp.test")

        sign_assertion(assertion, idp._private_key)

        xml_str = ET.tostring(response, encoding="unicode")
        from jam.saml.binding import encode_post
        encoded = encode_post(xml_str)

        with pytest.raises(JamSAMLNotYetValid):
            sp.parse_response(
                encoded, binding="post",
                audience="https://sp.test", issuer="https://idp.test",
            )

    def test_replay_detected(self, key_pair):
        private = key_pair["private"]
        public = key_pair["public"]
        idp = SAML(
            role="idp",
            private_key=private,
            entity_id="https://idp.test",
        )
        sp = SAML(
            role="sp",
            idp_public_key=public,
            id_store={},
        )
        xml_str = idp.build_response(
            subject="user@test.com",
            attributes={"email": "user@test.com"},
            issuer="https://idp.test",
            audience="https://sp.test",
        )
        from jam.saml.binding import encode_post
        encoded = encode_post(xml_str)

        result = sp.parse_response(encoded, binding="post", audience="https://sp.test")
        assert result.assertion is not None

        with pytest.raises(JamSAMLReplayDetected):
            sp.parse_response(encoded, binding="post", audience="https://sp.test")

    def test_xxe_protection(self):
        from jam.exceptions.saml import JamSAMLValidationError
        from jam.saml.xml import safe_fromstring

        malicious = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            '<root>&xxe;</root>'
        )
        with pytest.raises(JamSAMLValidationError):
            safe_fromstring(malicious)

    def test_want_assertions_signed_false(self, private_key_pem, public_key_pem):
        from jam.saml.xml import make_element, NS_SAMLP, NS_SAML, sub_element
        import xml.etree.ElementTree as ET
        from jam.saml.xml import fmt_instant

        sp = SAML(
            role="sp",
            want_assertions_signed=False,
        )
        response = make_element("Response", NS_SAMLP)
        response.set("ID", "_r_unsigned")
        response.set("Version", "2.0")
        response.set("IssueInstant", fmt_instant())
        sub_element(response, "Issuer", NS_SAML, text="https://idp.test")
        status = make_element("Status", NS_SAMLP)
        response.append(status)
        sub_element(status, "StatusCode", NS_SAMLP, attrib={"Value": "urn:oasis:names:tc:SAML:2.0:status:Success"})

        assertion = make_element("Assertion", NS_SAML)
        assertion.set("ID", "_a_unsigned")
        assertion.set("Version", "2.0")
        assertion.set("IssueInstant", fmt_instant())
        response.append(assertion)
        sub_element(assertion, "Issuer", NS_SAML, text="https://idp.test")

        subject = make_element("Subject", NS_SAML)
        assertion.append(subject)
        sub_element(subject, "NameID", NS_SAML, text="user@test.com")
        subj_conf = make_element("SubjectConfirmation", NS_SAML)
        subj_conf.set("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
        subject.append(subj_conf)
        sub_element(
            subj_conf, "SubjectConfirmationData", NS_SAML,
            attrib={"Recipient": "https://sp.test/acs", "NotOnOrAfter": fmt_instant()},
        )

        conditions = make_element("Conditions", NS_SAML)
        conditions.set("NotBefore", fmt_instant())
        conditions.set("NotOnOrAfter", fmt_instant())
        assertion.append(conditions)
        aud_restriction = sub_element(conditions, "AudienceRestriction", NS_SAML)
        sub_element(aud_restriction, "Audience", NS_SAML, text="https://sp.test")

        xml_str = ET.tostring(response, encoding="unicode")
        from jam.saml.binding import encode_post
        encoded = encode_post(xml_str)

        result = sp.parse_response(
            encoded, binding="post",
            audience="https://sp.test", issuer="https://idp.test",
        )
        assert result.assertion is not None

    def test_invalid_recipient(self, private_key_pem, public_key_pem):
        from jam.saml.xml import make_element, NS_SAMLP, NS_SAML, sub_element
        import xml.etree.ElementTree as ET
        from jam.saml.xml import fmt_instant
        from jam.saml.signature import sign_assertion

        idp = SAML(
            role="idp",
            private_key=private_key_pem,
        )
        sp = SAML(
            role="sp",
            idp_public_key=public_key_pem,
            acs_url="https://sp.test/acs",
        )
        response = make_element("Response", NS_SAMLP)
        response.set("ID", "_r_rec")
        response.set("Version", "2.0")
        response.set("IssueInstant", fmt_instant())
        sub_element(response, "Issuer", NS_SAML, text="https://idp.test")
        status = make_element("Status", NS_SAMLP)
        response.append(status)
        sub_element(status, "StatusCode", NS_SAMLP, attrib={"Value": "urn:oasis:names:tc:SAML:2.0:status:Success"})

        assertion = make_element("Assertion", NS_SAML)
        assertion.set("ID", "_a_rec")
        assertion.set("Version", "2.0")
        assertion.set("IssueInstant", fmt_instant())
        response.append(assertion)
        sub_element(assertion, "Issuer", NS_SAML, text="https://idp.test")

        subject = make_element("Subject", NS_SAML)
        assertion.append(subject)
        sub_element(subject, "NameID", NS_SAML, text="user@test.com")
        subj_conf = make_element("SubjectConfirmation", NS_SAML)
        subj_conf.set("Method", "urn:oasis:names:tc:SAML:2.0:cm:bearer")
        subject.append(subj_conf)
        sub_element(
            subj_conf, "SubjectConfirmationData", NS_SAML,
            attrib={
                "Recipient": "https://evil.test/acs",
                "NotOnOrAfter": fmt_instant(),
            },
        )

        conditions = make_element("Conditions", NS_SAML)
        conditions.set("NotBefore", fmt_instant())
        conditions.set("NotOnOrAfter", fmt_instant())
        assertion.append(conditions)
        aud_restriction = sub_element(conditions, "AudienceRestriction", NS_SAML)
        sub_element(aud_restriction, "Audience", NS_SAML, text="https://sp.test")

        sign_assertion(assertion, idp._private_key)

        xml_str = ET.tostring(response, encoding="unicode")
        from jam.saml.binding import encode_post
        encoded = encode_post(xml_str)

        with pytest.raises(JamSAMLInvalidRecipient):
            sp.parse_response(
                encoded, binding="post",
                audience="https://sp.test", issuer="https://idp.test",
            )


class TestAttributeQuery:
    def test_build_attribute_query_post(self, private_key_pem):
        sp = SAML(
            role="sp",
            private_key=private_key_pem,
            entity_id="https://sp.test",
        )
        result = sp.build_attribute_query(
            subject="user@test.com",
            issuer="https://sp.test",
            destination="https://idp.test/attr",
            attribute_names=["email", "role"],
            binding="post",
        )
        import base64
        decoded = base64.b64decode(result).decode("utf-8")
        assert "AttributeQuery" in decoded
        assert "user@test.com" in decoded
        assert 'Name="email"' in decoded or 'Name="email"' in decoded
        assert 'Name="role"' in decoded or 'Name="role"' in decoded

    def test_build_attribute_query_redirect(self, private_key_pem):
        sp = SAML(
            role="sp",
            private_key=private_key_pem,
            entity_id="https://sp.test",
        )
        url = sp.build_attribute_query(
            subject="user@test.com",
            issuer="https://sp.test",
            destination="https://idp.test/attr",
            binding="redirect",
        )
        assert url.startswith("https://idp.test/attr?")
        assert "SAMLRequest" in url
        assert "SigAlg" in url
        assert "Signature" in url

    def test_build_without_key_raises(self):
        sp = SAML(role="sp")
        with pytest.raises(JamSAMLEmptyPrivateKey):
            sp.build_attribute_query(
                subject="user",
                issuer="https://sp.test",
                destination="https://idp.test/attr",
            )

    def test_parse_attribute_query(self, private_key_pem, public_key_pem):
        sp = SAML(
            role="sp",
            private_key=private_key_pem,
            entity_id="https://sp.test",
        )
        encoded = sp.build_attribute_query(
            subject="user@test.com",
            issuer="https://sp.test",
            destination="https://idp.test/attr",
            attribute_names=["email"],
            binding="post",
        )
        idp = SAML(
            role="idp",
            sp_public_key=public_key_pem,
            entity_id="https://idp.test",
        )
        result = idp.parse_attribute_query(encoded, binding="post")
        assert result.issuer == "https://sp.test"
        assert result.subject == "user@test.com"
        assert result.attribute_names == ["email"]

    def test_parse_attribute_query_wrong_issuer(
        self, private_key_pem, public_key_pem
    ):
        sp = SAML(
            role="sp",
            private_key=private_key_pem,
            entity_id="https://sp.test",
        )
        encoded = sp.build_attribute_query(
            subject="user",
            issuer="https://sp.test",
            destination="https://idp.test/attr",
            binding="post",
        )
        idp = SAML(
            role="idp",
            sp_public_key=public_key_pem,
        )
        with pytest.raises(JamSAMLInvalidIssuer):
            idp.parse_attribute_query(
                encoded, binding="post", issuer="https://evil.test"
            )

    def test_attribute_query_no_attributes_requested(
        self, private_key_pem
    ):
        sp = SAML(
            role="sp",
            private_key=private_key_pem,
            entity_id="https://sp.test",
        )
        encoded = sp.build_attribute_query(
            subject="user@test.com",
            issuer="https://sp.test",
            destination="https://idp.test/attr",
            binding="post",
        )
        import base64
        decoded = base64.b64decode(encoded).decode("utf-8")
        assert "AttributeQuery" in decoded
        assert 'Attribute Name=' not in decoded

    def test_build_attribute_query_response(self, private_key_pem, cert_pem):
        idp = SAML(
            role="idp",
            private_key=private_key_pem,
            certificate=cert_pem,
            entity_id="https://idp.test",
        )
        xml_str = idp.build_attribute_query_response(
            in_response_to="_query_abc",
            subject="user@test.com",
            attributes={"email": "user@test.com", "role": "admin"},
            issuer="https://idp.test",
            audience="https://sp.test",
        )
        assert "Response" in xml_str
        assert "InResponseTo" in xml_str
        assert "_query_abc" in xml_str
        assert "AttributeStatement" in xml_str
        assert "AuthnStatement" not in xml_str

    def test_build_attribute_query_response_without_key_raises(self):
        idp = SAML(role="idp")
        with pytest.raises(JamSAMLEmptyPrivateKey):
            idp.build_attribute_query_response(
                in_response_to="_r",
                subject="user",
                attributes={},
                issuer="https://idp.test",
                audience="https://sp.test",
            )

    def test_parse_attribute_query_response(
        self, private_key_pem, public_key_pem, cert_pem
    ):
        idp = SAML(
            role="idp",
            private_key=private_key_pem,
            certificate=cert_pem,
            entity_id="https://idp.test",
        )
        sp = SAML(
            role="sp",
            idp_public_key=public_key_pem,
            entity_id="https://sp.test",
            acs_url="https://sp.test/acs",
        )
        xml_str = idp.build_attribute_query_response(
            in_response_to="_query_abc",
            subject="user@test.com",
            attributes={"email": "user@test.com"},
            issuer="https://idp.test",
            audience="https://sp.test",
        )
        from jam.saml.binding import encode_post
        encoded = encode_post(xml_str)
        result = sp.parse_attribute_query_response(
            encoded,
            binding="post",
            audience="https://sp.test",
            issuer="https://idp.test",
        )
        assert result.assertion is not None
        assert result.assertion.attributes.get("email") == "user@test.com"


class TestArtifactBinding:
    def test_build_artifact(self):
        sp = SAML(role="sp")
        artifact = sp.build_artifact(
            source_message_id="_msg_1", issuer="https://sp.test"
        )
        assert isinstance(artifact, str)
        assert len(artifact) > 0
        import base64
        decoded = base64.b64decode(artifact)
        assert len(decoded) == 44

    def test_build_artifact_resolve_post(self, private_key_pem):
        sp = SAML(
            role="sp",
            private_key=private_key_pem,
            entity_id="https://sp.test",
        )
        artifact = sp.build_artifact(
            source_message_id="_msg_1", issuer="https://sp.test"
        )
        result = sp.build_artifact_resolve(
            artifact=artifact,
            issuer="https://sp.test",
            destination="https://idp.test/artifact",
            binding="post",
        )
        import base64
        decoded = base64.b64decode(result).decode("utf-8")
        assert "ArtifactResolve" in decoded
        assert artifact in decoded

    def test_build_artifact_resolve_soap(self, private_key_pem):
        sp = SAML(
            role="sp",
            private_key=private_key_pem,
            entity_id="https://sp.test",
        )
        artifact = sp.build_artifact(
            source_message_id="_msg_1", issuer="https://sp.test"
        )
        xml_str = sp.build_artifact_resolve(
            artifact=artifact,
            issuer="https://sp.test",
            destination="https://idp.test/artifact",
            binding="soap",
        )
        assert "ArtifactResolve" in xml_str
        assert artifact in xml_str

    def test_parse_artifact_resolve(self, private_key_pem, public_key_pem):
        sp = SAML(
            role="sp",
            private_key=private_key_pem,
            entity_id="https://sp.test",
        )
        artifact = sp.build_artifact(
            source_message_id="_msg_1", issuer="https://sp.test"
        )
        encoded = sp.build_artifact_resolve(
            artifact=artifact,
            issuer="https://sp.test",
            destination="https://idp.test/artifact",
            binding="post",
        )
        idp = SAML(
            role="idp",
            sp_public_key=public_key_pem,
        )
        result = idp.parse_artifact_resolve(encoded, binding="post")
        assert result.issuer == "https://sp.test"
        assert result.artifact == artifact

    def test_build_artifact_response(self, private_key_pem):
        idp = SAML(
            role="idp",
            private_key=private_key_pem,
            entity_id="https://idp.test",
        )
        original_msg = (
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            ' ID="_orig" Version="2.0" IssueInstant="2024-01-15T12:00:00Z">'
            "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">"
            "https://idp.test</saml:Issuer></samlp:Response>"
        )
        xml_str = idp.build_artifact_response(
            in_response_to="_resolve_1",
            original_message_xml=original_msg,
            issuer="https://idp.test",
            destination="https://sp.test/acs",
            binding="soap",
        )
        assert "ArtifactResponse" in xml_str
        assert "_orig" in xml_str

    def test_parse_artifact_response(self, private_key_pem):
        idp = SAML(
            role="idp",
            private_key=private_key_pem,
            entity_id="https://idp.test",
        )
        original_msg = (
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            ' ID="_orig" Version="2.0" IssueInstant="2024-01-15T12:00:00Z">'
            "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">"
            "https://idp.test</saml:Issuer></samlp:Response>"
        )
        xml_str = idp.build_artifact_response(
            in_response_to="_resolve_1",
            original_message_xml=original_msg,
            issuer="https://idp.test",
            destination="https://sp.test/acs",
            binding="soap",
        )
        sp = SAML(role="sp")
        result = sp.parse_artifact_response(xml_str, binding="soap")
        assert result.issuer == "https://idp.test"
        assert result.in_response_to == "_resolve_1"
        assert result.original_message is not None

    def test_parse_artifact_response_wrong_issuer(
        self, private_key_pem, public_key_pem
    ):
        sp = SAML(
            role="sp",
            private_key=private_key_pem,
            entity_id="https://sp.test",
        )
        artifact = sp.build_artifact(
            source_message_id="_msg_1", issuer="https://sp.test"
        )
        encoded = sp.build_artifact_resolve(
            artifact=artifact,
            issuer="https://sp.test",
            destination="https://idp.test/artifact",
            binding="post",
        )
        idp = SAML(
            role="idp",
            sp_public_key=public_key_pem,
        )
        with pytest.raises(JamSAMLInvalidIssuer):
            idp.parse_artifact_resolve(
                encoded, binding="post", issuer="https://evil.test"
            )

    def test_artifact_resolve_without_key_raises(self):
        sp = SAML(role="sp")
        with pytest.raises(JamSAMLEmptyPrivateKey):
            sp.build_artifact_resolve(
                artifact="AAQA...",
                issuer="https://sp.test",
                destination="https://idp.test/artifact",
            )

    def test_resolve_artifact_soap_roundtrip(self, private_key_pem, public_key_pem):
        import urllib.request
        from unittest.mock import patch

        from jam.saml import SAML

        sp = SAML(
            role="sp",
            private_key=private_key_pem,
            entity_id="https://sp.test",
            idp_public_key=public_key_pem,
        )
        idp = SAML(
            role="idp",
            private_key=private_key_pem,
            entity_id="https://idp.test",
            sp_public_key=public_key_pem,
        )
        artifact = idp.build_artifact(
            source_message_id="_resp_1", issuer="https://idp.test"
        )
        original_msg = (
            '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"'
            ' ID="_orig" Version="2.0" IssueInstant="2024-01-15T12:00:00Z">'
            "<saml:Issuer xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">"
            "https://idp.test</saml:Issuer></samlp:Response>"
        )

        class FakeResponse:
            def __init__(self, data):
                self._data = data

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return self._data

        def fake_urlopen(request, timeout=None):
            resolve = idp.parse_artifact_resolve(
                request.data.decode("utf-8"), binding="soap"
            )
            assert resolve.artifact == artifact
            response_xml = idp.build_artifact_response(
                in_response_to=resolve.id,
                original_message_xml=original_msg,
                issuer="https://idp.test",
                destination="https://sp.test/acs",
                binding="soap",
            )
            envelope = (
                '<?xml version="1.0" encoding="UTF-8"?>'
                '<SOAP-ENV:Envelope xmlns:SOAP-ENV='
                '"http://schemas.xmlsoap.org/soap/envelope/">'
                f"<SOAP-ENV:Body>{response_xml}</SOAP-ENV:Body>"
                "</SOAP-ENV:Envelope>"
            )
            return FakeResponse(envelope.encode("utf-8"))

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            result = sp.resolve_artifact(
                artifact=artifact,
                issuer="https://sp.test",
                resolve_url="https://idp.test/artifact",
            )
        assert "_orig" in result

    def test_resolve_artifact_malformed_response_raises(
        self, private_key_pem
    ):
        import urllib.request
        from unittest.mock import patch

        sp = SAML(
            role="sp",
            private_key=private_key_pem,
            entity_id="https://sp.test",
        )

        class FakeResponse:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def read(self):
                return b""

        with patch("urllib.request.urlopen", return_value=FakeResponse()):
            with pytest.raises(JamSAMLSOAPError):
                sp.resolve_artifact(
                    artifact="AAQA...",
                    issuer="https://sp.test",
                    resolve_url="https://idp.test/artifact",
                )

    def test_resolve_artifact_http_error_raises(self, private_key_pem):
        import urllib.error
        import urllib.request
        from unittest.mock import patch

        sp = SAML(
            role="sp",
            private_key=private_key_pem,
            entity_id="https://sp.test",
        )

        def fake_urlopen(request, timeout=None):
            raise urllib.error.URLError("connection refused")

        with patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with pytest.raises(JamSAMLSOAPError):
                sp.resolve_artifact(
                    artifact="AAQA...",
                    issuer="https://sp.test",
                    resolve_url="https://idp.test/artifact",
                )


class TestManageNameID:
    def test_build_manage_name_id_request_post(self, private_key_pem):
        sp = SAML(
            role="sp",
            private_key=private_key_pem,
            entity_id="https://sp.test",
        )
        result = sp.build_manage_name_id_request(
            name_id="user@test.com",
            issuer="https://sp.test",
            destination="https://idp.test/nameid",
            binding="post",
        )
        import base64
        decoded = base64.b64decode(result).decode("utf-8")
        assert "ManageNameIDRequest" in decoded
        assert "user@test.com" in decoded

    def test_build_manage_name_id_request_change(self, private_key_pem):
        sp = SAML(
            role="sp",
            private_key=private_key_pem,
            entity_id="https://sp.test",
        )
        result = sp.build_manage_name_id_request(
            name_id="user@test.com",
            new_id="newuser@test.com",
            issuer="https://sp.test",
            destination="https://idp.test/nameid",
            binding="post",
        )
        import base64
        decoded = base64.b64decode(result).decode("utf-8")
        assert "NewID" in decoded
        assert "newuser@test.com" in decoded
        assert "ManageNameIDRequest" in decoded

    def test_build_manage_name_id_request_redirect(self, private_key_pem):
        sp = SAML(
            role="sp",
            private_key=private_key_pem,
            entity_id="https://sp.test",
        )
        url = sp.build_manage_name_id_request(
            name_id="user@test.com",
            issuer="https://sp.test",
            destination="https://idp.test/nameid",
            binding="redirect",
        )
        assert url.startswith("https://idp.test/nameid?")
        assert "SAMLRequest" in url

    def test_build_manage_name_id_without_key_raises(self):
        sp = SAML(role="sp")
        with pytest.raises(JamSAMLEmptyPrivateKey):
            sp.build_manage_name_id_request(
                name_id="user",
                issuer="https://sp.test",
                destination="https://idp.test/nameid",
            )

    def test_parse_manage_name_id_request(self, private_key_pem, public_key_pem):
        sp = SAML(
            role="sp",
            private_key=private_key_pem,
            entity_id="https://sp.test",
        )
        encoded = sp.build_manage_name_id_request(
            name_id="user@test.com",
            new_id="newuser@test.com",
            issuer="https://sp.test",
            destination="https://idp.test/nameid",
            binding="post",
        )
        idp = SAML(
            role="idp",
            sp_public_key=public_key_pem,
        )
        result = idp.parse_manage_name_id_request(
            encoded, binding="post"
        )
        assert result.issuer == "https://sp.test"
        assert result.name_id == "user@test.com"
        assert result.new_id == "newuser@test.com"

    def test_parse_manage_name_id_request_terminate(
        self, private_key_pem, public_key_pem
    ):
        sp = SAML(
            role="sp",
            private_key=private_key_pem,
            entity_id="https://sp.test",
        )
        encoded = sp.build_manage_name_id_request(
            name_id="user@test.com",
            issuer="https://sp.test",
            destination="https://idp.test/nameid",
            binding="post",
        )
        idp = SAML(
            role="idp",
            sp_public_key=public_key_pem,
        )
        result = idp.parse_manage_name_id_request(
            encoded, binding="post"
        )
        assert result.new_id is None

    def test_parse_manage_name_id_request_wrong_issuer(
        self, private_key_pem, public_key_pem
    ):
        sp = SAML(
            role="sp",
            private_key=private_key_pem,
            entity_id="https://sp.test",
        )
        encoded = sp.build_manage_name_id_request(
            name_id="user",
            issuer="https://sp.test",
            destination="https://idp.test/nameid",
            binding="post",
        )
        idp = SAML(
            role="idp",
            sp_public_key=public_key_pem,
        )
        with pytest.raises(JamSAMLInvalidIssuer):
            idp.parse_manage_name_id_request(
                encoded, binding="post", issuer="https://evil.test"
            )

    def test_build_manage_name_id_response_post(self, private_key_pem):
        idp = SAML(
            role="idp",
            private_key=private_key_pem,
            entity_id="https://idp.test",
        )
        result = idp.build_manage_name_id_response(
            in_response_to="_req_abc",
            issuer="https://idp.test",
            destination="https://sp.test/nameid",
            binding="post",
        )
        import base64
        decoded = base64.b64decode(result).decode("utf-8")
        assert "ManageNameIDResponse" in decoded
        assert "_req_abc" in decoded

    def test_build_manage_name_id_response_custom_status(
        self, private_key_pem
    ):
        idp = SAML(
            role="idp",
            private_key=private_key_pem,
            entity_id="https://idp.test",
        )
        from jam.saml.xml import STATUS_REQUESTER
        result = idp.build_manage_name_id_response(
            in_response_to="_req_abc",
            issuer="https://idp.test",
            destination="https://sp.test/nameid",
            status_code=STATUS_REQUESTER,
            binding="post",
        )
        import base64
        decoded = base64.b64decode(result).decode("utf-8")
        assert STATUS_REQUESTER in decoded

    def test_parse_manage_name_id_response(
        self, private_key_pem, public_key_pem
    ):
        idp = SAML(
            role="idp",
            private_key=private_key_pem,
            entity_id="https://idp.test",
        )
        encoded = idp.build_manage_name_id_response(
            in_response_to="_req_abc",
            issuer="https://idp.test",
            destination="https://sp.test/nameid",
            binding="post",
        )
        sp = SAML(
            role="sp",
            idp_public_key=public_key_pem,
        )
        result = sp.parse_manage_name_id_response(
            encoded, binding="post"
        )
        assert result.issuer == "https://idp.test"
        assert result.in_response_to == "_req_abc"
        assert result.status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"

    def test_parse_manage_name_id_response_wrong_issuer(
        self, private_key_pem, public_key_pem
    ):
        idp = SAML(
            role="idp",
            private_key=private_key_pem,
            entity_id="https://idp.test",
        )
        encoded = idp.build_manage_name_id_response(
            in_response_to="_req_abc",
            issuer="https://idp.test",
            destination="https://sp.test/nameid",
            binding="post",
        )
        sp = SAML(
            role="sp",
            idp_public_key=public_key_pem,
        )
        with pytest.raises(JamSAMLInvalidIssuer):
            sp.parse_manage_name_id_response(
                encoded, binding="post", issuer="https://evil.test"
            )

# -*- coding: utf-8 -*-

import pytest

from jam.exceptions import (
    JamConfigurationError,
    JamSAMLEmptyPrivateKey,
    JamSAMLExpired,
    JamSAMLInvalidAudience,
    JamSAMLInvalidDestination,
    JamSAMLInvalidIssuer,
    JamSAMLInvalidRecipient,
    JamSAMLNotYetValid,
    JamSAMLReplayDetected,
    JamSAMLResponseCorrelationError,
    JamSAMLSOAPError,
    JamSAMLValidationError,
)
from jam.saml import SAML


def test_saml_exceptions_are_publicly_exported():
    from jam.exceptions import __all__ as exception_exports

    assert {
        "JamSAMLInvalidDestination",
        "JamSAMLInvalidRecipient",
        "JamSAMLReplayDetected",
        "JamSAMLResponseCorrelationError",
        "JamSAMLSOAPError",
    } <= set(exception_exports)


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

    @pytest.mark.parametrize("allow_unsolicited", [None, 0, 1, "false"])
    def test_allow_unsolicited_requires_boolean(self, allow_unsolicited):
        with pytest.raises(JamConfigurationError) as exc_info:
            SAML(allow_unsolicited=allow_unsolicited)

        assert (
            exc_info.value.error_code
            == "configuration.saml.invalid_allow_unsolicited"
        )

    def test_shared_id_store_requires_shared_lock(self):
        with pytest.raises(JamConfigurationError) as exc_info:
            SAML(id_store={})

        assert (
            exc_info.value.error_code
            == "configuration.saml.missing_id_store_lock"
        )

    def test_deprecated_factory_forwards_custom_options_and_safe_default(
        self,
        monkeypatch,
    ):
        from jam.saml import create_instance
        from jam.utils import config_maker

        class CustomSAML:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

        monkeypatch.setattr(
            config_maker,
            "__module_loader__",
            lambda _path: CustomSAML,
        )

        with pytest.warns(DeprecationWarning):
            custom = create_instance(
                custom_module="tests.CustomSAML",
                custom_option="value",
            )

        assert custom.kwargs["allow_unsolicited"] is False
        assert custom.kwargs["custom_option"] == "value"

    def test_deprecated_factory_uses_supplied_replay_state(self):
        from threading import RLock

        from jam.saml import create_instance

        store = {}
        lock = RLock()

        with pytest.warns(DeprecationWarning):
            saml = create_instance(
                id_store=store,
                id_store_lock=lock,
            )

        assert saml._id_store is store
        assert saml._id_store_lock is lock


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
            "<saml:Issuer>https://sp.test</saml:Issuer>"
            "</samlp:AuthnRequest>"
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
        assert (
            result.status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"
        )

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
            idp.parse_logout_response(
                encoded, binding="post", issuer="https://evil.test"
            )


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
        from xml.etree import ElementTree as ET

        from jam.saml.binding import decode_post

        request = sp.prepare_authn_request(
            "https://idp.test/sso",
            binding="post",
        )
        request_id = ET.fromstring(decode_post(request)).get("ID")
        xml_str = idp.build_response(
            subject="user@test.com",
            attributes={"email": "user@test.com"},
            issuer="https://idp.test",
            audience="https://sp.test",
            destination="https://sp.test/acs",
            in_response_to=request_id,
        )

        from jam.saml.binding import encode_post

        encoded = encode_post(xml_str)

        result = sp.parse_response(
            encoded,
            binding="post",
            audience="https://sp.test",
            issuer="https://idp.test",
            expected_in_response_to=request_id,
        )

        assert result.id is not None
        assert result.issuer == "https://idp.test"
        assert (
            result.status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"
        )
        assert result.in_response_to == request_id

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
            destination="https://sp.test/acs",
        )

        from jam.saml.binding import encode_redirect

        encoded = encode_redirect(xml_str)

        result = sp.parse_response(
            encoded,
            binding="redirect",
            audience="https://sp.test",
            issuer="https://idp.test",
            allow_unsolicited=True,
        )
        assert result.assertion is not None
        assert result.assertion.subject.name_id == "user2@test.com"

    def test_mismatched_audience_raises(self, idp, sp):
        xml_str = idp.build_response(
            subject="user@test.com",
            attributes={},
            issuer="https://idp.test",
            audience="https://other-sp.test",
            destination="https://sp.test/acs",
        )
        from jam.saml.binding import encode_post

        encoded = encode_post(xml_str)

        with pytest.raises(JamSAMLInvalidAudience):
            sp.parse_response(
                encoded,
                binding="post",
                audience="https://sp.test",
                allow_unsolicited=True,
            )

    def test_expired_assertion(self, private_key_pem, public_key_pem):
        idp_zero = SAML(
            role="idp",
            private_key=private_key_pem,
            default_exp=-60,
        )
        sp = SAML(
            role="sp",
            acs_url="https://sp.test/acs",
            idp_public_key=public_key_pem,
            allowed_clock_skew=0,
        )
        xml_str = idp_zero.build_response(
            subject="user@test.com",
            attributes={},
            issuer="https://idp.test",
            audience="https://sp.test",
            destination="https://sp.test/acs",
        )

        from jam.saml.binding import encode_post

        encoded = encode_post(xml_str)

        with pytest.raises(JamSAMLExpired):
            sp.parse_response(
                encoded,
                binding="post",
                audience="https://sp.test",
                allow_unsolicited=True,
            )


class TestHardening:
    @pytest.mark.parametrize(
        ("configured_acs", "configured_audience", "expected_code"),
        [
            (None, "https://sp.test", "configuration.saml.missing_acs_url"),
            (
                "https://sp.test/acs",
                None,
                "configuration.saml.missing_audience",
            ),
        ],
    )
    def test_sp_expectations_are_required(
        self,
        key_pair,
        configured_acs,
        configured_audience,
        expected_code,
    ):
        from jam.saml.binding import encode_post

        idp = SAML(role="idp", private_key=key_pair["private"])
        sp = SAML(
            role="sp",
            acs_url=configured_acs,
            idp_public_key=key_pair["public"],
            allow_unsolicited=True,
        )
        response = idp.build_response(
            subject="user@test.com",
            attributes={},
            issuer="https://idp.test",
            audience="https://sp.test",
            destination="https://sp.test/acs",
        )

        with pytest.raises(JamConfigurationError) as exc_info:
            sp.parse_response(
                encode_post(response),
                audience=configured_audience,
            )

        assert exc_info.value.error_code == expected_code

    def test_unsolicited_response_is_rejected_by_default(self, key_pair):
        from jam.saml.binding import encode_post

        idp = SAML(role="idp", private_key=key_pair["private"])
        sp = SAML(role="sp", idp_public_key=key_pair["public"])
        response = idp.build_response(
            subject="user@test.com",
            attributes={},
            issuer="https://idp.test",
            audience="https://sp.test",
        )

        with pytest.raises(JamSAMLResponseCorrelationError) as exc_info:
            sp.parse_response(
                encode_post(response),
                audience="https://sp.test",
            )

        assert exc_info.value.details == {"reason": "missing_in_response_to"}

    def test_unsolicited_response_requires_explicit_opt_in(self, key_pair):
        from jam.saml.binding import encode_post

        idp = SAML(role="idp", private_key=key_pair["private"])
        sp = SAML(
            role="sp",
            acs_url="https://sp.test/acs",
            idp_public_key=key_pair["public"],
            allow_unsolicited=True,
        )
        response = idp.build_response(
            subject="user@test.com",
            attributes={},
            issuer="https://idp.test",
            audience="https://sp.test",
            destination="https://sp.test/acs",
        )

        parsed = sp.parse_response(
            encode_post(response),
            audience="https://sp.test",
        )

        assert parsed.assertion is not None

    def test_per_call_unsolicited_override_requires_boolean(self, key_pair):
        from jam.saml.binding import encode_post

        idp = SAML(role="idp", private_key=key_pair["private"])
        sp = SAML(role="sp", idp_public_key=key_pair["public"])
        response = idp.build_response(
            subject="user@test.com",
            attributes={},
            issuer="https://idp.test",
            audience="https://sp.test",
        )

        with pytest.raises(JamConfigurationError):
            sp.parse_response(
                encode_post(response),
                audience="https://sp.test",
                allow_unsolicited="true",
            )

    def test_unknown_in_response_to_is_rejected(self, key_pair):
        from jam.saml.binding import encode_post

        idp = SAML(role="idp", private_key=key_pair["private"])
        sp = SAML(
            role="sp",
            idp_public_key=key_pair["public"],
            allow_unsolicited=True,
        )
        response = idp.build_response(
            subject="user@test.com",
            attributes={},
            issuer="https://idp.test",
            audience="https://sp.test",
            in_response_to="_unknown",
        )

        with pytest.raises(JamSAMLResponseCorrelationError) as exc_info:
            sp.parse_response(
                encode_post(response),
                audience="https://sp.test",
                expected_in_response_to="_unknown",
            )

        assert exc_info.value.details == {"reason": "unknown_in_response_to"}

    def test_outer_and_assertion_in_response_to_must_match(self, key_pair):
        from xml.etree import ElementTree as ET

        from jam.saml.binding import decode_post, encode_post

        idp = SAML(role="idp", private_key=key_pair["private"])
        sp = SAML(
            role="sp",
            acs_url="https://sp.test/acs",
            idp_public_key=key_pair["public"],
        )

        def prepare_request() -> str:
            request = sp.prepare_authn_request(
                "https://idp.test/sso",
                binding="post",
            )
            request_id = ET.fromstring(decode_post(request)).get("ID")
            assert request_id is not None
            return request_id

        first_request = prepare_request()
        second_request = prepare_request()
        response = idp.build_response(
            subject="user@test.com",
            attributes={},
            issuer="https://idp.test",
            audience="https://sp.test",
            destination="https://sp.test/acs",
            in_response_to=first_request,
        )

        with pytest.raises(JamSAMLResponseCorrelationError) as exc_info:
            sp.parse_response(
                encode_post(response),
                audience="https://sp.test",
                expected_in_response_to=second_request,
            )

        assert exc_info.value.details == {
            "reason": "in_response_to_mismatch"
        }

        tampered = ET.fromstring(response)
        tampered.set("InResponseTo", second_request)

        with pytest.raises(JamSAMLResponseCorrelationError) as exc_info:
            sp.parse_response(
                encode_post(ET.tostring(tampered, encoding="unicode")),
                audience="https://sp.test",
                expected_in_response_to=second_request,
            )

        assert exc_info.value.details == {
            "reason": "assertion_in_response_to_mismatch"
        }

        parsed = sp.parse_response(
            encode_post(response),
            audience="https://sp.test",
            expected_in_response_to=first_request,
        )
        assert parsed.in_response_to == first_request

        second_response = idp.build_response(
            subject="user@test.com",
            attributes={},
            issuer="https://idp.test",
            audience="https://sp.test",
            destination="https://sp.test/acs",
            in_response_to=second_request,
        )
        assert (
            sp.parse_response(
                encode_post(second_response),
                audience="https://sp.test",
                expected_in_response_to=second_request,
            ).in_response_to
            == second_request
        )

    def test_assertion_replay_with_new_response_id_is_rejected(self, key_pair):
        from xml.etree import ElementTree as ET

        from jam.saml.binding import encode_post

        idp = SAML(role="idp", private_key=key_pair["private"])
        sp = SAML(
            role="sp",
            acs_url="https://sp.test/acs",
            idp_public_key=key_pair["public"],
            allow_unsolicited=True,
        )
        response = idp.build_response(
            subject="user@test.com",
            attributes={},
            issuer="https://idp.test",
            audience="https://sp.test",
            destination="https://sp.test/acs",
        )
        sp.parse_response(
            encode_post(response),
            audience="https://sp.test",
        )

        replay = ET.fromstring(response)
        replay.set("ID", "_attacker-controlled-response-id")

        with pytest.raises(JamSAMLReplayDetected):
            sp.parse_response(
                encode_post(ET.tostring(replay, encoding="unicode")),
                audience="https://sp.test",
            )

    def test_unsigned_error_response_is_rejected_without_consuming_request(
        self,
        key_pair,
    ):
        from xml.etree import ElementTree as ET

        from jam.saml.binding import encode_post
        from jam.saml.xml import NS_SAML

        idp = SAML(role="idp", private_key=key_pair["private"])
        sp = SAML(
            role="sp",
            acs_url="https://sp.test/acs",
            idp_public_key=key_pair["public"],
        )
        request_id = "_failed-login-request"
        sp.prepare_authn_request(
            "https://idp.test/sso",
            request_id=request_id,
        )
        response = ET.fromstring(
            idp.build_response(
                subject="user@test.com",
                attributes={},
                issuer="https://idp.test",
                audience="https://sp.test",
                destination="https://sp.test/acs",
                in_response_to=request_id,
            )
        )
        assertion = response.find(f"{{{NS_SAML}}}Assertion")
        assert assertion is not None
        response.remove(assertion)
        encoded = encode_post(ET.tostring(response, encoding="unicode"))

        with pytest.raises(
            JamSAMLValidationError,
            match="no signed assertion",
        ):
            sp.parse_response(
                encoded,
                audience="https://sp.test",
                expected_in_response_to=request_id,
            )

        assert sp._pending_request_key(request_id) in sp._id_store

    def test_response_destination_is_required(self, key_pair):
        from jam.saml.binding import encode_post

        idp = SAML(role="idp", private_key=key_pair["private"])
        sp = SAML(
            role="sp",
            acs_url="https://sp.test/acs",
            idp_public_key=key_pair["public"],
            allow_unsolicited=True,
        )
        response = idp.build_response(
            subject="user@test.com",
            attributes={},
            issuer="https://idp.test",
            audience="https://sp.test",
        )

        with pytest.raises(JamSAMLInvalidDestination) as exc_info:
            sp.parse_response(
                encode_post(response),
                audience="https://sp.test",
            )

        assert exc_info.value.details == {"reason": "missing_destination"}

    @pytest.mark.parametrize(
        ("scope", "expected_exception"),
        [
            ("audience", JamSAMLInvalidAudience),
            ("recipient", JamSAMLInvalidRecipient),
        ],
    )
    def test_signed_assertion_requires_sp_scope(
        self,
        key_pair,
        scope,
        expected_exception,
    ):
        from xml.etree import ElementTree as ET

        from jam.saml.binding import encode_post
        from jam.saml.signature import sign_assertion
        from jam.saml.xml import NS_DS, NS_SAML

        idp = SAML(role="idp", private_key=key_pair["private"])
        sp = SAML(
            role="sp",
            entity_id="https://sp.test",
            acs_url="https://sp.test/acs",
            idp_public_key=key_pair["public"],
            allow_unsolicited=True,
        )
        response = ET.fromstring(
            idp.build_response(
                subject="user@test.com",
                attributes={},
                issuer="https://idp.test",
                audience="https://sp.test",
                destination="https://sp.test/acs",
            )
        )
        assertion = response.find(f"{{{NS_SAML}}}Assertion")
        assert assertion is not None
        signature = assertion.find(f"{{{NS_DS}}}Signature")
        assert signature is not None
        assertion.remove(signature)
        if scope == "audience":
            conditions = assertion.find(f"{{{NS_SAML}}}Conditions")
            assert conditions is not None
            restriction = conditions.find(f"{{{NS_SAML}}}AudienceRestriction")
            assert restriction is not None
            conditions.remove(restriction)
        else:
            confirmation = assertion.find(
                f".//{{{NS_SAML}}}SubjectConfirmationData"
            )
            assert confirmation is not None
            del confirmation.attrib["Recipient"]
        sign_assertion(assertion, idp._private_key)

        with pytest.raises(expected_exception):
            sp.parse_response(
                encode_post(ET.tostring(response, encoding="unicode")),
                audience="https://sp.test",
            )

    def test_every_audience_restriction_must_allow_the_sp(self, key_pair):
        from xml.etree import ElementTree as ET

        from jam.saml.binding import encode_post
        from jam.saml.signature import sign_assertion
        from jam.saml.xml import NS_DS, NS_SAML, sub_element

        idp = SAML(role="idp", private_key=key_pair["private"])
        sp = SAML(
            role="sp",
            entity_id="https://sp.test",
            acs_url="https://sp.test/acs",
            idp_public_key=key_pair["public"],
            allow_unsolicited=True,
        )
        response = ET.fromstring(
            idp.build_response(
                subject="user@test.com",
                attributes={},
                issuer="https://idp.test",
                audience="https://sp.test",
                destination="https://sp.test/acs",
            )
        )
        assertion = response.find(f"{{{NS_SAML}}}Assertion")
        assert assertion is not None
        signature = assertion.find(f"{{{NS_DS}}}Signature")
        assert signature is not None
        assertion.remove(signature)
        conditions = assertion.find(f"{{{NS_SAML}}}Conditions")
        assert conditions is not None
        restriction = sub_element(
            conditions,
            "AudienceRestriction",
            NS_SAML,
        )
        sub_element(
            restriction,
            "Audience",
            NS_SAML,
            text="https://other-sp.test",
        )
        sign_assertion(assertion, idp._private_key)

        with pytest.raises(JamSAMLInvalidAudience):
            sp.parse_response(
                encode_post(ET.tostring(response, encoding="unicode")),
                audience="https://sp.test",
            )

    @pytest.mark.parametrize(
        ("mutation", "expected_exception"),
        [
            ("non_bearer", JamSAMLValidationError),
            ("missing_method", JamSAMLValidationError),
            ("expired", JamSAMLExpired),
            ("not_yet_valid", JamSAMLNotYetValid),
        ],
    )
    def test_subject_confirmation_constraints_are_enforced(
        self,
        key_pair,
        mutation,
        expected_exception,
    ):
        from datetime import datetime, timedelta, timezone
        from xml.etree import ElementTree as ET

        from jam.saml.binding import encode_post
        from jam.saml.signature import sign_assertion
        from jam.saml.xml import NS_DS, NS_SAML, fmt_instant

        idp = SAML(role="idp", private_key=key_pair["private"])
        sp = SAML(
            role="sp",
            acs_url="https://sp.test/acs",
            idp_public_key=key_pair["public"],
            allowed_clock_skew=0,
            allow_unsolicited=True,
        )
        response = ET.fromstring(
            idp.build_response(
                subject="user@test.com",
                attributes={},
                issuer="https://idp.test",
                audience="https://sp.test",
                destination="https://sp.test/acs",
            )
        )
        assertion = response.find(f"{{{NS_SAML}}}Assertion")
        assert assertion is not None
        signature = assertion.find(f"{{{NS_DS}}}Signature")
        assert signature is not None
        assertion.remove(signature)
        confirmation = assertion.find(
            f".//{{{NS_SAML}}}SubjectConfirmation"
        )
        confirmation_data = assertion.find(
            f".//{{{NS_SAML}}}SubjectConfirmationData"
        )
        assert confirmation is not None
        assert confirmation_data is not None
        now = datetime.now(timezone.utc)
        if mutation == "non_bearer":
            confirmation.set(
                "Method",
                "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key",
            )
        elif mutation == "missing_method":
            del confirmation.attrib["Method"]
        elif mutation == "expired":
            confirmation_data.set(
                "NotOnOrAfter",
                fmt_instant(now - timedelta(minutes=1)),
            )
        else:
            confirmation_data.set(
                "NotBefore",
                fmt_instant(now + timedelta(minutes=1)),
            )
        sign_assertion(assertion, idp._private_key)

        with pytest.raises(expected_exception):
            sp.parse_response(
                encode_post(ET.tostring(response, encoding="unicode")),
                audience="https://sp.test",
            )

    def test_later_valid_bearer_confirmation_is_accepted(self, key_pair):
        from copy import deepcopy
        from xml.etree import ElementTree as ET

        from jam.saml.binding import encode_post
        from jam.saml.signature import sign_assertion
        from jam.saml.xml import NS_DS, NS_SAML

        idp = SAML(role="idp", private_key=key_pair["private"])
        sp = SAML(
            role="sp",
            entity_id="https://sp.test",
            acs_url="https://sp.test/acs",
            idp_public_key=key_pair["public"],
            allow_unsolicited=True,
        )
        response = ET.fromstring(
            idp.build_response(
                subject="user@test.com",
                attributes={},
                issuer="https://idp.test",
                audience="https://sp.test",
                destination="https://sp.test/acs",
            )
        )
        assertion = response.find(f"{{{NS_SAML}}}Assertion")
        assert assertion is not None
        signature = assertion.find(f"{{{NS_DS}}}Signature")
        assert signature is not None
        assertion.remove(signature)
        subject = assertion.find(f"{{{NS_SAML}}}Subject")
        confirmation = assertion.find(
            f".//{{{NS_SAML}}}SubjectConfirmation"
        )
        assert subject is not None
        assert confirmation is not None
        valid_confirmation = deepcopy(confirmation)
        del confirmation.attrib["Method"]
        subject.append(valid_confirmation)
        sign_assertion(assertion, idp._private_key)

        parsed = sp.parse_response(
            encode_post(ET.tostring(response, encoding="unicode")),
        )

        assert parsed.assertion is not None
        assert (
            parsed.assertion.subject.subject_confirmation_method
            == "urn:oasis:names:tc:SAML:2.0:cm:bearer"
        )

    def test_replay_marker_outlives_assertion_acceptance_window(
        self,
        key_pair,
    ):
        from xml.etree import ElementTree as ET

        from jam.saml.binding import encode_post
        from jam.saml.xml import NS_SAML, parse_instant

        idp = SAML(
            role="idp",
            private_key=key_pair["private"],
            default_exp=600,
        )
        sp = SAML(
            role="sp",
            acs_url="https://sp.test/acs",
            idp_public_key=key_pair["public"],
            allowed_clock_skew=120,
            allow_unsolicited=True,
            replay_ttl=1,
        )
        response = idp.build_response(
            subject="user@test.com",
            attributes={},
            issuer="https://idp.test",
            audience="https://sp.test",
            destination="https://sp.test/acs",
        )
        root = ET.fromstring(response)
        assertion = root.find(f"{{{NS_SAML}}}Assertion")
        assert assertion is not None
        assertion_id = assertion.get("ID")
        conditions = assertion.find(f"{{{NS_SAML}}}Conditions")
        assert assertion_id is not None
        assert conditions is not None
        acceptance_end = (
            parse_instant(conditions.get("NotOnOrAfter", "")).timestamp()
            + 120
        )

        sp.parse_response(
            encode_post(response),
            audience="https://sp.test",
        )

        consumed_key = sp._consumed_key(assertion_id)
        assert sp._id_store[consumed_key] >= acceptance_end
        sp._purge_stale_ids(now=acceptance_end - 1)
        assert consumed_key in sp._id_store

    def test_clock_skew_tolerance(self, private_key_pem, public_key_pem):
        from datetime import datetime, timezone
        from jam.saml.xml import fmt_instant

        sp = SAML(
            role="sp",
            acs_url="https://sp.test/acs",
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
        response.set("Destination", "https://sp.test/acs")
        sub_element(response, "Issuer", NS_SAML, text="https://idp.test")
        status = make_element("Status", NS_SAMLP)
        response.append(status)
        sub_element(
            status,
            "StatusCode",
            NS_SAMLP,
            attrib={"Value": "urn:oasis:names:tc:SAML:2.0:status:Success"},
        )

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
            subj_conf,
            "SubjectConfirmationData",
            NS_SAML,
            attrib={
                "Recipient": "https://sp.test/acs",
                "NotOnOrAfter": fmt_instant(),
            },
        )

        conditions = make_element("Conditions", NS_SAML)
        conditions.set("NotBefore", future)
        conditions.set("NotOnOrAfter", fmt_instant())
        assertion.append(conditions)
        aud_restriction = sub_element(
            conditions, "AudienceRestriction", NS_SAML
        )
        sub_element(
            aud_restriction, "Audience", NS_SAML, text="https://sp.test"
        )

        sign_assertion(assertion, idp._private_key)

        xml_str = ET.tostring(response, encoding="unicode")
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

    def test_clock_skew_rejects_outside(self, private_key_pem, public_key_pem):
        from datetime import datetime, timezone
        from jam.saml.xml import fmt_instant

        sp = SAML(
            role="sp",
            acs_url="https://sp.test/acs",
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
        response.set("Destination", "https://sp.test/acs")
        sub_element(response, "Issuer", NS_SAML, text="https://idp.test")
        status = make_element("Status", NS_SAMLP)
        response.append(status)
        sub_element(
            status,
            "StatusCode",
            NS_SAMLP,
            attrib={"Value": "urn:oasis:names:tc:SAML:2.0:status:Success"},
        )

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
            subj_conf,
            "SubjectConfirmationData",
            NS_SAML,
            attrib={
                "Recipient": "https://sp.test/acs",
                "NotOnOrAfter": fmt_instant(),
            },
        )

        conditions = make_element("Conditions", NS_SAML)
        conditions.set("NotBefore", far_future)
        conditions.set("NotOnOrAfter", fmt_instant())
        assertion.append(conditions)
        aud_restriction = sub_element(
            conditions, "AudienceRestriction", NS_SAML
        )
        sub_element(
            aud_restriction, "Audience", NS_SAML, text="https://sp.test"
        )

        sign_assertion(assertion, idp._private_key)

        xml_str = ET.tostring(response, encoding="unicode")
        from jam.saml.binding import encode_post

        encoded = encode_post(xml_str)

        with pytest.raises(JamSAMLNotYetValid):
            sp.parse_response(
                encoded,
                binding="post",
                audience="https://sp.test",
                issuer="https://idp.test",
                allow_unsolicited=True,
            )

    def test_replay_detected(self, key_pair):
        from threading import RLock

        private = key_pair["private"]
        public = key_pair["public"]
        idp = SAML(
            role="idp",
            private_key=private,
            entity_id="https://idp.test",
        )
        sp = SAML(
            role="sp",
            acs_url="https://sp.test/acs",
            idp_public_key=public,
            id_store={},
            id_store_lock=RLock(),
        )
        xml_str = idp.build_response(
            subject="user@test.com",
            attributes={"email": "user@test.com"},
            issuer="https://idp.test",
            audience="https://sp.test",
            destination="https://sp.test/acs",
        )
        from jam.saml.binding import encode_post

        encoded = encode_post(xml_str)

        result = sp.parse_response(
            encoded,
            binding="post",
            audience="https://sp.test",
            allow_unsolicited=True,
        )
        assert result.assertion is not None

        with pytest.raises(JamSAMLReplayDetected):
            sp.parse_response(
                encoded,
                binding="post",
                audience="https://sp.test",
                allow_unsolicited=True,
            )

    def test_legacy_replay_timestamps_survive_rolling_upgrade(self):
        from datetime import datetime, timezone
        from threading import RLock

        now = datetime.now(timezone.utc).timestamp()
        store = {"_legacy-response": now - 10}
        sp = SAML(
            id_store=store,
            id_store_lock=RLock(),
            replay_ttl=300,
        )

        sp._purge_stale_ids(now=now)

        assert "_legacy-response" in store
        with pytest.raises(JamSAMLReplayDetected):
            sp._assert_not_replayed("_legacy-response")

    def test_xxe_protection(self):
        from jam.exceptions.saml import JamSAMLValidationError
        from jam.saml.xml import safe_fromstring

        malicious = (
            '<?xml version="1.0"?>'
            '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
            "<root>&xxe;</root>"
        )
        with pytest.raises(JamSAMLValidationError):
            safe_fromstring(malicious)

    def test_want_assertions_signed_false(
        self, private_key_pem, public_key_pem
    ):
        from jam.saml.xml import make_element, NS_SAMLP, NS_SAML, sub_element
        import xml.etree.ElementTree as ET
        from jam.saml.xml import fmt_instant

        sp = SAML(
            role="sp",
            acs_url="https://sp.test/acs",
            want_assertions_signed=False,
        )
        response = make_element("Response", NS_SAMLP)
        response.set("ID", "_r_unsigned")
        response.set("Version", "2.0")
        response.set("IssueInstant", fmt_instant())
        response.set("Destination", "https://sp.test/acs")
        sub_element(response, "Issuer", NS_SAML, text="https://idp.test")
        status = make_element("Status", NS_SAMLP)
        response.append(status)
        sub_element(
            status,
            "StatusCode",
            NS_SAMLP,
            attrib={"Value": "urn:oasis:names:tc:SAML:2.0:status:Success"},
        )

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
            subj_conf,
            "SubjectConfirmationData",
            NS_SAML,
            attrib={
                "Recipient": "https://sp.test/acs",
                "NotOnOrAfter": fmt_instant(),
            },
        )

        conditions = make_element("Conditions", NS_SAML)
        conditions.set("NotBefore", fmt_instant())
        conditions.set("NotOnOrAfter", fmt_instant())
        assertion.append(conditions)
        aud_restriction = sub_element(
            conditions, "AudienceRestriction", NS_SAML
        )
        sub_element(
            aud_restriction, "Audience", NS_SAML, text="https://sp.test"
        )

        xml_str = ET.tostring(response, encoding="unicode")
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
        response.set("Destination", "https://sp.test/acs")
        sub_element(response, "Issuer", NS_SAML, text="https://idp.test")
        status = make_element("Status", NS_SAMLP)
        response.append(status)
        sub_element(
            status,
            "StatusCode",
            NS_SAMLP,
            attrib={"Value": "urn:oasis:names:tc:SAML:2.0:status:Success"},
        )

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
            subj_conf,
            "SubjectConfirmationData",
            NS_SAML,
            attrib={
                "Recipient": "https://evil.test/acs",
                "NotOnOrAfter": fmt_instant(),
            },
        )

        conditions = make_element("Conditions", NS_SAML)
        conditions.set("NotBefore", fmt_instant())
        conditions.set("NotOnOrAfter", fmt_instant())
        assertion.append(conditions)
        aud_restriction = sub_element(
            conditions, "AudienceRestriction", NS_SAML
        )
        sub_element(
            aud_restriction, "Audience", NS_SAML, text="https://sp.test"
        )

        sign_assertion(assertion, idp._private_key)

        xml_str = ET.tostring(response, encoding="unicode")
        from jam.saml.binding import encode_post

        encoded = encode_post(xml_str)

        with pytest.raises(JamSAMLInvalidRecipient):
            sp.parse_response(
                encoded,
                binding="post",
                audience="https://sp.test",
                issuer="https://idp.test",
                allow_unsolicited=True,
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

    def test_attribute_query_no_attributes_requested(self, private_key_pem):
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
        assert "Attribute Name=" not in decoded

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
            private_key=private_key_pem,
            idp_public_key=public_key_pem,
            entity_id="https://sp.test",
            acs_url="https://sp.test/acs",
        )
        from xml.etree import ElementTree as ET

        from jam.saml.binding import decode_post

        query = sp.build_attribute_query(
            subject="user@test.com",
            issuer="https://sp.test",
            destination="https://idp.test/attributes",
            binding="post",
        )
        query_id = ET.fromstring(decode_post(query)).get("ID")
        xml_str = idp.build_attribute_query_response(
            in_response_to=query_id,
            subject="user@test.com",
            attributes={"email": "user@test.com"},
            issuer="https://idp.test",
            audience="https://sp.test",
            destination="https://sp.test/acs",
        )
        from jam.saml.binding import encode_post

        encoded = encode_post(xml_str)
        result = sp.parse_attribute_query_response(
            encoded,
            binding="post",
            audience="https://sp.test",
            issuer="https://idp.test",
            expected_in_response_to=query_id,
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
            '<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
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
            '<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
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

    def test_resolve_artifact_soap_roundtrip(
        self, private_key_pem, public_key_pem
    ):
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
            '<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
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
                "<SOAP-ENV:Envelope xmlns:SOAP-ENV="
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

    def test_resolve_artifact_malformed_response_raises(self, private_key_pem):
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

    def test_parse_manage_name_id_request(
        self, private_key_pem, public_key_pem
    ):
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
        result = idp.parse_manage_name_id_request(encoded, binding="post")
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
        result = idp.parse_manage_name_id_request(encoded, binding="post")
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

    def test_build_manage_name_id_response_custom_status(self, private_key_pem):
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
        result = sp.parse_manage_name_id_response(encoded, binding="post")
        assert result.issuer == "https://idp.test"
        assert result.in_response_to == "_req_abc"
        assert (
            result.status_code == "urn:oasis:names:tc:SAML:2.0:status:Success"
        )

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

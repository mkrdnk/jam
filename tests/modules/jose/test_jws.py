# -*- coding: utf-8 -*-

import base64
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import pytest

from jam.exceptions import JamJWSVerificationError, JamJWTUnsupportedAlgorithm
from jam.exceptions.jose import JamJWSSigningError
from jam.jose import JWS
from jam.utils import generate_ecdsa_keypair, generate_rsa_key_pair


class TestJWSHMAC:
    @pytest.fixture
    def symmetric_key(self):
        return "SOME_JWT_KEY"

    def test_hs256_serialize_compact(self, symmetric_key):
        jws = JWS(alg="HS256", key=symmetric_key)
        token = jws.serialize_compact({"alg": "HS256"}, "test payload")
        assert token.count(".") == 2
        assert token.startswith("ey")

    def test_hs256_deserialize_compact(self, symmetric_key):
        jws = JWS(alg="HS256", key=symmetric_key)
        token = jws.serialize_compact({"alg": "HS256"}, "test payload")
        result = jws.deserialize_compact(token)
        assert result["header"]["alg"] == "HS256"
        assert result["payload"] == b"test payload"

    def test_hs384_serialize_compact(self, symmetric_key):
        jws = JWS(alg="HS384", key=symmetric_key)
        token = jws.serialize_compact({"alg": "HS384"}, "test payload")
        assert token.count(".") == 2

    def test_hs384_deserialize_compact(self, symmetric_key):
        jws = JWS(alg="HS384", key=symmetric_key)
        token = jws.serialize_compact({"alg": "HS384"}, "test payload")
        result = jws.deserialize_compact(token)
        assert result["header"]["alg"] == "HS384"

    def test_hs512_serialize_compact(self, symmetric_key):
        jws = JWS(alg="HS512", key=symmetric_key)
        token = jws.serialize_compact({"alg": "HS512"}, "test payload")
        assert token.count(".") == 2

    def test_hs512_deserialize_compact(self, symmetric_key):
        jws = JWS(alg="HS512", key=symmetric_key)
        token = jws.serialize_compact({"alg": "HS512"}, "test payload")
        result = jws.deserialize_compact(token)
        assert result["header"]["alg"] == "HS512"

    def test_hs256_sign_and_verify(self, symmetric_key):
        jws = JWS(alg="HS256", key=symmetric_key)
        token = jws.sign({"typ": "JWT"}, "test data")
        result = jws.verify(token)
        assert result["payload"] == b"test data"

    def test_hs256_with_dict_payload(self, symmetric_key):
        jws = JWS(alg="HS256", key=symmetric_key)
        token = jws.sign({"typ": "JWT"}, {"key": "value"})
        result = jws.verify(token)

        assert json.loads(result["payload"]) == {"key": "value"}


class TestJWSRSA:
    @pytest.fixture
    def rsa_key_pair(self):
        return generate_rsa_key_pair()

    def test_rs256_sign_and_verify(self, rsa_key_pair):
        jws = JWS(alg="RS256", key=rsa_key_pair["private"])
        token = jws.sign({"typ": "JWT"}, "test data")
        result = jws.verify(token)
        assert result["payload"] == b"test data"

    def test_rs256_verify_with_public_key(self, rsa_key_pair):
        jws_sign = JWS(alg="RS256", key=rsa_key_pair["private"])
        jws_verify = JWS(alg="RS256", key=rsa_key_pair["public"])
        token = jws_sign.sign({"typ": "JWT"}, "test data")
        result = jws_verify.verify(token)
        assert result["payload"] == b"test data"

    def test_rs384_sign_and_verify(self, rsa_key_pair):
        jws = JWS(alg="RS384", key=rsa_key_pair["private"])
        token = jws.sign({"typ": "JWT"}, "test data")
        result = jws.verify(token)
        assert result["payload"] == b"test data"

    def test_rs512_sign_and_verify(self, rsa_key_pair):
        jws = JWS(alg="RS512", key=rsa_key_pair["private"])
        token = jws.sign({"typ": "JWT"}, "test data")
        result = jws.verify(token)
        assert result["payload"] == b"test data"

    def test_sign_with_jwk(self, rsa_key_pair):
        jws = JWS(alg="RS256", key=rsa_key_pair["private"])
        token = jws.sign({"typ": "JWT"}, "test data")
        result = jws.verify(token)
        assert result["payload"] == b"test data"

    def test_ps256_interoperates_with_raw_cryptography(self, rsa_key_pair):
        private_key = serialization.load_pem_private_key(
            rsa_key_pair["private"].encode(), password=None
        )
        public_key = private_key.public_key()
        jws = JWS(alg="PS256", key=rsa_key_pair["private"])
        token = jws.sign({"typ": "JWT"}, "test data")
        protected_b64, payload_b64, signature_b64 = token.split(".")
        signing_input = f"{protected_b64}.{payload_b64}".encode()
        pss = padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=hashes.SHA256().digest_size,
        )

        public_key.verify(
            base64.urlsafe_b64decode(signature_b64 + "=="),
            signing_input,
            pss,
            hashes.SHA256(),
        )

        raw_signature = private_key.sign(signing_input, pss, hashes.SHA256())
        raw_token = (
            f"{protected_b64}.{payload_b64}."
            f"{base64.urlsafe_b64encode(raw_signature).rstrip(b'=').decode()}"
        )
        assert jws.verify(raw_token)["payload"] == b"test data"

        legacy_pss = padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        )
        legacy_signature = private_key.sign(
            signing_input,
            legacy_pss,
            hashes.SHA256(),
        )
        legacy_token = (
            f"{protected_b64}.{payload_b64}."
            f"{base64.urlsafe_b64encode(legacy_signature).rstrip(b'=').decode()}"
        )
        assert jws.verify(legacy_token)["payload"] == b"test data"


class TestJWSECDSA:
    @pytest.mark.parametrize(
        ("alg", "curve"),
        [("ES256", "P-256"), ("ES384", "P-384"), ("ES512", "P-521")],
    )
    def test_sign_and_verify(self, alg, curve):
        key_pair = generate_ecdsa_keypair(curve)
        jws = JWS(alg=alg, key=key_pair["private"])
        token = jws.sign({"typ": "JWT"}, "test data")
        result = jws.verify(token)
        assert result["payload"] == b"test data"

    def test_verify_with_public_key(self):
        key_pair = generate_ecdsa_keypair("P-256")
        jws_sign = JWS(alg="ES256", key=key_pair["private"])
        jws_verify = JWS(alg="ES256", key=key_pair["public"])
        token = jws_sign.sign({"typ": "JWT"}, "test data")
        result = jws_verify.verify(token)
        assert result["payload"] == b"test data"

    def test_rejects_curve_that_does_not_match_algorithm(self):
        key_pair = generate_ecdsa_keypair("P-384")
        with pytest.raises(
            JamJWSSigningError, match="ES256 requires secp256r1"
        ):
            JWS(alg="ES256", key=key_pair["private"]).sign({}, "test data")

    def test_verification_rejects_curve_that_does_not_match_algorithm(self):
        p256 = generate_ecdsa_keypair("P-256")
        token = JWS(alg="ES256", key=p256["private"]).sign({}, "test data")
        p384 = generate_ecdsa_keypair("P-384")

        with pytest.raises(JamJWSVerificationError, match="requires secp256r1"):
            JWS(alg="ES256", key=p384["public"]).verify(token)


class TestJWSValidation:
    @pytest.fixture
    def symmetric_key(self):
        return "SOME_JWT_KEY"

    def test_invalid_algorithm(self, symmetric_key):
        with pytest.raises(JamJWTUnsupportedAlgorithm):
            JWS(alg="INVALID", key=symmetric_key)

    def test_invalid_jws_format(self, symmetric_key):
        jws = JWS(alg="HS256", key=symmetric_key)
        with pytest.raises(JamJWSVerificationError):
            jws.deserialize_compact("invalid.token")

    def test_invalid_jws_format_no_dots(self, symmetric_key):
        jws = JWS(alg="HS256", key=symmetric_key)
        with pytest.raises(JamJWSVerificationError):
            jws.deserialize_compact("invalid")

    def test_algorithm_mismatch(self, symmetric_key):
        jws_hs256 = JWS(alg="HS256", key=symmetric_key)
        jws_hs384 = JWS(alg="HS384", key=symmetric_key)
        token = jws_hs256.sign({"typ": "JWT"}, "test data")
        with pytest.raises(JamJWSVerificationError):
            jws_hs384.deserialize_compact(token)

    def test_signature_verification_failed(self, symmetric_key):
        jws = JWS(alg="HS256", key=symmetric_key)
        jws_invalid = JWS(alg="HS256", key="different_key")
        token = jws.sign({"typ": "JWT"}, "test data")
        with pytest.raises(JamJWSVerificationError):
            jws_invalid.deserialize_compact(token)

    def test_deserialize_without_validation(self, symmetric_key):
        jws = JWS(alg="HS256", key=symmetric_key)
        token = jws.sign({"typ": "JWT"}, "test data")
        jws_invalid = JWS(alg="HS256", key="different_key")
        result = jws_invalid.deserialize_compact(token, validate=False)
        assert result["payload"] == b"test data"


class TestJWSCompactSerialization:
    @pytest.fixture
    def symmetric_key(self):
        return "SOME_JWT_KEY"

    def test_adds_alg_to_header(self, symmetric_key):
        jws = JWS(alg="HS256", key=symmetric_key)
        token = jws.serialize_compact({}, "test")
        result = jws.deserialize_compact(token)
        assert result["header"]["alg"] == "HS256"

    def test_merges_provided_header_with_alg(self, symmetric_key):
        jws = JWS(alg="HS256", key=symmetric_key)
        token = jws.serialize_compact({"typ": "JWT"}, "test")
        result = jws.deserialize_compact(token)
        assert result["header"]["alg"] == "HS256"
        assert result["header"]["typ"] == "JWT"

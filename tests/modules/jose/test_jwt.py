# -*- coding: utf-8 -*-

import pytest
import json
import os
import tempfile
from jam.jose import JWT, JWS, JWE
from jam.exceptions import (
    JamJWTExpired,
    JamJWTInBlackList,
    JamJWTInvalidClaim,
    JamJWTNotInWhiteList,
    JamJWTUnsupportedAlgorithm,
)
from jam.exceptions.jose import JamJWSVerificationError
from jam.utils import generate_ecdsa_keypair, generate_rsa_key_pair


def decode_payload(jwt, token):
    data = jwt.decode(token)
    return data["payload"]


class TestJWTHS:
    @pytest.fixture
    def symmetric_key(self):
        return "SOME_JWT_KEY_THIS_IS_MORE_THAN_16_BYTES"

    @pytest.fixture
    def jwt(self, symmetric_key):
        return JWT(alg="HS256", secret_key=symmetric_key)

    def test_encode(self, jwt):
        token = jwt.encode(payload={"user_id": 123})
        assert token.count(".") == 2
        assert token.startswith("ey")

    def test_encode_with_exp(self, jwt):
        token = jwt.encode(exp=3600, payload={"user_id": 123})
        decoded = decode_payload(jwt, token)
        assert decoded["exp"] is not None
        assert decoded["iat"] is not None

    def test_encode_with_claims(self, jwt):
        token = jwt.encode(
            iss="issuer",
            sub="subject",
            aud="audience",
            exp=3600,
            nbf=0,
            payload={"user_id": 123},
        )
        decoded = decode_payload(jwt, token)
        assert decoded["iss"] == "issuer"
        assert decoded["sub"] == "subject"
        assert decoded["aud"] == "audience"
        assert "nbf" in decoded

    def test_decode(self, jwt):
        token = jwt.encode(payload={"user_id": 123})
        decoded = decode_payload(jwt, token)
        assert decoded["user_id"] == 123

    def test_decode_with_include_headers(self, jwt):
        token = jwt.encode(payload={"user_id": 123})
        decoded = jwt.decode(token)
        assert "header" in decoded
        assert decoded["header"]["alg"] == "HS256"
        assert "payload" in decoded

    def test_jti_generated(self, jwt):
        token = jwt.encode(payload={"data": "test"})
        decoded = decode_payload(jwt, token)
        assert "jti" in decoded
        assert decoded["jti"] is not None


class TestJWTHS384:
    @pytest.fixture
    def symmetric_key(self):
        return "SOME_JWT_KEY_THIS_IS_MORE_THAN_24_BYTES_LONG"

    @pytest.fixture
    def jwt(self, symmetric_key):
        return JWT(alg="HS384", secret_key=symmetric_key)

    def test_encode_decode(self, jwt):
        token = jwt.encode(payload={"data": "test"})
        decoded = decode_payload(jwt, token)
        assert decoded["data"] == "test"


class TestJWTHS512:
    @pytest.fixture
    def symmetric_key(self):
        return "SOME_JWT_KEY_THIS_IS_MORE_THAN_32_BYTES_LONG"

    @pytest.fixture
    def jwt(self, symmetric_key):
        return JWT(alg="HS512", secret_key=symmetric_key)

    def test_encode_decode(self, jwt):
        token = jwt.encode(payload={"data": "test"})
        decoded = decode_payload(jwt, token)
        assert decoded["data"] == "test"


class TestJWTRSA:
    @pytest.fixture
    def rsa_key_pair(self):
        return generate_rsa_key_pair()

    @pytest.fixture
    def jwt(self, rsa_key_pair):
        return JWT(alg="RS256", secret_key=rsa_key_pair["private"])

    def test_encode_decode(self, jwt):
        token = jwt.encode(payload={"user_id": 123})
        decoded = decode_payload(jwt, token)
        assert decoded["user_id"] == 123

    def test_decode_with_public_key(self, rsa_key_pair):
        jwt_private = JWT(alg="RS256", secret_key=rsa_key_pair["private"])
        jwt_public = JWT(alg="RS256", secret_key=rsa_key_pair["public"])

        token = jwt_private.encode(payload={"user_id": 123})
        decoded = decode_payload(jwt_public, token)
        assert decoded["user_id"] == 123


class TestJWTRSAVariants:
    @pytest.fixture
    def rsa_key_pair(self):
        return generate_rsa_key_pair()

    def test_rs384(self, rsa_key_pair):
        jwt = JWT(alg="RS384", secret_key=rsa_key_pair["private"])
        token = jwt.encode(payload={"data": "test"})
        decoded = decode_payload(jwt, token)
        assert decoded["data"] == "test"

    def test_rs512(self, rsa_key_pair):
        jwt = JWT(alg="RS512", secret_key=rsa_key_pair["private"])
        token = jwt.encode(payload={"data": "test"})
        decoded = decode_payload(jwt, token)
        assert decoded["data"] == "test"


class TestJWTECDSA:
    @pytest.fixture
    def ecdsa_key_pair(self):
        return generate_ecdsa_keypair("P-256")

    @pytest.fixture
    def jwt(self, ecdsa_key_pair):
        return JWT(alg="ES256", secret_key=ecdsa_key_pair["private"])

    def test_encode_decode(self, jwt):
        token = jwt.encode(payload={"user_id": 123})
        decoded = decode_payload(jwt, token)
        assert decoded["user_id"] == 123

    def test_decode_with_public_key(self, ecdsa_key_pair):
        jwt_private = JWT(alg="ES256", secret_key=ecdsa_key_pair["private"])
        jwt_public = JWT(alg="ES256", secret_key=ecdsa_key_pair["public"])

        token = jwt_private.encode(payload={"user_id": 123})
        decoded = decode_payload(jwt_public, token)
        assert decoded["user_id"] == 123


class TestJWTECDSAVariants:
    def test_es384(self):
        ecdsa_key_pair = generate_ecdsa_keypair("P-384")
        jwt = JWT(alg="ES384", secret_key=ecdsa_key_pair["private"])
        token = jwt.encode(payload={"data": "test"})
        decoded = decode_payload(jwt, token)
        assert decoded["data"] == "test"

    def test_es512(self):
        ecdsa_key_pair = generate_ecdsa_keypair("P-521")
        jwt = JWT(alg="ES512", secret_key=ecdsa_key_pair["private"])
        token = jwt.encode(payload={"data": "test"})
        decoded = decode_payload(jwt, token)
        assert decoded["data"] == "test"


class TestJWTJWE:
    @pytest.fixture
    def symmetric_key(self):
        return "SOME_JWE_KEY_THIS_IS_32_BYTES_LONG"

    def test_encrypt_decrypt_a128kw_a128cbc(self, symmetric_key):
        jwt = JWT(enc="A128CBC-HS256", secret_key=symmetric_key)

        ciphertext = jwt.encrypt({"user_id": 123})
        assert ciphertext.count(".") == 4

        decrypted = jwt.decrypt(ciphertext)
        assert decrypted["user_id"] == 123

    def test_encrypt_decrypt_a128kw_a256gcm(self, symmetric_key):
        jwt = JWT(enc="A256GCM", secret_key=symmetric_key)

        ciphertext = jwt.encrypt({"user_id": 123})
        decrypted = jwt.decrypt(ciphertext)
        assert decrypted["user_id"] == 123

    def test_encrypt_decrypt_a256kw_a256gcm(self):
        symmetric_key = "THIS_KEY_IS_MORE_THAN_32_BYTES_LONG"
        jwt = JWT(enc="A256GCM", secret_key=symmetric_key)

        ciphertext = jwt.encrypt({"user_id": 123})
        decrypted = jwt.decrypt(ciphertext)
        assert decrypted["user_id"] == 123

    def test_encrypt_with_header(self, symmetric_key):
        jwt = JWT(enc="A128CBC-HS256", secret_key=symmetric_key)

        ciphertext = jwt.encrypt({"data": "test"}, {"kid": "my-key"})
        decrypted = jwt.decrypt(ciphertext)
        assert decrypted["data"] == "test"

    def test_encrypt_string_payload(self, symmetric_key):
        jwt = JWT(enc="A128CBC-HS256", secret_key=symmetric_key)

        ciphertext = jwt.encrypt("plain text")
        decrypted = jwt.decrypt(ciphertext)
        assert decrypted.get("raw") == "plain text"


class TestJWTJWERSA:
    @pytest.fixture
    def rsa_key_pair(self):
        return generate_rsa_key_pair()

    def test_encrypt_rsa_oaep_decrypt(self, rsa_key_pair):
        jwt = JWT(
            enc="A256GCM",
            secret_key=rsa_key_pair["private"],
        )

        ciphertext = jwt.encrypt({"user_id": 123})
        decrypted = jwt.decrypt(ciphertext)
        assert decrypted["user_id"] == 123

    def test_jws_jwe_sign_then_encrypt(self, rsa_key_pair):
        jwt = JWT(
            alg="RS256",
            enc="A256GCM",
            secret_key=rsa_key_pair["private"],
        )

        token = jwt.encode(payload={"data": "secret"})
        ciphertext = jwt.encrypt(token)

        decrypted = jwt.decrypt(ciphertext)
        assert decrypted["data"] == "secret"


class TestJWTErrors:
    def test_missing_alg_and_enc(self):
        from jam.exceptions import JamConfigurationError

        with pytest.raises(JamConfigurationError):
            JWT(secret_key="some_key")

    def test_invalid_algorithm(self):
        with pytest.raises(JamJWTUnsupportedAlgorithm):
            JWT(alg="INVALID", secret_key="some_key")

    def test_invalid_enc_algorithm(self):
        with pytest.raises(JamJWTUnsupportedAlgorithm):
            JWT(enc="INVALID", secret_key="some_key")

    def test_decode_without_jws_config(self):
        from jam.exceptions import JamConfigurationError

        jwt = JWT(enc="A128CBC-HS256", secret_key="some_key_32_bytes_long")
        with pytest.raises(JamConfigurationError):
            jwt.decode("some.token")

    def test_encrypt_without_jwe_config(self):
        from jam.exceptions import JamConfigurationError

        jwt = JWT(alg="HS256", secret_key="some_key")
        with pytest.raises(JamConfigurationError):
            jwt.encrypt({"data": "test"})

    def test_cannot_specify_both_alg_and_jws(self):
        from jam.exceptions import JamConfigurationError

        jws = JWS(alg="HS256", key="SOME_KEY_THAT_IS_LONG")
        with pytest.raises(JamConfigurationError, match="Cannot specify both"):
            JWT(alg="HS256", jws=jws, secret_key="SOME_KEY")

    def test_cannot_specify_both_enc_and_jwe(self):
        from jam.exceptions import JamConfigurationError

        jwe = JWE(
            alg="A128KW", enc="A128CBC-HS256", key="SOME_KEY_THAT_IS_LONG"
        )
        with pytest.raises(JamConfigurationError, match="Cannot specify both"):
            JWT(enc="A128CBC-HS256", jwe=jwe, secret_key="SOME_KEY")

    def test_invalid_token_type(self):
        jwt = JWT(
            alg="HS256", secret_key="SOME_JWT_KEY_THIS_IS_MORE_THAN_16_BYTES"
        )
        token = jwt.encode(payload={"data": "test"})

        parts = token.split(".")
        header = json.loads(
            __import__("base64").b64decode(parts[0] + "==").decode()
        )
        header["typ"] = "NOT_JWT"
        import base64

        new_header = (
            base64.urlsafe_b64encode(json.dumps(header).encode())
            .decode()
            .rstrip("=")
        )
        new_token = f"{new_header}.{parts[1]}.{parts[2]}"

        with pytest.raises(JamJWSVerificationError):
            jwt.decode(new_token)


class TestJWTListMemory:
    def test_blacklist_revokes_complete_token(self):
        jwt = JWT(
            alg="HS256",
            secret_key="SOME_JWT_KEY_THIS_IS_MORE_THAN_16_BYTES",
            list={"backend": "memory", "type": "black"},
        )

        token = jwt.encode(payload={"user_id": 123})
        jwt.list.add(token)

        assert jwt.list.check(token) is True
        with pytest.raises(JamJWTInBlackList):
            jwt.decode(token)

    def test_whitelist_registers_issued_token(self):
        jwt = JWT(
            alg="HS256",
            secret_key="SOME_JWT_KEY_THIS_IS_MORE_THAN_16_BYTES",
            list={"backend": "memory", "type": "white"},
        )

        token = jwt.encode(payload={"user_id": 123})

        assert jwt.list.check(token) is True
        assert decode_payload(jwt, token)["user_id"] == 123

    def test_whitelist_rejects_token_issued_elsewhere(self):
        key = "SOME_JWT_KEY_THIS_IS_MORE_THAN_16_BYTES"
        jwt = JWT(
            alg="HS256",
            secret_key=key,
            list={"backend": "memory", "type": "white"},
        )
        token = JWT(alg="HS256", secret_key=key).encode(
            payload={"user_id": 123}
        )

        assert jwt.list.check(token) is False
        with pytest.raises(JamJWTNotInWhiteList):
            jwt.decode(token)


class TestJWTListJSON:
    def test_blacklist_json(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json_path = f.name

        try:
            jwt = JWT(
                alg="HS256",
                secret_key="SOME_JWT_KEY_THIS_IS_MORE_THAN_16_BYTES",
                list={
                    "backend": "json",
                    "type": "black",
                    "json_path": json_path,
                },
            )

            token = jwt.encode(payload={"user_id": 123})
            jwt.list.add(token)

            assert jwt.list.check(token) is True
            with pytest.raises(JamJWTInBlackList):
                jwt.decode(token)

            jwt2 = JWT(
                alg="HS256",
                secret_key="SOME_JWT_KEY_THIS_IS_MORE_THAN_16_BYTES",
                list={
                    "backend": "json",
                    "type": "black",
                    "json_path": json_path,
                },
            )
            assert jwt2.list.check(token) is True
        finally:
            if os.path.exists(json_path):
                os.remove(json_path)

    def test_whitelist_json(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".json", delete=False
        ) as f:
            json_path = f.name

        try:
            jwt = JWT(
                alg="HS256",
                secret_key="SOME_JWT_KEY_THIS_IS_MORE_THAN_16_BYTES",
                list={
                    "backend": "json",
                    "type": "white",
                    "json_path": json_path,
                },
            )

            token = jwt.encode(payload={"user_id": 123})

            assert jwt.list.check(token) is True
            assert decode_payload(jwt, token)["user_id"] == 123
        finally:
            if os.path.exists(json_path):
                os.remove(json_path)


class TestJWTJWKIntegration:
    @pytest.fixture
    def rsa_key_pair(self):
        return generate_rsa_key_pair()

    def test_jwk_with_jwt(self, rsa_key_pair):
        jwt = JWT(alg="RS256", secret_key=rsa_key_pair["private"])
        token = jwt.encode(payload={"user_id": 123})
        decoded = decode_payload(jwt, token)
        assert decoded["user_id"] == 123


class TestJWTSignThenEncryptHybrid:
    @pytest.fixture
    def rsa_key_pair(self):
        return generate_rsa_key_pair()

    def test_with_prebuilt_jws_jwe(self, rsa_key_pair):
        jws = JWS(alg="RS256", key=rsa_key_pair["private"])
        jwe = JWE(alg="RSA-OAEP", enc="A256GCM", key=rsa_key_pair["private"])

        jwt = JWT(jws=jws, jwe=jwe, secret_key=rsa_key_pair["private"])
        token = jwt.encode(payload={"data": "secret"})
        ciphertext = jwt.encrypt(token)
        decrypted = jwt.decrypt(ciphertext)
        assert decrypted["data"] == "secret"

    def test_sign_then_encrypt_with_symmetric_key(self):
        jwt = JWT(
            alg="HS256",
            enc="A256GCM",
            secret_key="SOME_SECRET_KEY_THAT_IS_LONG_ENOUGH",
        )
        token = jwt.encode(payload={"data": "symmetric_test"})
        ciphertext = jwt.encrypt(token)
        decrypted = jwt.decrypt(ciphertext)
        assert decrypted["data"] == "symmetric_test"

    def test_mixed_prebuilt_and_auto(self, rsa_key_pair):
        jws = JWS(alg="RS256", key=rsa_key_pair["private"])
        jwt = JWT(
            jws=jws,
            enc="A256GCM",
            secret_key=rsa_key_pair["private"],
        )
        assert jwt.jws is jws
        assert jwt.jwe is not None
        token = jwt.encode(payload={"data": "mixed"})
        ciphertext = jwt.encrypt(token)
        decrypted = jwt.decrypt(ciphertext)
        assert decrypted["data"] == "mixed"


class TestJWTEncoding:
    def test_encode_with_custom_header(self):
        jwt = JWT(
            alg="HS256",
            secret_key="SOME_JWT_KEY_THIS_IS_MORE_THAN_16_BYTES",
        )

        token = jwt.encode(
            payload={"data": "test"},
            header={"kid": "my-key", "x5t": "thumbprint"},
        )

        decoded = jwt.decode(token)
        assert decoded["header"]["kid"] == "my-key"
        assert decoded["header"]["x5t"] == "thumbprint"


class TestJWTClaims:
    @pytest.fixture
    def jwt(self):
        return JWT(
            alg="HS256",
            secret_key="SOME_JWT_KEY_THIS_IS_MORE_THAN_16_BYTES",
        )

    def test_all_claims(self):
        jwt = JWT(
            alg="HS256",
            secret_key="SOME_JWT_KEY_THIS_IS_MORE_THAN_16_BYTES",
        )

        token = jwt.encode(
            iss="issuer",
            sub="subject",
            aud="audience",
            exp=3600,
            nbf=-10,
            payload={"custom": "claim"},
        )

        decoded = jwt.decode(token)["payload"]

        assert decoded["iss"] == "issuer"
        assert decoded["sub"] == "subject"
        assert decoded["aud"] == "audience"
        assert decoded["exp"] is not None
        assert decoded["nbf"] is not None
        assert decoded["iat"] is not None
        assert decoded["jti"] is not None
        assert decoded["custom"] == "claim"

    @pytest.mark.parametrize("claim", ["exp", "nbf"])
    @pytest.mark.parametrize(
        "value", ["123", True, False, float("nan"), float("inf"), -float("inf")]
    )
    def test_invalid_numeric_date_claim(self, jwt, claim, value):
        token = jwt.encode(payload={claim: value})

        with pytest.raises(JamJWTInvalidClaim) as exc_info:
            jwt.decode(token)

        assert exc_info.value.error_code == "jwt.invalid_claim"
        assert exc_info.value.details["claim"] == claim

    def test_exp_equal_to_now_is_expired(self, jwt, monkeypatch):
        now = 1_700_000_000
        monkeypatch.setattr("jam.jose.jwt.time.time", lambda: now)
        token = jwt.encode(payload={"exp": now})

        with pytest.raises(JamJWTExpired):
            jwt.decode(token)

    @pytest.mark.parametrize(
        ("claim", "value"),
        [
            ("exp", 2_000_000_000),
            ("exp", 2_000_000_000.5),
            ("exp", 10**1000),
            ("nbf", 0),
            ("nbf", 0.5),
        ],
    )
    def test_valid_numeric_date_claim(self, jwt, claim, value):
        token = jwt.encode(payload={claim: value})

        assert jwt.decode(token)["payload"][claim] == value

    def test_invalid_claim_validation_can_be_disabled(self, jwt):
        token = jwt.encode(payload={"exp": "not-a-numeric-date"})

        payload = jwt.decode(token, validate_claims=False)["payload"]

        assert payload["exp"] == "not-a-numeric-date"

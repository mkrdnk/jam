# -*- coding: utf-8 -*-

import base64
import json

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import pytest

from jam.exceptions import JamJWEDecryptionError, JamJWEEncryptionError
from jam.jose import JWE
from jam.jose.__algorithms__ import create_key_algorithm
from jam.jose.jwk import JWK
from jam.utils import generate_rsa_key_pair


def _base64url_encode(value: bytes) -> str:
    """Encode bytes without base64url padding."""
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()


def _base64url_decode(value: str) -> bytes:
    """Decode an unpadded base64url string."""
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _replace_protected_header(token: str, **updates: object) -> str:
    """Replace fields in a compact JWE's protected header."""
    protected_b64, *parts = token.split(".")
    protected = json.loads(_base64url_decode(protected_b64))
    protected.update(updates)
    return ".".join(
        [
            _base64url_encode(
                json.dumps(protected, separators=(",", ":")).encode()
            ),
            *parts,
        ]
    )


def _remove_protected_header(token: str, field: str) -> str:
    """Remove a field from a compact JWE's protected header."""
    protected_b64, *parts = token.split(".")
    protected = json.loads(_base64url_decode(protected_b64))
    del protected[field]
    return ".".join(
        [
            _base64url_encode(
                json.dumps(protected, separators=(",", ":")).encode()
            ),
            *parts,
        ]
    )


class TestJWEAESKeyWrap:
    @pytest.fixture
    def symmetric_key_aes128(self):
        return "SOME_JWE_KEY_THIS_IS_16B"

    @pytest.fixture
    def symmetric_key_aes256(self):
        from jam.utils import generate_aes_key

        return generate_aes_key()

    def test_a128kw_a128cbc_encrypt_decrypt(self, symmetric_key_aes128):
        jwe = JWE(alg="A128KW", enc="A128CBC-HS256", key=symmetric_key_aes128)
        ciphertext = jwe.encrypt("test plaintext")
        assert ciphertext.count(".") == 4

        plaintext = jwe.decrypt(ciphertext)
        assert plaintext == b"test plaintext"

    def test_a128kw_a256gcm_encrypt_decrypt(self, symmetric_key_aes128):
        jwe = JWE(alg="A128KW", enc="A256GCM", key=symmetric_key_aes128)
        ciphertext = jwe.encrypt("test plaintext")

        plaintext = jwe.decrypt(ciphertext)
        assert plaintext == b"test plaintext"

    def test_a256kw_a128cbc_encrypt_decrypt(self, symmetric_key_aes256):
        jwe = JWE(alg="A256KW", enc="A128CBC-HS256", key=symmetric_key_aes256)
        ciphertext = jwe.encrypt("test plaintext")

        plaintext = jwe.decrypt(ciphertext)
        assert plaintext == b"test plaintext"

    def test_a256kw_a256gcm_encrypt_decrypt(self, symmetric_key_aes256):
        jwe = JWE(alg="A256KW", enc="A256GCM", key=symmetric_key_aes256)
        ciphertext = jwe.encrypt("test plaintext")

        plaintext = jwe.decrypt(ciphertext)
        assert plaintext == b"test plaintext"

    def test_encrypt_with_header(self, symmetric_key_aes128):
        jwe = JWE(alg="A128KW", enc="A128CBC-HS256", key=symmetric_key_aes128)
        ciphertext = jwe.encrypt("test", {"kid": "my-key"})

        plaintext = jwe.decrypt(ciphertext)
        assert plaintext == b"test"

    @pytest.mark.parametrize("field", ["alg", "enc"])
    def test_encrypt_rejects_reserved_header_override(
        self, symmetric_key_aes128, field
    ):
        jwe = JWE(alg="A128KW", enc="A128CBC-HS256", key=symmetric_key_aes128)

        with pytest.raises(JamJWEEncryptionError) as exc_info:
            jwe.encrypt("test", {field: "attacker-selected"})

        assert exc_info.value.error_code == "jwe.encryption_error"
        assert exc_info.value.details == {
            "reason": "reserved_header_override",
            "headers": [field],
        }

    def test_encrypt_dict_payload(self, symmetric_key_aes128):
        jwe = JWE(alg="A128KW", enc="A128CBC-HS256", key=symmetric_key_aes128)
        ciphertext = jwe.encrypt({"key": "value"})

        plaintext = jwe.decrypt(ciphertext)
        assert json.loads(plaintext) == {"key": "value"}

    def test_encrypt_bytes_payload(self, symmetric_key_aes128):
        jwe = JWE(alg="A128KW", enc="A128CBC-HS256", key=symmetric_key_aes128)
        ciphertext = jwe.encrypt(b"binary data")

        plaintext = jwe.decrypt(ciphertext)
        assert plaintext == b"binary data"

    def test_encrypt_with_jwk(self, symmetric_key_aes128):
        jwk = JWK.from_dict({"kty": "oct", "k": "U09NRV9KV0VfS0VZXzE2Qg"})
        jwe = JWE(alg="A128KW", enc="A128CBC-HS256", key=jwk)
        ciphertext = jwe.encrypt("test")

        plaintext = jwe.decrypt(ciphertext)
        assert plaintext == b"test"


class TestJWERSAAES:
    @pytest.fixture
    def rsa_key_pair(self):
        return generate_rsa_key_pair()

    def test_rsa_oaep_a128cbc_encrypt_decrypt(self, rsa_key_pair):
        jwe = JWE(
            alg="RSA-OAEP", enc="A128CBC-HS256", key=rsa_key_pair["private"]
        )
        ciphertext = jwe.encrypt("test plaintext")

        plaintext = jwe.decrypt(ciphertext)
        assert plaintext == b"test plaintext"

    def test_rsa_oaep_a256gcm_encrypt_decrypt(self, rsa_key_pair):
        jwe = JWE(alg="RSA-OAEP", enc="A256GCM", key=rsa_key_pair["private"])
        ciphertext = jwe.encrypt("test plaintext")

        plaintext = jwe.decrypt(ciphertext)
        assert plaintext == b"test plaintext"

    def test_rsa_oaep_decrypt_with_public_key_fails(self, rsa_key_pair):
        jwe_private = JWE(
            alg="RSA-OAEP", enc="A128CBC-HS256", key=rsa_key_pair["private"]
        )
        ciphertext = jwe_private.encrypt("test plaintext")

        jwe_public = JWE(
            alg="RSA-OAEP", enc="A128CBC-HS256", key=rsa_key_pair["public"]
        )
        with pytest.raises(Exception):
            jwe_public.decrypt(ciphertext)

    def test_rsa_oaep_256_a256gcm(self, rsa_key_pair):
        jwe = JWE(
            alg="RSA-OAEP-256", enc="A256GCM", key=rsa_key_pair["private"]
        )
        ciphertext = jwe.encrypt("test plaintext")

        plaintext = jwe.decrypt(ciphertext)
        assert plaintext == b"test plaintext"

    @pytest.mark.parametrize(
        ("alg", "hash_algorithm"),
        [
            ("RSA-OAEP", hashes.SHA1),
            ("RSA-OAEP-256", hashes.SHA256),
        ],
    )
    def test_rsa_oaep_interoperates_with_raw_cryptography(
        self, rsa_key_pair, alg, hash_algorithm
    ):
        private_key = serialization.load_pem_private_key(
            rsa_key_pair["private"].encode(), password=None
        )
        public_key = private_key.public_key()
        key_algorithm = create_key_algorithm(
            alg, rsa_key_pair["private"], password=None
        )
        cek = b"0123456789abcdef"
        hash_alg = hash_algorithm()
        oaep = padding.OAEP(
            mgf=padding.MGF1(hash_alg),
            algorithm=hash_alg,
            label=b"",
        )

        wrapped, _ = key_algorithm.wrap_key(cek)
        assert private_key.decrypt(wrapped, oaep) == cek

        raw_wrapped = public_key.encrypt(cek, oaep)
        assert key_algorithm.unwrap_key(raw_wrapped, {}) == cek

        if alg == "RSA-OAEP":
            legacy_hash = hashes.SHA256()
            legacy_oaep = padding.OAEP(
                mgf=padding.MGF1(legacy_hash),
                algorithm=legacy_hash,
                label=b"",
            )
            legacy_wrapped = public_key.encrypt(cek, legacy_oaep)
            assert key_algorithm.unwrap_key(legacy_wrapped, {}) == cek


class TestJWEUnsupportedAlgorithms:
    @pytest.fixture
    def symmetric_key(self):
        return "SOME_JWE_KEY_THIS_IS_32_BYTES"

    def test_unsupported_key_algorithm(self, symmetric_key):
        with pytest.raises(JamJWEEncryptionError):
            JWE(alg="UNSUPPORTED", enc="A128CBC-HS256", key=symmetric_key)

    def test_unsupported_enc_algorithm(self, symmetric_key):
        with pytest.raises(JamJWEEncryptionError):
            JWE(alg="A128KW", enc="UNSUPPORTED", key=symmetric_key)


class TestJWEDecryptionErrors:
    @pytest.fixture
    def symmetric_key_aes128(self):
        return "SOME_JWE_KEY_THIS_IS_16B"

    def test_invalid_jwe_format(self, symmetric_key_aes128):
        jwe = JWE(alg="A128KW", enc="A128CBC-HS256", key=symmetric_key_aes128)
        with pytest.raises(Exception):
            jwe.decrypt("invalid.format")

    def test_invalid_jwe_parts_count(self, symmetric_key_aes128):
        jwe = JWE(alg="A128KW", enc="A128CBC-HS256", key=symmetric_key_aes128)
        with pytest.raises(Exception):
            jwe.decrypt("a.b.c")

    def test_decryption_with_wrong_key(self, symmetric_key_aes128):
        jwe_encrypt = JWE(
            alg="A128KW", enc="A128CBC-HS256", key=symmetric_key_aes128
        )
        ciphertext = jwe_encrypt.encrypt("test")

        jwe_decrypt = JWE(
            alg="A128KW", enc="A128CBC-HS256", key="wrong_key_16_bytes"
        )
        with pytest.raises(Exception):
            jwe_decrypt.decrypt(ciphertext)

    @pytest.mark.parametrize(
        ("field", "value", "details"),
        [
            (
                "alg",
                "A256KW",
                {
                    "reason": "algorithm_mismatch",
                    "expected": "A128KW",
                    "got": "A256KW",
                },
            ),
            (
                "enc",
                "A256GCM",
                {
                    "reason": "content_encryption_mismatch",
                    "expected": "A128CBC-HS256",
                    "got": "A256GCM",
                },
            ),
        ],
    )
    def test_decrypt_rejects_mismatched_protected_algorithm(
        self, symmetric_key_aes128, field, value, details
    ):
        jwe = JWE(alg="A128KW", enc="A128CBC-HS256", key=symmetric_key_aes128)
        token = _replace_protected_header(jwe.encrypt("test"), **{field: value})

        with pytest.raises(JamJWEDecryptionError) as exc_info:
            jwe.decrypt(token)

        assert exc_info.value.error_code == "jwe.decryption_error"
        assert exc_info.value.details == details

    @pytest.mark.parametrize(
        ("field", "details"),
        [
            (
                "alg",
                {
                    "reason": "algorithm_mismatch",
                    "expected": "A128KW",
                    "got": None,
                },
            ),
            (
                "enc",
                {
                    "reason": "content_encryption_mismatch",
                    "expected": "A128CBC-HS256",
                    "got": None,
                },
            ),
        ],
    )
    def test_decrypt_rejects_missing_protected_algorithm(
        self, symmetric_key_aes128, field, details
    ):
        jwe = JWE(alg="A128KW", enc="A128CBC-HS256", key=symmetric_key_aes128)
        token = _remove_protected_header(jwe.encrypt("test"), field)

        with pytest.raises(JamJWEDecryptionError) as exc_info:
            jwe.decrypt(token)

        assert exc_info.value.error_code == "jwe.decryption_error"
        assert exc_info.value.details == details


class TestJWEKeyManagement:
    @pytest.fixture
    def symmetric_key_aes128(self):
        return "SOME_JWE_KEY_THIS_IS_16B"

    def test_key_wrap_aeskw(self, symmetric_key_aes128):
        jwe = JWE(alg="A128KW", enc="A128CBC-HS256", key=symmetric_key_aes128)
        ciphertext = jwe.encrypt("message")

        plaintext = jwe.decrypt(ciphertext)
        assert plaintext == b"message"

    def test_key_derivation_for_encryption(self, symmetric_key_aes128):
        jwe = JWE(alg="A128KW", enc="A128CBC-HS256", key=symmetric_key_aes128)
        ciphertext = jwe.encrypt("test")

        plaintext = jwe.decrypt(ciphertext)
        assert plaintext == b"test"

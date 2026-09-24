# -*- coding: utf-8 -*-

import pytest
import json
from jam.jose import JWE
from jam.jose.jwk import JWK
from jam.exceptions import JamJWEEncryptionError, JamJWEDecryptionError
from jam.utils import generate_rsa_key_pair


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

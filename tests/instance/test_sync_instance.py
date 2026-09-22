# -*- coding: utf-8 -*-

from dataclasses import dataclass
from typing import Any, cast

import pytest
from fakeredis import FakeRedis

from jam import Jam
from jam.exceptions import JamConfigurationError, JamJWTInBlackList
from jam.subject import BaseSubject
from jam.utils import generate_symmetric_key


@dataclass
class User(BaseSubject):
    id: str
    name: str


@pytest.fixture
def jam_jwt_instance():
    jam = Jam(
        config={"jose": {"jwt": {"alg": "HS256", "secret_key": "SECRET"}}},
        subject=User,
    )
    return jam


@pytest.fixture
def jam_session_instance():
    jam = Jam(
        config={
            "session": {
                "type": "redis",
                "redis_uri": FakeRedis(decode_responses=True),
            }
        }
    )
    return jam


def test_jwt_instance(jam_jwt_instance):
    user = User(id="user123", name="test")
    token = jam_jwt_instance.issue(user, exp=89898989, via="jwt")
    assert isinstance(token, str)
    assert len(token.split(".")) == 3  # JWT has three parts separated by dots

    decoded = jam_jwt_instance.authenticate(token, via="jwt")
    assert decoded.subject == user
    assert decoded.subject.id == "user123"
    assert decoded.claims["sub"] == "user123"


def test_jwt_denylist_through_facade():
    jam = Jam(
        config={
            "jose": {
                "jwt": {
                    "alg": "HS256",
                    "secret_key": "SECRET",
                    "list": {"backend": "memory", "type": "black"},
                }
            }
        }
    )
    token = jam.issue({"id": "user123"}, via="jwt")

    jam.jwt_list.add(token)

    with pytest.raises(JamJWTInBlackList):
        jam.authenticate(token, via="jwt")


def test_paseto_denylist_through_facade():
    jam = Jam(
        config={
            "paseto": {
                "version": "v4",
                "purpose": "local",
                "secret_key": generate_symmetric_key(32),
                "list": {"backend": "memory", "type": "black"},
            }
        }
    )
    token = jam.issue({"id": "user123"}, via="paseto")

    jam.paseto_list.add(token)

    with pytest.raises(JamJWTInBlackList):
        jam.authenticate(token, via="paseto")


def test_jwt_and_paseto_share_named_token_list():
    jam = Jam(
        config={
            "lists": {
                "credentials": {
                    "backend": "memory",
                    "type": "white",
                }
            },
            "jose": {
                "jwt": {
                    "alg": "HS256",
                    "secret_key": "SECRET",
                    "list": "credentials",
                }
            },
            "paseto": {
                "version": "v4",
                "purpose": "local",
                "secret_key": generate_symmetric_key(32),
                "list": "credentials",
            },
        }
    )

    jwt = jam.issue({"id": "jwt-user"}, via="jwt")
    paseto = jam.issue({"id": "paseto-user"}, via="paseto")
    token_list = jam.lists["credentials"]

    assert jam.jwt_list is token_list
    assert jam.paseto_list is token_list
    assert jam.jwt.list is token_list
    assert jam.paseto.list is token_list
    assert token_list.check_many([jwt, paseto]) == {
        jwt: True,
        paseto: True,
    }
    assert jam.authenticate(jwt, via="jwt").subject["id"] == "jwt-user"
    assert jam.authenticate(paseto, via="paseto").subject["id"] == "paseto-user"


def test_named_token_list_must_exist():
    with pytest.raises(JamConfigurationError) as exc_info:
        Jam(
            config={
                "jose": {
                    "jwt": {
                        "alg": "HS256",
                        "secret_key": "SECRET",
                        "list": "missing",
                    }
                }
            }
        )

    assert (
        exc_info.value.error_code == "configuration.lists.not_configured"
    )


def test_named_token_list_from_toml(tmp_path):
    config_path = tmp_path / "jam.toml"
    config_path.write_text(
        """
[jam.lists.credentials]
backend = "memory"
type = "white"

[jam.jose.jwt]
alg = "HS256"
secret_key = "SECRET"
list = "credentials"
""",
        encoding="utf-8",
    )

    jam = Jam(config=str(config_path))
    token = jam.issue({"id": "user123"}, via="jwt")

    assert jam.jwt_list is jam.lists["credentials"]
    assert jam.lists["credentials"].check(token)


def test_jwe_authentication():
    jam = Jam(
        config={
            "jose": {
                "jwt": {
                    "alg": "HS256",
                    "enc": "A256GCM",
                    "secret_key": "SECRET",
                }
            }
        },
        subject=User,
    )
    user = User(id="user123", name="test")
    token = jam.jwt.encrypt({"id": user.id, "name": user.name})
    assert token.count(".") == 4
    decoded = jam.authenticate(token, via="jwe")
    assert decoded.subject == user


def test_issue_rejects_jwe(jam_jwt_instance):
    with pytest.raises(
        JamConfigurationError,
        match="Unknown 'via' type: jwe",
    ):
        jam_jwt_instance.issue(
            {"id": "user123"},
            via=cast(Any, "jwe"),
        )


def test_session_instance(jam_session_instance):
    session_data = {"user_id": "user123"}
    session_id = jam_session_instance.session.create("user", session_data)
    assert isinstance(session_id, str)
    assert len(session_id) > 0

    retrieved_data = jam_session_instance.session.get(session_id)
    assert retrieved_data == session_data

    jam_session_instance.session.delete(session_id)
    assert jam_session_instance.session.get(session_id) is None


def test_issue_via_session(jam_session_instance):
    session_id = jam_session_instance.issue(
        {"id": "user123", "role": "admin"}, via="session"
    )
    decoded = jam_session_instance.authenticate(session_id, via="session")
    assert decoded.subject["id"] == "user123"
    assert "jti" not in decoded.claims


def test_saml_issue_and_authenticate(saml_configs):
    idp_config, sp_config = saml_configs
    idp = Jam(config=idp_config)
    sp = Jam(config=sp_config)

    token = idp.issue(
        {"id": "user123", "role": "admin"},
        via="saml",
        exp=60,
        jti="_assertion-id",
        permissions=["documents:read"],
    )
    principal = sp.authenticate(token, via="saml")

    assert principal.subject["id"] == "user123"
    assert principal.subject["role"] == "admin"
    assert principal.claims["sub"] == "user123"
    assert principal.claims["aud"] == "https://sp.test"
    assert principal.claims["iss"] == "https://idp.test"
    assert principal.claims["jti"] == "_assertion-id"
    assert principal.claims["permissions"] == ["documents:read"]
    assert principal.claims["exp"] > principal.claims["nbf"]
    assert principal.token_type == "saml"


def test_saml_requires_configuration():
    jam = Jam()

    with pytest.raises(
        JamConfigurationError,
        match="SAML module is not configured",
    ):
        jam.issue({"id": "user123"}, via="saml")


def test_saml_filestorage_keychain_issue_and_authenticate(tmp_path):
    keychain_config = {
        "saml": {
            "type": "FileStorage",
            "path": str(tmp_path / "saml"),
            "algorithm": "RS256",
        }
    }
    idp = Jam(
        config={
            "keychains": keychain_config,
            "saml": {
                "role": "idp",
                "keychain": "saml",
                "entity_id": "https://idp.test",
                "audience": "https://sp.test",
            },
        }
    )
    sp = Jam(
        config={
            "keychains": keychain_config,
            "saml": {
                "role": "sp",
                "keychain": "saml",
                "entity_id": "https://sp.test",
                "expected_issuer": "https://idp.test",
            },
        }
    )
    idp.keychains["saml"].rotate("saml-key")

    token = idp.issue({"id": "user123"}, via="saml")
    principal = sp.authenticate(token, via="saml")

    assert principal.subject["id"] == "user123"
    assert idp.saml.keychain is idp.keychains["saml"]
    assert sp.saml.keychain is sp.keychains["saml"]

    idp.keychains["saml"].rotate("rotated-key")

    rotated_token = idp.issue({"id": "user456"}, via="saml")
    rotated_principal = sp.authenticate(rotated_token, via="saml")

    assert rotated_principal.subject["id"] == "user456"


def test_authorize(jam_jwt_instance):
    user = User(id="user123", name="test")
    assert not jam_jwt_instance.authorize(user, "any")


def test_authorize_with_policy():
    jam = Jam(
        config={
            "jose": {"jwt": {"alg": "HS256", "secret_key": "SECRET"}},
            "authz": {
                "rules": {"post:read": ["*"], "post:edit": ["id=user123"]}
            },
        },
        subject=User,
    )
    user = User(id="user123", name="test")
    other = User(id="other", name="other")
    assert jam.authorize(user, "post:read") is True
    assert jam.authorize(other, "post:read") is True
    assert jam.authorize(user, "post:edit") is True
    assert jam.authorize(other, "post:edit") is False
    assert jam.authorize(user, "post:delete") is False

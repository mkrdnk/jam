# -*- coding: utf-8 -*-

from dataclasses import dataclass

import pytest
from fakeredis import FakeRedis

from jam import Jam
from jam.subject import BaseSubject


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
    token = jam_jwt_instance.issue(user, exp=89898989)
    assert isinstance(token, str)
    assert len(token.split(".")) == 3  # JWT has three parts separated by dots

    decoded = jam_jwt_instance.authenticate(token)
    assert decoded.subject == user
    assert decoded.subject.id == "user123"
    assert decoded.claims["sub"] == "user123"


def test_jwt_autodetect(jam_jwt_instance):
    user = User(id="user123", name="test")
    token = jam_jwt_instance.issue(user)
    decoded = jam_jwt_instance.authenticate(token, via=None)
    assert decoded.subject == user


def test_jwe_autodetect():
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
    decoded = jam.authenticate(token)
    assert decoded.subject == user


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
    decoded = jam_session_instance.authenticate(session_id)
    assert decoded.subject["id"] == "user123"
    assert "jti" not in decoded.claims


def test_authorize(jam_jwt_instance):
    user = User(id="user123", name="test")
    assert not jam_jwt_instance.authorize(user, "any")


def test_authorize_with_policy():
    jam = Jam(
        config={
            "jose": {"jwt": {"alg": "HS256", "secret_key": "SECRET"}},
            "authz": {"rules": {"post:read": ["*"], "post:edit": ["id=user123"]}},
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

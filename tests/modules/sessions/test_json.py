# -*- coding: utf-8 -*-

from jam.exceptions import JamSessionNotFound
import pytest
from cryptography.fernet import Fernet
from tinydb import Query, TinyDB

from jam.sessions.json import JSONSessions


t = TinyDB(":memory:")
ts = Query()


@pytest.fixture(scope="function")
def json_sessions_no_crypt():
    return JSONSessions(
        json_path=":memory:",
        is_session_crypt=False,
    )


@pytest.fixture(scope="session")
def aes_key():
    from jam.utils import generate_aes_key

    return generate_aes_key()


@pytest.fixture(scope="session")
def f(aes_key):
    return Fernet(aes_key)


@pytest.fixture(scope="function")
def json_session_with_crypt(aes_key):
    return JSONSessions(
        json_path=":memory:", is_session_crypt=True, session_aes_secret=aes_key
    )


def test_create_session(json_sessions_no_crypt):
    session = json_sessions_no_crypt.create(
        session_key="test", data={"user": "test_user"}
    )

    assert isinstance(session, str)
    assert len(session) > 0

    stored_data = t.search(ts.session_id == session)
    assert stored_data[0]["data"] == '{"user": "test_user"}'

    t.truncate()


def test_get_session(json_sessions_no_crypt):
    session = json_sessions_no_crypt.create(
        session_key="test", data={"user": "test_user"}
    )
    retrieved_data = json_sessions_no_crypt.get(session)
    assert retrieved_data == {"user": "test_user"}

    t.truncate()


def test_get_nonexistent_session(json_sessions_no_crypt):
    retrieved_data = json_sessions_no_crypt.get("nonexistent:session")
    assert retrieved_data is None

    t.truncate()


def test_delete_session(json_sessions_no_crypt):
    session = json_sessions_no_crypt.create(
        session_key="test", data={"user": "test_user"}
    )
    json_sessions_no_crypt.delete(session)
    retrieved_data = json_sessions_no_crypt.get(session)
    assert retrieved_data is None

    t.truncate()


def test_update_session(json_sessions_no_crypt):
    session = json_sessions_no_crypt.create(
        session_key="test", data={"user": "test_user"}
    )
    json_sessions_no_crypt.update(session, {"user": "updated_user"})
    retrieved_data = json_sessions_no_crypt.get(session)
    assert retrieved_data == {"user": "updated_user"}

    t.truncate()


def test_update_nonexistent_session(json_sessions_no_crypt):
    with pytest.raises(JamSessionNotFound):
        json_sessions_no_crypt.update(
            "nonexistent:session", {"user": "updated_user"}
        )
    t.truncate()


def test_create_new_crypt_session(json_session_with_crypt, f):
    session = json_session_with_crypt.create(
        session_key="test", data={"user": "test_user"}
    )

    assert isinstance(session, str)
    assert len(session) > 0
    assert session.startswith("J$_")

    stored_data = t.search(ts.session_id == session)
    assert stored_data[0]["data"] != {"user": "test_user"}

    encoded_data: str = stored_data[0]["data"]
    assert encoded_data.startswith("J$_")

    assert (
        f.decrypt(encoded_data.split("J$_")[1]).decode()
        == '{"user": "test_user"}'
    )

    t.truncate()


def test_get_get_session(json_session_with_crypt, f):
    session_id = json_session_with_crypt.create("test", {"user": "test_user"})

    decoded_session_data = json_session_with_crypt.get(session_id)
    assert decoded_session_data == {"user": "test_user"}

    encoded_session_data = t.search(ts.session_id == session_id)
    assert encoded_session_data != {"user": "test_user"}
    assert encoded_session_data != '{"user": "test_user"}'

    t.truncate()


def test_close_is_idempotent(json_sessions_no_crypt):
    json_sessions_no_crypt.close()
    json_sessions_no_crypt.close()

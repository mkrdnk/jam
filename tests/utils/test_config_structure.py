"""Configuration structure, file formats and literal environment values."""

import copy

from fakeredis import FakeRedis
import pytest

from jam import Jam
from jam.aio import AsyncJam
from jam.exceptions import JamConfigurationError
from jam.sessions.redis import RedisSessions
from jam.utils.config_maker import __config_maker__, __config_cache_clear__


@pytest.mark.parametrize("cls", [Jam, AsyncJam])
@pytest.mark.parametrize(
    "section",
    [
        "jose",
        "session",
        "paseto",
        "saml",
        "otp",
        "authz",
        "oauth2",
        "keychains",
    ],
)
@pytest.mark.parametrize("bad", ["broken", [], False, 3])
def test_invalid_sections_are_rejected(cls, section, bad):
    with pytest.raises(JamConfigurationError) as error:
        cls(config={section: bad})
    assert error.value.error_code == "configuration.invalid_structure"
    assert error.value.details == {"field": section, "expected": "mapping"}


@pytest.mark.parametrize(
    "cfg,path",
    [
        ({"jose": {"jwt": []}}, "jose.jwt"),
        ({"oauth2": {"github": 1}}, "oauth2.github"),
        ({"keychains": {"main": None}}, "keychains.main"),
        ({"lists": {"deny": True}}, "lists.deny"),
    ],
)
def test_invalid_nested_sections(cfg, path):
    with pytest.raises(JamConfigurationError) as error:
        Jam(config=cfg)
    assert error.value.details["field"] == path


@pytest.mark.parametrize("cls", [Jam, AsyncJam])
def test_optional_none_and_extension_keys(cls):
    cfg = {
        name: None
        for name in (
            "jose",
            "session",
            "paseto",
            "saml",
            "otp",
            "authz",
            "oauth2",
            "keychains",
            "lists",
        )
    }
    cfg["application_extension"] = "untouched"
    original = copy.deepcopy(cfg)
    cls(config=cfg)
    assert cfg == original


@pytest.mark.parametrize(
    "ext,content",
    [
        ("json", "[]"),
        ("json", "null"),
        ("yaml", "- a"),
        ("yaml", "jam: wrong"),
        ("toml", 'jam = "wrong"'),
    ],
)
def test_selected_file_section_must_be_mapping(tmp_path, ext, content):
    file = tmp_path / f"config.{ext}"
    file.write_text(content)
    with pytest.raises(JamConfigurationError) as error:
        __config_maker__(str(file))
    assert error.value.error_code == "configuration.invalid_structure"


@pytest.mark.parametrize(
    "literal",
    [
        "literal$OTHER",
        "${OTHER}",
        "line1\nline2\t\r",
        '"quoted"\\path',
        "юникод",
        "",
    ],
)
@pytest.mark.parametrize("quoted", [False, True])
def test_json_environment_values_are_literal(
    tmp_path, monkeypatch, literal, quoted
):
    monkeypatch.setenv("FIRST", literal)
    monkeypatch.setenv("OTHER", "must not expand")
    file = tmp_path / "config.json"
    placeholder = '"$FIRST"' if quoted else "$FIRST"
    file.write_text('{"value": ' + placeholder + "}")
    assert __config_maker__(str(file))["value"] == literal


def test_json_nested_env_defaults_keys_and_escaped_placeholders(
    tmp_path, monkeypatch
):
    monkeypatch.setenv("KEY", "renamed")
    monkeypatch.setenv("VALUE", "hello")
    monkeypatch.delenv("MISSING", raising=False)
    file = tmp_path / "config.json"
    file.write_text(
        r'{"$KEY": ["${MISSING:-fallback}", "${MISSING:-}", "\u0024VALUE", 5, true, null]}'
    )
    assert __config_maker__(str(file)) == {
        "renamed": ["fallback", "", "hello", 5, True, None]
    }


@pytest.mark.parametrize(
    "content,code",
    [
        ('{"a":"$MISSING_ENV_VAR"}', "configuration.env_var_not_set"),
        ('{"a":', "configuration.json_parse_error"),
    ],
)
def test_json_errors(tmp_path, monkeypatch, content, code):
    monkeypatch.delenv("MISSING_ENV_VAR", raising=False)
    file = tmp_path / "config.json"
    file.write_text(content)
    with pytest.raises(JamConfigurationError) as error:
        __config_maker__(str(file))
    assert error.value.error_code == code


def test_json_missing_file(tmp_path):
    with pytest.raises(JamConfigurationError) as error:
        __config_maker__(str(tmp_path / "missing.json"))
    assert error.value.error_code == "configuration.file_not_found"


@pytest.mark.parametrize(
    "ext,content,pointer",
    [
        ("toml", "[custom.session]\nttl = 45", "custom.session"),
        ("yaml", "custom.session:\n  ttl: 45", "custom.session"),
        ("json", '{"ttl":45}', "ignored"),
    ],
)
def test_direct_session_config_precedence(tmp_path, ext, content, pointer):
    file = tmp_path / f"config.{ext}"
    file.write_text(content)
    backend = RedisSessions(
        config=str(file), pointer=pointer, redis_uri=FakeRedis()
    )
    assert backend.ttl == 45
    assert (
        RedisSessions(
            config=str(file), pointer=pointer, redis_uri=FakeRedis(), ttl=None
        ).ttl
        is None
    )


@pytest.mark.parametrize("cls", [Jam, AsyncJam])
@pytest.mark.parametrize(
    "ext,content",
    [
        ("toml", '[jam.session]\ntype="redis"\ndefault_ttl=25'),
        ("yaml", "jam:\n  session:\n    type: redis\n    default_ttl: 25"),
        ("json", '{"session":{"type":"redis","default_ttl":25}}'),
    ],
)
def test_facade_file_ttl_alias(tmp_path, cls, ext, content):
    file = tmp_path / f"config.{ext}"
    file.write_text(content)
    jam = cls(config=str(file))  # Construction must not contact Redis.
    assert jam.session.ttl == 25


@pytest.mark.parametrize(
    "cfg,path",
    [
        ({"authz": {"rules": []}}, "authz.rules"),
        ({"serializer": 3}, "serializer"),
        ({"jose": {"jwt": {"list": []}}}, "jose.jwt.list"),
        ({"paseto": {"list": True}}, "paseto.list"),
        ({"saml": {"list": 42}}, "saml.list"),
    ],
)
def test_invalid_nested_options_fail_before_construction(cfg, path):
    with pytest.raises(JamConfigurationError) as error:
        Jam(config=cfg)
    assert error.value.error_code == "configuration.invalid_structure"
    assert error.value.details["field"] == path


def test_config_preserves_cache_isolation(tmp_path, monkeypatch):
    from dataclasses import replace
    import jam.utils.config_maker as config_maker

    monkeypatch.setattr(
        config_maker,
        "defaults",
        replace(config_maker.defaults, CONFIG_CACHING=True),
    )
    monkeypatch.setenv("JWT_REVIEW_SECRET", "first")
    file = tmp_path / "cache.json"
    file.write_text(
        '{"jose":{"jwt":{"alg":"HS256","secret_key":"$JWT_REVIEW_SECRET"}}}'
    )
    __config_cache_clear__()
    try:
        first = __config_maker__(str(file))
        first["jose"]["jwt"]["secret_key"] = "mutated"
        monkeypatch.setenv("JWT_REVIEW_SECRET", "second")
        assert (
            __config_maker__(str(file))["jose"]["jwt"]["secret_key"] == "first"
        )
        __config_cache_clear__()
        assert (
            __config_maker__(str(file))["jose"]["jwt"]["secret_key"] == "second"
        )
    finally:
        __config_cache_clear__()

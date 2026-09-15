# -*- coding: utf-8 -*-

"""In-memory Jam instances for application tests.

The test instances deliberately reuse the production facades. Only modules
that perform cryptography, persistence or network I/O are replaced with
small in-memory implementations.
"""

import binascii
from collections.abc import Callable, Iterable, Mapping
import json
import time
from typing import Any
from urllib.parse import urlencode
import uuid

from jam.aio import AsyncJam
from jam.authz import AuthorizationContext, BasePolicy, Principal
from jam.exceptions import (
    JamJWEDecryptionError,
    JamJWSVerificationError,
    JamJWTExpired,
    JamJWTNotYetValid,
    JamPASETOInvalidTokenFormat,
    JamSessionNotFound,
)
from jam.instance import Jam
from jam.jose.utils import (
    __base64url_decode__ as base64url_decode,
)
from jam.jose.utils import (
    __base64url_encode__ as base64url_encode,
)
from jam.subject import BaseSubject


AuthorizationResult = bool | Callable[
    [
        Principal[Any] | BaseSubject | Mapping[str, Any],
        str,
        AuthorizationContext | None,
    ],
    bool,
]


def _json_b64(value: Any) -> str:
    """Serialize a value as base64url-encoded JSON."""
    return base64url_encode(
        json.dumps(value, separators=(",", ":")).encode("utf-8")
    )


def _decode_json(value: str) -> Any:
    """Decode base64url-encoded JSON."""
    return json.loads(base64url_decode(value).decode("utf-8"))


class FakePolicy(BasePolicy):
    """Configurable authorization policy used by test instances."""

    def __init__(self, result: AuthorizationResult = True) -> None:
        """Initialize the policy with a fixed result or callback."""
        self.result = result
        self.calls: list[
            tuple[
                Principal[Any] | BaseSubject | Mapping[str, Any],
                str,
                AuthorizationContext | None,
            ]
        ] = []

    def check(
        self,
        principal: Principal[Any] | BaseSubject | Mapping[str, Any],
        permission: str,
        context: AuthorizationContext | None = None,
    ) -> bool:
        """Return the configured result and record the call."""
        self.calls.append((principal, permission, context))
        if callable(self.result):
            return self.result(principal, permission, context)
        return self.result


class FakeJWS:
    """Unsigned but well-formed JWS implementation."""

    def sign(
        self,
        header: dict[str, Any],
        data: bytes | str | dict[str, Any],
    ) -> str:
        """Serialize test data as compact JWS."""
        if isinstance(data, dict):
            payload = json.dumps(data, separators=(",", ":")).encode()
        elif isinstance(data, str):
            payload = data.encode()
        else:
            payload = data
        return (
            f"{_json_b64(header)}.{base64url_encode(payload)}."
            "test-signature"
        )

    def verify(
        self, token: str, validate: bool = True
    ) -> dict[str, Any]:
        """Deserialize compact JWS without checking its signature."""
        try:
            header, payload, _signature = token.split(".")
            return {
                "header": _decode_json(header),
                "payload": base64url_decode(payload),
            }
        except (
            binascii.Error,
            ValueError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as error:
            raise JamJWSVerificationError from error

    def serialize_compact(
        self, protected: dict[str, Any], payload: bytes | str
    ) -> str:
        """Serialize a compact JWS."""
        return self.sign(protected, payload)

    def deserialize_compact(
        self, serialized: str, validate: bool = True
    ) -> dict[str, Any]:
        """Deserialize a compact JWS."""
        result = self.verify(serialized, validate)
        return {**result, "signature": b"test-signature"}


class FakeJWE:
    """Reversible JWE-shaped serializer for tests."""

    def encrypt(
        self,
        plaintext: bytes | str | dict[str, Any],
        header: dict[str, Any] | None = None,
    ) -> str:
        """Serialize plaintext as compact JWE without encryption."""
        if isinstance(plaintext, dict):
            payload = json.dumps(plaintext, separators=(",", ":")).encode()
        elif isinstance(plaintext, str):
            payload = plaintext.encode()
        else:
            payload = plaintext
        protected = {"alg": "dir", "enc": "test", **(header or {})}
        return (
            f"{_json_b64(protected)}..test-iv."
            f"{base64url_encode(payload)}.test-tag"
        )

    def decrypt(self, token: str) -> bytes:
        """Return plaintext from a test JWE."""
        try:
            parts = token.split(".")
            if len(parts) != 5:
                raise ValueError
            return base64url_decode(parts[3])
        except (binascii.Error, ValueError, UnicodeDecodeError) as error:
            raise JamJWEDecryptionError from error


class FakeJWT:
    """JWT module matching the current public ``jam.jwt`` API."""

    def __init__(self, jws: FakeJWS, jwe: FakeJWE) -> None:
        """Initialize the module with test JOSE primitives."""
        self.jws = jws
        self.jwe = jwe
        self.list = None

    @property
    def jti(self) -> str:
        """Return a unique test token identifier."""
        return f"test-{uuid.uuid4()}"

    def encode(
        self,
        iss: str | None = None,
        sub: str | None = None,
        aud: str | None = None,
        exp: int | None = None,
        nbf: int | None = None,
        jti: str | None = None,
        header: dict[str, Any] | None = None,
        payload: dict[str, Any] | None = None,
    ) -> str:
        """Create an unsigned JWT with production claim semantics."""
        now = int(time.time())
        claims = {
            "jti": jti or self.jti,
            "iat": now,
            "iss": iss,
            "sub": sub,
            "aud": aud,
            "exp": now + exp if exp else None,
            "nbf": now + nbf if nbf is not None else None,
        }
        claims.update(payload or {})
        claims = {key: value for key, value in claims.items() if value is not None}
        protected = {"alg": "none", "typ": "JWT", **(header or {})}
        return self.jws.sign(protected, claims)

    def decode(
        self,
        token: str,
        validate_claims: bool = True,
        check_list: bool = True,
    ) -> dict[str, Any]:
        """Decode a test JWT and optionally validate time claims."""
        result = self.jws.verify(token)
        if result["header"].get("typ") != "JWT":
            raise JamJWSVerificationError
        try:
            payload = json.loads(result["payload"])
        except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise JamJWSVerificationError from error
        if validate_claims:
            now = time.time()
            if payload.get("exp") is not None and payload["exp"] < now:
                raise JamJWTExpired
            if payload.get("nbf") is not None and payload["nbf"] > now:
                raise JamJWTNotYetValid
        return {"header": result["header"], "payload": payload}

    def encrypt(
        self,
        plaintext: bytes | str | dict[str, Any],
        header: dict[str, Any] | None = None,
    ) -> str:
        """Create a test JWE."""
        return self.jwe.encrypt(plaintext, header)

    def decrypt(self, token: str) -> dict[str, Any] | bytes:
        """Decrypt a test JWE, decoding JSON objects when possible."""
        plaintext = self.jwe.decrypt(token)
        try:
            value = json.loads(plaintext)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return plaintext
        return value if isinstance(value, dict) else plaintext


class FakePaseto:
    """Reversible PASETO-shaped serializer for tests."""

    def encode(
        self,
        payload: dict[str, Any],
        footer: dict[str, Any] | str | bytes | None = None,
        serializer: Any = None,
    ) -> str:
        """Create a locally scoped PASETO-shaped token."""
        token = f"v4.local.{_json_b64(payload)}"
        if footer is not None:
            if isinstance(footer, bytes):
                footer_bytes = footer
            elif isinstance(footer, str):
                footer_bytes = footer.encode()
            else:
                footer_bytes = json.dumps(footer).encode()
            token = f"{token}.{base64url_encode(footer_bytes)}"
        return token

    def decode(
        self, token: str, serializer: Any = None
    ) -> tuple[dict[str, Any], Any]:
        """Decode a test PASETO token."""
        try:
            parts = token.split(".")
            if len(parts) not in (3, 4) or parts[:2] != ["v4", "local"]:
                raise ValueError
            payload = _decode_json(parts[2])
            footer = None
            if len(parts) == 4:
                footer_bytes = base64url_decode(parts[3])
                try:
                    footer = json.loads(footer_bytes)
                except (UnicodeDecodeError, json.JSONDecodeError):
                    footer = footer_bytes.decode()
            if not isinstance(payload, dict):
                raise ValueError
            return payload, footer
        except (
            binascii.Error,
            ValueError,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as error:
            raise JamPASETOInvalidTokenFormat from error


class MemorySession:
    """Isolated synchronous in-memory session store."""

    def __init__(self) -> None:
        """Initialize an empty store."""
        self._items: dict[str, tuple[str, dict[str, Any]]] = {}
        self._next_id = 1

    def create(self, session_key: str, data: dict[str, Any]) -> str:
        """Create a session."""
        session_id = f"test-session-{self._next_id}"
        self._next_id += 1
        self._items[session_id] = (session_key, dict(data))
        return session_id

    def get(self, session_id: str) -> dict[str, Any] | None:
        """Get a defensive copy of session data."""
        item = self._items.get(session_id)
        return dict(item[1]) if item is not None else None

    def delete(self, session_id: str) -> None:
        """Delete a session."""
        self._items.pop(session_id, None)

    def update(self, session_id: str, data: dict[str, Any]) -> None:
        """Update an existing session."""
        item = self._items.get(session_id)
        if item is None:
            raise JamSessionNotFound(details={"session_id": session_id})
        item[1].update(data)

    def rework(self, session_id: str) -> str:
        """Rotate an existing session identifier."""
        item = self._items.get(session_id)
        if item is None:
            raise JamSessionNotFound(details={"session_id": session_id})
        new_session_id = self.create(item[0], item[1])
        self.delete(session_id)
        return new_session_id

    def clear(self, session_key: str) -> None:
        """Delete sessions belonging to a key."""
        for session_id, item in list(self._items.items()):
            if item[0] == session_key:
                del self._items[session_id]


class AsyncMemorySession:
    """Asynchronous facade over an isolated in-memory session store."""

    def __init__(self) -> None:
        """Initialize an empty store."""
        self._store = MemorySession()

    async def create(self, session_key: str, data: dict[str, Any]) -> str:
        """Create a session."""
        return self._store.create(session_key, data)

    async def get(self, session_id: str) -> dict[str, Any] | None:
        """Get session data."""
        return self._store.get(session_id)

    async def delete(self, session_id: str) -> None:
        """Delete a session."""
        self._store.delete(session_id)

    async def update(self, session_id: str, data: dict[str, Any]) -> None:
        """Update an existing session."""
        self._store.update(session_id, data)

    async def rework(self, session_id: str) -> str:
        """Rotate an existing session identifier."""
        return self._store.rework(session_id)

    async def clear(self, session_key: str) -> None:
        """Delete sessions belonging to a key."""
        self._store.clear(session_key)


class FakeOTP:
    """Deterministic OTP module."""

    code = "123456"

    def at(self, factor: int | None = None) -> str:
        """Return a deterministic OTP code."""
        return self.code

    def now(self) -> str:
        """Return a deterministic TOTP code."""
        return self.code

    def verify(
        self, code: str, factor: int | None = None, look_ahead: int = 1
    ) -> bool:
        """Validate the deterministic OTP code."""
        return code == self.code

    def provisioning_uri(
        self,
        name: str,
        issuer: str,
        type_: str = "totp",
        counter: int | None = None,
    ) -> str:
        """Create a stable provisioning URI."""
        params = {"secret": "TEST", "issuer": issuer}
        if type_ == "hotp" and counter is not None:
            params["counter"] = str(counter)
        return f"otpauth://{type_}/{issuer}:{name}?{urlencode(params)}"


class FakeOAuth2Client:
    """Network-free OAuth2 client with configurable responses."""

    def __init__(self) -> None:
        """Initialize the default token response."""
        self.token = {
            "access_token": "test-access-token",
            "refresh_token": "test-refresh-token",
            "token_type": "bearer",
        }

    def get_authorization_url(self, scope: list[str]) -> str:
        """Return a stable authorization URL."""
        return f"https://example.test/authorize?{urlencode({'scope': ' '.join(scope)})}"

    def fetch_token(
        self, code: str, grant_type: str = "authorization_code"
    ) -> dict[str, Any]:
        """Return the configured token response."""
        return dict(self.token)

    def refresh_token(
        self, refresh_token: str, grant_type: str = "refresh_token"
    ) -> dict[str, Any]:
        """Return the configured token response."""
        return dict(self.token)

    def client_credentials_flow(
        self, scope: list[str] | None = None
    ) -> dict[str, Any]:
        """Return the configured token response."""
        return dict(self.token)


class AsyncFakeOAuth2Client:
    """Awaitable OAuth2 test client."""

    def __init__(self) -> None:
        """Initialize the default token response."""
        self.token = {
            "access_token": "test-access-token",
            "refresh_token": "test-refresh-token",
            "token_type": "bearer",
        }

    async def get_authorization_url(self, scope: list[str]) -> str:
        """Return a stable authorization URL."""
        return (
            "https://example.test/authorize?"
            f"{urlencode({'scope': ' '.join(scope)})}"
        )

    async def fetch_token(
        self, code: str, grant_type: str = "authorization_code"
    ) -> dict[str, Any]:
        """Return the configured token response."""
        return dict(self.token)

    async def refresh_token(
        self, refresh_token: str, grant_type: str = "refresh_token"
    ) -> dict[str, Any]:
        """Return the configured token response."""
        return dict(self.token)

    async def client_credentials_flow(
        self, scope: list[str] | None = None
    ) -> dict[str, Any]:
        """Return the configured token response."""
        return dict(self.token)


def _install_modules(
    jam: Jam | AsyncJam,
    authorization: AuthorizationResult,
    oauth2_providers: Iterable[str],
    *,
    asynchronous: bool,
) -> None:
    """Install isolated test modules on a production facade."""
    jws = FakeJWS()
    jwe = FakeJWE()
    jam.jws = jws
    jam.jwe = jwe
    jam.jwt = FakeJWT(jws, jwe)
    jam.jose = {"jwt": jam.jwt, "jws": jws, "jwe": jwe}
    jam.session = AsyncMemorySession() if asynchronous else MemorySession()
    jam.paseto = FakePaseto()
    jam.otp = FakeOTP()
    oauth_cls = AsyncFakeOAuth2Client if asynchronous else FakeOAuth2Client
    jam.oauth2 = {name: oauth_cls() for name in oauth2_providers}
    jam._policy = FakePolicy(authorization)


class TestJam(Jam):
    """Synchronous Jam facade backed by isolated in-memory modules."""

    __test__ = False

    def __init__(
        self,
        *,
        authorization: AuthorizationResult = True,
        oauth2_providers: Iterable[str] = (),
        subject: type[BaseSubject] | None = None,
    ) -> None:
        """Initialize a test instance.

        Args:
            authorization: Fixed authorization result or callback.
            oauth2_providers: Provider names to expose under ``jam.oauth2``.
            subject: Subject class used by ``authenticate``.
        """
        super().__init__(config={}, subject=subject)
        _install_modules(
            self,
            authorization,
            oauth2_providers,
            asynchronous=False,
        )

    @property
    def policy(self) -> FakePolicy:
        """Expose the test policy for assertions and runtime configuration."""
        return self._policy  # type: ignore[return-value]


class TestAsyncJam(AsyncJam):
    """Asynchronous Jam facade backed by isolated in-memory modules."""

    __test__ = False

    def __init__(
        self,
        *,
        authorization: AuthorizationResult = True,
        oauth2_providers: Iterable[str] = (),
        subject: type[BaseSubject] | None = None,
    ) -> None:
        """Initialize an asynchronous test instance."""
        super().__init__(config={}, subject=subject)
        _install_modules(
            self,
            authorization,
            oauth2_providers,
            asynchronous=True,
        )

    @property
    def policy(self) -> FakePolicy:
        """Expose the test policy for assertions and runtime configuration."""
        return self._policy  # type: ignore[return-value]


__all__ = [
    "AsyncFakeOAuth2Client",
    "AsyncMemorySession",
    "FakeJWE",
    "FakeJWS",
    "FakeJWT",
    "FakeOAuth2Client",
    "FakeOTP",
    "FakePaseto",
    "FakePolicy",
    "MemorySession",
    "TestAsyncJam",
    "TestJam",
]

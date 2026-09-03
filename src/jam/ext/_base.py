# -*- coding: utf-8 -*-

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

from jam import Jam
from jam.authz import Principal
from jam.exceptions import JamConfigurationError, JamError


@dataclass(frozen=True, slots=True)
class CredentialSource:
    """Describe a place from which an HTTP credential is read."""

    kind: Literal["header", "cookie", "query"]
    name: str
    scheme: str | None = None

    @classmethod
    def bearer(cls, name: str = "Authorization") -> CredentialSource:
        """Create an HTTP Bearer credential source."""
        return cls("header", name, "Bearer")

    @classmethod
    def header(
        cls, name: str, scheme: str | None = None
    ) -> CredentialSource:
        """Create a header credential source."""
        return cls("header", name, scheme)

    @classmethod
    def cookie(cls, name: str) -> CredentialSource:
        """Create a cookie credential source."""
        return cls("cookie", name)

    @classmethod
    def query(cls, name: str) -> CredentialSource:
        """Create a query-string credential source."""
        return cls("query", name)


DEFAULT_SOURCES = (CredentialSource.bearer(),)


@dataclass(frozen=True, slots=True)
class AuthenticationResult:
    """Result of an HTTP authentication attempt."""

    principal: Principal[Any] | None = None
    token: str | None = field(default=None, repr=False)
    source: CredentialSource | None = None
    error: Exception | None = field(default=None, repr=False)

    @property
    def is_authenticated(self) -> bool:
        """Whether a credential was successfully authenticated."""
        return self.principal is not None


class Authenticator:
    """Framework-independent adapter between HTTP and :class:`jam.Jam`."""

    def __init__(
        self,
        jam: Jam,
        *,
        sources: Sequence[CredentialSource] = DEFAULT_SOURCES,
        via: str | None = None,
    ) -> None:
        if not sources:
            raise ValueError("At least one credential source is required.")
        self.jam = jam
        self.sources = tuple(sources)
        self.via = via

    def extract(
        self,
        *,
        headers: Mapping[str, str],
        cookies: Mapping[str, str],
        query: Mapping[str, str] | None = None,
    ) -> tuple[str | None, CredentialSource | None]:
        """Extract the first available credential in configured order."""
        normalized_headers = {
            key.casefold(): value for key, value in headers.items()
        }
        for source in self.sources:
            if source.kind == "header":
                value = normalized_headers.get(source.name.casefold())
            elif source.kind == "cookie":
                value = cookies.get(source.name)
            elif query is not None:
                value = query.get(source.name)
            else:
                continue
            if not value:
                continue
            if source.scheme is not None:
                scheme, separator, credential = value.partition(" ")
                if (
                    not separator
                    or scheme.casefold() != source.scheme.casefold()
                    or not credential
                ):
                    continue
                value = credential.strip()
            if value:
                return value, source
        return None, None

    def authenticate(self, token: str) -> AuthenticationResult:
        """Authenticate one credential without leaking expected failures."""
        try:
            principal = self.jam.authenticate(token, via=self.via)
        except JamConfigurationError:
            raise
        except JamError as error:
            return AuthenticationResult(token=token, error=error)
        return AuthenticationResult(principal=principal, token=token)

    def authenticate_request(
        self,
        *,
        headers: Mapping[str, str],
        cookies: Mapping[str, str],
        query: Mapping[str, str] | None = None,
    ) -> AuthenticationResult:
        """Extract and authenticate a credential from an HTTP request."""
        token, source = self.extract(
            headers=headers,
            cookies=cookies,
            query=query,
        )
        if token is None:
            return AuthenticationResult()
        result = self.authenticate(token)
        return AuthenticationResult(
            principal=result.principal,
            token=result.token,
            source=source,
            error=result.error,
        )


def permissions_from(principal: Principal[Any]) -> list[str]:
    """Return normalized permissions carried by a principal."""
    return sorted(principal.permissions)

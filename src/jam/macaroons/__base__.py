# -*- coding: utf-8 -*-

from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from .core import Macaroon, VerificationResult


class BaseMacaroon(ABC):
    """Independent macaroon protocol interface with explicit root keys."""

    @abstractmethod
    def encode(
        self,
        identifier: bytes | str,
        root_key: bytes | str,
        *,
        location: str = "",
    ) -> str:
        """Create and serialize a root macaroon.

        Args:
            identifier (bytes | str): Nonempty, opaque root identifier.
            root_key (bytes | str): Explicit secret signing key.
            location (str): Optional, unauthenticated location hint.

        Returns:
            str: Base64url-encoded binary v2 macaroon.

        Raises:
            SerializationError: If input or configured limits are invalid.
            ValueError: If the identifier is empty.
            TypeError: If a byte-string input has an unsupported type.
        """
        raise NotImplementedError

    @abstractmethod
    def decode(self, token: bytes | str) -> Macaroon:
        """Decode a macaroon without authenticating it.

        Args:
            token (bytes | str): Base64url-encoded binary v2 macaroon.

        Returns:
            Macaroon: Unverified model suitable for attenuation.

        Raises:
            SerializationError: If the transport is malformed or too large.
        """
        raise NotImplementedError

    @abstractmethod
    def verify(
        self,
        token: bytes | str | Macaroon,
        root_key: bytes | str,
        discharges: Iterable[bytes | str | Macaroon] = (),
        *,
        structured_satisfiers: Mapping[str, Callable[[Any], bool]]
        | None = None,
        collect_structured: bool = False,
    ) -> VerificationResult:
        """Verify signatures and predicates across the discharge graph.

        Args:
            token (bytes | str | Macaroon): Primary token or decoded model.
            root_key (bytes | str): Explicit secret root key.
            discharges (Iterable[bytes | str | Macaroon]): Bound discharges.
            structured_satisfiers (Mapping | None): Callbacks keyed by caveat
                name, accepting its value and returning exactly True.
            collect_structured (bool): Collect unknown structured caveats for
                subsequent policy evaluation instead of rejecting them.
                The caller must enforce every collected caveat before access.

        Returns:
            VerificationResult: Structured caveats from the verified graph.
                This is not a claims mapping or an authorization decision.

        Raises:
            SerializationError: If an encoded token is malformed.
            InvalidCaveatError: If a structured predicate is unknown or invalid.
            VerificationError: If signatures, discharges, predicates, or
                resource limits fail verification. Unknown opaque predicates
                always fail unless an opaque satisfier accepts them.
        """
        raise NotImplementedError

    @abstractmethod
    def satisfy_exact(self, caveat: bytes | str) -> None:
        """Register an accepted opaque predicate.

        Args:
            caveat (bytes | str): Exact opaque predicate to accept.

        Returns:
            None: Registration updates this instance.

        Raises:
            SerializationError: If the predicate cannot be encoded.
            TypeError: If the predicate is neither bytes nor str.
        """
        raise NotImplementedError

    @abstractmethod
    def satisfy_general(self, satisfier: Callable[[bytes], bool]) -> None:
        """Register an opaque predicate callback.

        Args:
            satisfier (Callable[[bytes], bool]): Callback that must return
                exactly True to accept a predicate.

        Returns:
            None: Registration updates this instance.

        Raises:
            TypeError: If the satisfier is not callable.
        """
        raise NotImplementedError

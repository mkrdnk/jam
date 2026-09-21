"""Standard binary macaroon v2 and independent jam:v1 caveat predicates."""

from __future__ import annotations

import base64
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, replace
import hmac
from itertools import islice
import json
from types import MappingProxyType
from typing import Any

from cryptography.exceptions import InvalidTag

from jam.exceptions.macaroons import (
    InvalidCaveatError,
    SerializationError,
    VerificationError,
)

from ._secretbox import decrypt as decrypt_secretbox
from ._secretbox import encrypt as encrypt_secretbox


_PREFIX = "jam:v1:"
_KEY_LABEL = b"macaroons-key-generator"
_BIND_KEY = bytes(32)


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value: object) -> bytes:
    if not isinstance(value, str):
        raise SerializationError("base64 value must be a string")
    try:
        return base64.b64decode(
            value + "=" * (-len(value) % 4), altchars=b"-_", validate=True
        )
    except (ValueError, TypeError) as exc:
        raise SerializationError("invalid base64url value") from exc


def _bytes(value: bytes | str, name: str) -> bytes:
    if isinstance(value, str):
        try:
            return value.encode()
        except UnicodeEncodeError as error:
            raise SerializationError("Invalid UTF-8 string") from error
    if isinstance(value, bytes):
        return value
    raise TypeError(f"{name} must be bytes or str")


def _hmac(key: bytes, message: bytes) -> bytes:
    return hmac.digest(key, message, "sha256")


def _derived(key: bytes) -> bytes:
    return _hmac(_KEY_LABEL, key)


def _hash2(key: bytes, first: bytes, second: bytes) -> bytes:
    return _hmac(key, _hmac(key, first) + _hmac(key, second))


def _bind(primary: bytes, discharge: bytes) -> bytes:
    if hmac.compare_digest(primary, discharge):
        return discharge
    return _hash2(_BIND_KEY, primary, discharge)


def _varint(value: int) -> bytes:
    result = bytearray()
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def _packet(kind: int, value: bytes) -> bytes:
    return bytes([kind]) + _varint(len(value)) + value


class _Reader:
    def __init__(self, data: bytes) -> None:
        self.data = data
        self.offset = 0

    def integer(self) -> int:
        start = self.offset
        value = 0
        for shift in range(0, 63, 7):
            if self.offset >= len(self.data):
                break
            byte = self.data[self.offset]
            self.offset += 1
            value |= (byte & 127) << shift
            if byte < 128:
                if self.data[start : self.offset] != _varint(value):
                    break
                return value
        raise SerializationError("Invalid v2 integer")

    def section(self) -> dict[int, bytes]:
        fields: dict[int, bytes] = {}
        previous = 0
        while True:
            kind = self.integer()
            if kind == 0:
                return fields
            if kind not in (1, 2, 4, 6) or kind <= previous:
                raise SerializationError("Invalid v2 field order")
            previous = kind
            size = self.integer()
            end = self.offset + size
            if end > len(self.data):
                raise SerializationError("Truncated v2 field")
            fields[kind] = self.data[self.offset : end]
            self.offset = end
            if kind == 6:
                return fields


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
        allow_nan=False,
    ).encode()


@dataclass(frozen=True, slots=True)
class Limits:
    """Resource bounds applied while decoding and verifying."""

    serialized_size: int = 64 * 1024
    caveat_payload_size: int = 8 * 1024
    caveat_count: int = 64
    discharge_count: int = 32
    discharge_depth: int = 8

    def __post_init__(self) -> None:
        """Reject negative limits."""
        if any(
            type(value) is not int or value < 0
            for value in (
                self.serialized_size,
                self.caveat_payload_size,
                self.caveat_count,
                self.discharge_count,
                self.discharge_depth,
            )
        ):
            raise ValueError("limits cannot be negative")


DEFAULT_LIMITS = Limits()


@dataclass(frozen=True, slots=True)
class Caveat:
    """A structured first-party caveat."""

    name: str
    value: Any

    def encode(self) -> bytes:
        """Encode this caveat to its canonical payload."""
        if not isinstance(self.name, str) or not self.name:
            raise SerializationError("caveat name must be a non-empty string")
        try:
            return (
                _PREFIX
                + _b64(_canonical({"name": self.name, "value": self.value}))
            ).encode()
        except (UnicodeError, ValueError, TypeError, RecursionError) as exc:
            raise SerializationError("Invalid JSON caveat") from exc

    @classmethod
    def decode(cls, payload: bytes | str) -> Caveat:
        """Decode a canonical structured caveat payload."""
        raw = _bytes(payload, "payload")
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise SerializationError("structured caveat is not ASCII") from exc
        if not text.startswith(_PREFIX):
            raise SerializationError("unknown structured caveat format")
        decoded = _unb64(text[len(_PREFIX) :])
        if _b64(decoded) != text[len(_PREFIX) :]:
            raise SerializationError("Noncanonical base64url caveat")
        try:
            data = json.loads(decoded)
            canonical = _canonical(data)
        except (UnicodeDecodeError, ValueError, RecursionError) as exc:
            raise SerializationError("invalid structured caveat JSON") from exc
        if (
            not isinstance(data, dict)
            or set(data) != {"name", "value"}
            or not isinstance(data["name"], str)
            or not data["name"]
            or canonical != decoded
        ):
            raise SerializationError("non-canonical structured caveat")
        return cls(data["name"], data["value"])


@dataclass(frozen=True, slots=True)
class FirstPartyCaveat:
    """Opaque signed first-party predicate."""

    payload: bytes


@dataclass(frozen=True, slots=True)
class ThirdPartyCaveat:
    """Third-party identifier and encrypted caveat root key."""

    identifier: bytes
    location: str
    verification_id: bytes


MacaroonCaveat = FirstPartyCaveat | ThirdPartyCaveat


@dataclass(frozen=True, slots=True)
class Macaroon:
    """Immutable macaroon token."""

    identifier: bytes
    location: str
    caveats: tuple[MacaroonCaveat, ...]
    signature: bytes

    @classmethod
    def create(
        cls,
        root_key: bytes | str,
        identifier: bytes | str,
        location: str = "",
    ) -> Macaroon:
        """Mint a new primary macaroon."""
        ident = _bytes(identifier, "identifier")
        if not ident:
            raise ValueError("identifier cannot be empty")
        return cls(
            ident,
            location,
            (),
            _hmac(_derived(_bytes(root_key, "root_key")), ident),
        )

    @classmethod
    def create_discharge(
        cls,
        caveat_root_key: bytes | str,
        identifier: bytes | str,
        location: str = "",
    ) -> Macaroon:
        """Create a discharge issued by a third party."""
        return cls.create(caveat_root_key, identifier, location)

    def add_caveat(self, caveat: Caveat | bytes | str) -> Macaroon:
        """Return an attenuated copy with a first-party caveat."""
        payload = (
            caveat.encode()
            if isinstance(caveat, Caveat)
            else _bytes(caveat, "caveat")
        )
        item = FirstPartyCaveat(payload)
        return replace(
            self,
            caveats=(*self.caveats, item),
            signature=_hmac(self.signature, payload),
        )

    def add_third_party_caveat(
        self,
        caveat_root_key: bytes | str,
        identifier: bytes | str,
        location: str = "",
    ) -> Macaroon:
        """Return a copy requiring a third-party discharge."""
        key = _bytes(caveat_root_key, "caveat_root_key")
        ident = _bytes(identifier, "identifier")
        if not ident:
            raise ValueError("identifier cannot be empty")
        verification_id = encrypt_secretbox(self.signature, _derived(key))
        item = ThirdPartyCaveat(ident, location, verification_id)
        return replace(
            self,
            caveats=(*self.caveats, item),
            signature=_hash2(self.signature, verification_id, ident),
        )

    def bind(self, primary: Macaroon | bytes) -> Macaroon:
        """Bind this discharge to a primary macaroon."""
        signature = (
            primary.signature if isinstance(primary, Macaroon) else primary
        )
        bound = _bind(signature, self.signature)
        return replace(self, signature=bound)

    def encode(self, limits: Limits = DEFAULT_LIMITS) -> str:
        """Encode standard binary v2 as base64url."""
        if len(self.caveats) > limits.caveat_count:
            raise SerializationError("Too many caveats")
        raw_size = 1

        def count_field(payload: bytes | str) -> None:
            nonlocal raw_size
            if len(payload) > limits.serialized_size:
                raise SerializationError("serialized macaroon is too large")
            length = len(_bytes(payload, "field"))
            raw_size += 1 + len(_varint(length)) + length
            if (raw_size * 8 + 5) // 6 > limits.serialized_size:
                raise SerializationError("serialized macaroon is too large")

        if self.location:
            count_field(self.location)
        count_field(self.identifier)
        raw_size += 1
        for item in self.caveats:
            if isinstance(item, FirstPartyCaveat):
                size = len(item.payload)
                count_field(item.payload)
            else:
                if item.location:
                    count_field(item.location)
                count_field(item.identifier)
                count_field(item.verification_id)
                size = (
                    len(item.identifier)
                    + len(item.location.encode())
                    + len(item.verification_id)
                )
            if size > limits.caveat_payload_size:
                raise SerializationError("Caveat is too large")
            raw_size += 1
        raw_size += 1
        count_field(self.signature)
        data = bytearray(b"\x02")
        if self.location:
            data.extend(_packet(1, self.location.encode()))
        data.extend(_packet(2, self.identifier) + b"\x00")
        for item in self.caveats:
            if isinstance(item, FirstPartyCaveat):
                payload = item.payload
                data.extend(_packet(2, payload))
            else:
                payload = item.identifier
                if item.location:
                    data.extend(_packet(1, item.location.encode()))
                data.extend(_packet(2, payload))
                data.extend(_packet(4, item.verification_id))
            if len(payload) > limits.caveat_payload_size:
                raise SerializationError("Caveat is too large")
            data.append(0)
        data.extend(b"\x00" + _packet(6, self.signature))
        result = _b64(bytes(data))
        if len(result) > limits.serialized_size:
            raise SerializationError("serialized macaroon is too large")
        return result

    @classmethod
    def decode(
        cls, token: bytes | str, limits: Limits = DEFAULT_LIMITS
    ) -> Macaroon:
        """Strictly decode a transport token."""
        raw = _bytes(token, "token")
        if len(raw) > limits.serialized_size:
            raise SerializationError("serialized macaroon is too large")
        try:
            text = raw.decode("ascii")
        except UnicodeDecodeError as exc:
            raise SerializationError("macaroon is not ASCII") from exc
        packed = _unb64(text)
        if _b64(packed) != text or not packed.startswith(b"\x02"):
            raise SerializationError("Invalid v2 transport")
        reader = _Reader(packed)
        reader.offset = 1
        header = reader.section()
        if set(header) not in ({2}, {1, 2}) or not header[2]:
            raise SerializationError("Invalid v2 header")
        caveats: list[MacaroonCaveat] = []
        while fields := reader.section():
            if len(caveats) >= limits.caveat_count:
                raise SerializationError("Too many caveats")
            if set(fields) not in ({2}, {2, 4}, {1, 2, 4}):
                raise SerializationError("Invalid v2 caveat")
            payload = fields[2]
            if 4 not in fields:
                if len(payload) > limits.caveat_payload_size:
                    raise SerializationError("Caveat is too large")
                caveats.append(FirstPartyCaveat(payload))
            else:
                if not payload or len(fields[4]) != 72:
                    raise SerializationError("Invalid verification identifier")
                location = _location(fields.get(1, b""))
                if (
                    len(payload) + len(location.encode()) + len(fields[4])
                    > limits.caveat_payload_size
                ):
                    raise SerializationError("Caveat is too large")
                caveats.append(ThirdPartyCaveat(payload, location, fields[4]))
        final = reader.section()
        if (
            set(final) != {6}
            or len(final[6]) != 32
            or reader.offset != len(packed)
        ):
            raise SerializationError("Invalid v2 signature")
        return cls(
            header[2],
            _location(header.get(1, b"")),
            tuple(caveats),
            final[6],
        )


def _location(value: bytes) -> str:
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SerializationError("Invalid location") from exc


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Structured caveats collected from the validated token graph."""

    caveats: tuple[Caveat, ...]


OpaqueSatisfier = Callable[[bytes], bool]


def _freeze_json(value: Any) -> Any:
    """Return an immutable snapshot of a decoded JSON value."""
    if isinstance(value, dict):
        return MappingProxyType(
            {key: _freeze_json(item) for key, item in value.items()}
        )
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    return value


def _satisfied(check: Callable[[Any], bool], value: Any) -> bool:
    try:
        return check(value) is True
    except Exception as error:
        raise VerificationError("Caveat satisfier failed") from error


def _verify(
    macaroon: Macaroon,
    root_key: bytes | str,
    discharges: Iterable[Macaroon] = (),
    *,
    limits: Limits = DEFAULT_LIMITS,
    exact_satisfiers: set[bytes] | frozenset[bytes] = frozenset(),
    general_satisfiers: Iterable[OpaqueSatisfier] = (),
    structured_satisfiers: Mapping[str, Callable[[Any], bool]] | None = None,
    collect_structured: bool = False,
) -> VerificationResult:
    """Privately validate a decoded macaroon and its discharge graph."""
    supplied = tuple(islice(discharges, limits.discharge_count + 1))
    if len(supplied) > limits.discharge_count:
        raise VerificationError("too many discharges")
    by_id: dict[bytes, list[Macaroon]] = {}
    for discharge in supplied:
        by_id.setdefault(discharge.identifier, []).append(discharge)
    used: set[int] = set()
    pending: list[bytes] = []
    _verify_one(
        macaroon,
        _derived(_bytes(root_key, "root_key")),
        macaroon.signature,
        by_id,
        pending,
        used,
        frozenset(),
        0,
        [0],
        limits,
    )
    collected: list[Caveat] = []
    checks = tuple(general_satisfiers)
    for payload in pending:
        if payload.startswith(_PREFIX.encode()):
            try:
                parsed = Caveat.decode(payload)
            except SerializationError as exc:
                raise InvalidCaveatError("Invalid caveat") from exc
            parsed = Caveat(parsed.name, _freeze_json(parsed.value))
            check = (structured_satisfiers or {}).get(parsed.name)
            if check is None:
                if not collect_structured:
                    raise InvalidCaveatError("Unknown caveat")
            elif not _satisfied(check, parsed.value):
                raise VerificationError("Caveat is not satisfied")
            collected.append(parsed)
        elif payload.startswith(b"jam:"):
            raise InvalidCaveatError("Unsupported caveat version")
        elif payload not in exact_satisfiers and not any(
            _satisfied(check, payload) for check in checks
        ):
            raise VerificationError("Opaque caveat is not satisfied")
    return VerificationResult(tuple(collected))


def _verify_one(
    macaroon: Macaroon,
    root_key: bytes,
    primary_signature: bytes,
    by_id: Mapping[bytes, list[Macaroon]],
    pending: list[bytes],
    used: set[int],
    path: frozenset[int],
    depth: int,
    caveat_count: list[int],
    limits: Limits,
) -> None:
    if depth > limits.discharge_depth:
        raise VerificationError("maximum discharge depth exceeded")
    identity = id(macaroon)
    if identity in used or identity in path:
        raise VerificationError("Discharge reuse")
    used.add(identity)
    caveat_count[0] += len(macaroon.caveats)
    if caveat_count[0] > limits.caveat_count:
        raise VerificationError("too many caveats")
    if (
        not macaroon.identifier
        or len(macaroon.identifier) > limits.serialized_size
        or len(macaroon.signature) != 32
    ):
        raise VerificationError("Invalid macaroon")
    path = path | {identity}
    signature = _hmac(root_key, macaroon.identifier)
    for item in macaroon.caveats:
        if isinstance(item, FirstPartyCaveat):
            if len(item.payload) > limits.caveat_payload_size:
                raise VerificationError("caveat payload is too large")
            pending.append(item.payload)
            signature = _hmac(signature, item.payload)
            continue
        if len(item.verification_id) != 72:
            raise VerificationError("invalid verification id")
        if (
            len(item.identifier)
            + len(item.location.encode())
            + len(item.verification_id)
            > limits.caveat_payload_size
        ):
            raise VerificationError("caveat payload is too large")
        try:
            caveat_key = decrypt_secretbox(signature, item.verification_id)
        except (InvalidTag, ValueError) as exc:
            raise VerificationError("cannot decrypt caveat key") from exc
        matches = by_id.get(item.identifier, ())
        if len(matches) != 1:
            raise VerificationError("missing or ambiguous discharge")
        _verify_one(
            matches[0],
            caveat_key,
            primary_signature,
            by_id,
            pending,
            used,
            path,
            depth + 1,
            caveat_count,
            limits,
        )
        signature = _hash2(signature, item.verification_id, item.identifier)
    expected = signature
    if depth:
        expected = _bind(primary_signature, expected)
    if not hmac.compare_digest(expected, macaroon.signature):
        raise VerificationError("invalid macaroon signature")

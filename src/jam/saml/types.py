# -*- coding: utf-8 -*-

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any


__all__ = [
    "SAMLSubjectConfirmation",
    "SAMLSubject",
    "SAMLConditions",
    "SAMLAuthnStatement",
    "SAMLAssertion",
    "SAMLResponse",
    "SAMLRequest",
    "SAMLLogoutRequest",
    "SAMLLogoutResponse",
    "SAMLMetadata",
    "SAMLAttributeQuery",
    "SAMLArtifactResolve",
    "SAMLArtifactResponse",
    "SAMLManageNameIDRequest",
    "SAMLManageNameIDResponse",
]


@dataclass
class SAMLSubjectConfirmation:
    """One SAML subject confirmation method and its constraint data."""

    method: str | None
    data: dict[str, Any] | None = None


@dataclass
class SAMLSubject:
    """SAML assertion subject (NameID + confirmation)."""

    name_id: str
    format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
    subject_confirmation_method: str | None = None
    subject_confirmation_data: dict[str, Any] | None = None
    confirmations: list[SAMLSubjectConfirmation] = field(default_factory=list)


@dataclass
class SAMLConditions:
    """SAML assertion conditions (time constraints + audience)."""

    not_before: datetime | None = None
    not_on_or_after: datetime | None = None
    audience_restriction: list[str] = field(default_factory=list)
    audience_restrictions: list[list[str]] = field(default_factory=list)


@dataclass
class SAMLAuthnStatement:
    """SAML authentication statement."""

    authn_instant: datetime
    session_index: str | None = None


@dataclass
class SAMLAssertion:
    """Parsed SAML assertion data."""

    id: str
    issuer: str
    issue_instant: datetime
    subject: SAMLSubject | None = None
    conditions: SAMLConditions | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    authn_statement: SAMLAuthnStatement | None = None


@dataclass
class SAMLResponse:
    """Parsed SAML protocol Response."""

    id: str
    issuer: str
    issue_instant: datetime
    status_code: str = "urn:oasis:names:tc:SAML:2.0:status:Success"
    destination: str | None = None
    in_response_to: str | None = None
    assertion: SAMLAssertion | None = None


@dataclass
class SAMLRequest:
    """Parsed SAML AuthnRequest."""

    id: str
    issuer: str | None
    issue_instant: datetime
    destination: str | None = None
    acs_url: str | None = None
    binding: str | None = None


@dataclass
class SAMLLogoutRequest:
    """Parsed SAML LogoutRequest."""

    id: str
    issuer: str | None
    issue_instant: datetime
    name_id: str
    session_index: str | None = None
    destination: str | None = None


@dataclass
class SAMLLogoutResponse:
    """Parsed SAML LogoutResponse."""

    id: str
    issuer: str | None
    issue_instant: datetime
    status_code: str = "urn:oasis:names:tc:SAML:2.0:status:Success"
    destination: str | None = None
    in_response_to: str | None = None


@dataclass
class SAMLMetadata:
    """Parsed SAML metadata."""

    entity_id: str
    role: str
    sso_url: str | None = None
    acs_url: str | None = None
    certificate: str | None = None
    want_authn_requests_signed: bool = False
    authn_requests_signed: bool = False


@dataclass
class SAMLAttributeQuery:
    """Parsed SAML AttributeQuery."""

    id: str
    issuer: str | None
    issue_instant: datetime
    subject: str
    destination: str | None = None
    attribute_names: list[str] | None = None


@dataclass
class SAMLArtifactResolve:
    """Parsed SAML ArtifactResolve."""

    id: str
    issuer: str | None
    issue_instant: datetime
    artifact: str


@dataclass
class SAMLArtifactResponse:
    """Parsed SAML ArtifactResponse."""

    id: str
    issuer: str | None
    issue_instant: datetime
    status_code: str = "urn:oasis:names:tc:SAML:2.0:status:Success"
    in_response_to: str | None = None
    original_message: str | None = None


@dataclass
class SAMLManageNameIDRequest:
    """Parsed SAML ManageNameIDRequest."""

    id: str
    issuer: str | None
    issue_instant: datetime
    name_id: str
    new_id: str | None = None
    destination: str | None = None


@dataclass
class SAMLManageNameIDResponse:
    """Parsed SAML ManageNameIDResponse."""

    id: str
    issuer: str | None
    issue_instant: datetime
    status_code: str = "urn:oasis:names:tc:SAML:2.0:status:Success"
    destination: str | None = None
    in_response_to: str | None = None

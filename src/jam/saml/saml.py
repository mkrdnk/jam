# -*- coding: utf-8 -*-

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import os
from typing import TYPE_CHECKING, Any
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

from jam.exceptions.saml import (
    JamSAMLEmptyPrivateKey,
    JamSAMLExpired,
    JamSAMLInvalidAudience,
    JamSAMLInvalidIssuer,
    JamSAMLInvalidRecipient,
    JamSAMLNotYetValid,
    JamSAMLReplayDetected,
    JamSAMLSOAPError,
    JamSAMLValidationError,
)
from jam.saml.__base__ import BaseSAML
from jam.saml.binding import (
    build_redirect_url,
    decode_post,
    decode_redirect,
    encode_post,
    encode_redirect,
    parse_redirect_request,
)
from jam.saml.encryption import (
    decrypt_assertion,
    encrypt_assertion,
    load_encryption_key,
)
from jam.saml.metadata import (
    generate_idp_metadata,
    generate_sp_metadata,
    parse_metadata,
)
from jam.saml.signature import (
    extract_key_id_from_keyinfo,
    load_private_key,
    load_public_key,
    sign_assertion,
    verify_assertion_signature,
)
from jam.saml.types import (
    SAMLArtifactResolve,
    SAMLArtifactResponse,
    SAMLAttributeQuery,
    SAMLAuthnStatement,
    SAMLConditions,
    SAMLLogoutRequest,
    SAMLLogoutResponse,
    SAMLManageNameIDRequest,
    SAMLManageNameIDResponse,
    SAMLMetadata,
    SAMLRequest,
    SAMLResponse,
    SAMLSubject,
)
from jam.saml.types import (
    SAMLAssertion as SAMLAssertionData,
)
from jam.saml.xml import (
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
    CM_BEARER,
    NAMEID_UNSPECIFIED,
    NS_DS,
    NS_SAML,
    NS_SAMLP,
    NS_SOAP,
    STATUS_SUCCESS,
    fmt_instant,
    make_element,
    make_id,
    parse_instant,
    register_namespaces,
    safe_fromstring,
    sub_element,
)
from jam.utils.config_maker import __key_loader__
from jam.utils.config_meta import ConfigMeta


if TYPE_CHECKING:
    from jam.keychain import BaseKeyChain


class SAML(BaseSAML, metaclass=ConfigMeta):
    """Concrete SAML 2.0 implementation."""

    _CONFIG_POINTER = "jam.saml"

    def __init__(
        self,
        *,
        role: str = "sp",
        private_key: str | None = None,
        public_key: str | None = None,
        certificate: str | None = None,
        entity_id: str | None = None,
        acs_url: str | None = None,
        sso_url: str | None = None,
        idp_public_key: str | None = None,
        sp_public_key: str | None = None,
        encryption_key: str | None = None,
        default_exp: int = 300,
        allowed_clock_skew: int = 120,
        want_assertions_signed: bool = True,
        id_store: dict | None = None,
        replay_ttl: int = 300,
        keychain: BaseKeyChain | None = None,
        config: str | dict[str, Any] | None = None,
        pointer: str | None = None,
    ) -> None:
        """Initialize SAML instance.

        Args:
            role: ``"sp"`` or ``"idp"``.
            private_key: PEM string or path to private key file.
            public_key: PEM string or path to public key / certificate.
            certificate: PEM cert string (included in metadata/KeyInfo).
            entity_id: Entity ID of this party.
            acs_url: ACS URL (``sp`` role).
            sso_url: SSO URL (``idp`` role).
            idp_public_key: IdP public key for signature verification (``sp``).
            sp_public_key: SP public key for signature verification (``idp``).
            encryption_key: SP public key PEM for assertion encryption (``idp``).
            default_exp: Default assertion lifetime in seconds.
            allowed_clock_skew: Clock skew tolerance in seconds (default 120).
            want_assertions_signed: Require signed assertions (``sp``, default True).
            id_store: Dict for replay attack protection. Auto-created if None.
            replay_ttl: Seconds before a consumed ID is eligible for cleanup.
            keychain: Key lifecycle manager for SAML signing and verification.
            config: Configuration dict or file path.
            pointer: Config pointer. Defaults to ``"jam.saml"``.
        """
        register_namespaces()

        self.role = role.lower()
        self._entity_id = entity_id
        self._acs_url = acs_url
        self._sso_url = sso_url
        self._default_exp = default_exp
        self._allowed_clock_skew = allowed_clock_skew
        self._want_assertions_signed = want_assertions_signed
        self._replay_ttl = replay_ttl
        self.keychain = keychain
        self._id_store: dict[str, float] = (
            id_store if id_store is not None else {}
        )

        self._private_key: Any = None
        self._public_key: Any = None
        self._certificate: str | None = certificate
        self._encryption_key: Any = None
        self._idp_public_key: Any = None
        self._sp_public_key: Any = None

        if private_key:
            pem = __key_loader__(private_key)
            self._private_key = load_private_key(pem)

        if public_key:
            pem = __key_loader__(public_key)
            self._public_key = load_public_key(pem)

        if idp_public_key:
            pem = __key_loader__(idp_public_key)
            self._idp_public_key = load_public_key(pem)
        else:
            self._idp_public_key = None

        if sp_public_key:
            pem = __key_loader__(sp_public_key)
            self._sp_public_key = load_public_key(pem)
        else:
            self._sp_public_key = None

        if encryption_key:
            pem = __key_loader__(encryption_key)
            self._encryption_key = load_encryption_key(pem)
        else:
            self._encryption_key = None

    def _signing_key(self) -> tuple[Any, str | None]:
        """Return the configured static or current KeyChain signing key."""
        if self.keychain is not None:
            key_id, material = self.keychain._material_for_issue()
            return load_private_key(material.decode("utf-8")), key_id
        return self._private_key, None

    def _sign_element(self, element: ET.Element) -> None:
        """Sign an XML element with the active static or KeyChain key."""
        signing_key, key_id = self._signing_key()
        sign_assertion(
            element,
            signing_key,
            self._certificate,
            key_id=key_id,
        )

    def _verification_key(self, assertion: ET.Element) -> Any:
        """Resolve the verification key for a signed assertion."""
        if self.keychain is None:
            return self._idp_public_key
        key_id = extract_key_id_from_keyinfo(assertion)
        material = self.keychain._material_for_verify(key_id)
        return load_public_key(material.decode("utf-8"))

    # ── Replay protection ──

    def _check_replay(self, msg_id: str) -> None:
        """Check if a message ID has already been consumed (replay attack).

        Args:
            msg_id: SAML message ID (``ID`` attribute).

        Raises:
            JamSAMLReplayDetected: If the ID was already seen.
        """
        self._purge_stale_ids()
        if msg_id in self._id_store:
            raise JamSAMLReplayDetected
        self._id_store[msg_id] = datetime.now(timezone.utc).timestamp()

    def _mark_consumed(self, msg_id: str) -> None:
        """Mark a locally-generated message ID as consumed.

        Args:
            msg_id: SAML message ID.
        """
        self._id_store[msg_id] = datetime.now(timezone.utc).timestamp()

    def _purge_stale_ids(self, now: float | None = None) -> None:
        """Remove consumed IDs older than ``replay_ttl``."""
        if now is None:
            now = datetime.now(timezone.utc).timestamp()
        cutoff = now - self._replay_ttl
        stale = [k for k, ts in self._id_store.items() if ts < cutoff]
        for k in stale:
            del self._id_store[k]

    # ── SP operations ──

    def prepare_authn_request(
        self,
        idp_sso_url: str,
        *,
        acs_url: str | None = None,
        binding: str = "redirect",
        **kwargs: Any,
    ) -> str:
        """Build AuthnRequest and return IdP redirect URL or POST form data.

        Args:
            idp_sso_url: IdP SSO endpoint URL.
            acs_url: SP ACS URL.
            binding: ``"redirect"`` or ``"post"``.
            **kwargs: relay_state, issuer, etc.

        Returns:
            Redirect URL (``binding="redirect"``) or Base64 form data (``"post"``).
        """
        request_id = make_id()
        now = fmt_instant()

        authn = make_element("AuthnRequest", NS_SAMLP)
        authn.set("ID", request_id)
        authn.set("Version", "2.0")
        authn.set("IssueInstant", now)
        authn.set("Destination", idp_sso_url)

        acs = acs_url or self._acs_url
        if acs:
            authn.set("AssertionConsumerServiceURL", acs)

        if binding == "post":
            authn.set("ProtocolBinding", BINDING_HTTP_POST)
        else:
            authn.set("ProtocolBinding", BINDING_HTTP_REDIRECT)

        entity_id = kwargs.get("issuer") or self._entity_id
        if entity_id:
            sub_element(authn, "Issuer", NS_SAML, text=entity_id)

        relay_state = kwargs.get("relay_state") or ""

        self._mark_consumed(request_id)
        xml_str = ET.tostring(authn, encoding="unicode")

        if binding == "post":
            return encode_post(xml_str)

        params = {"SAMLRequest": encode_redirect(xml_str)}
        if relay_state:
            params["RelayState"] = relay_state

        return build_redirect_url(
            idp_sso_url,
            params,
            signing_key=self._signing_key()[0],
        )

    def parse_response(
        self,
        saml_response: str,
        *,
        binding: str = "post",
        **kwargs: Any,
    ) -> SAMLResponse:
        """Parse and validate a SAML Response from an IdP.

        Args:
            saml_response: Raw SAMLResponse (Base64 POST or query-string).
            binding: ``"post"`` or ``"redirect"``.
            **kwargs: audience, issuer, verify_signature.

        Returns:
            SAMLResponse with parsed assertion data.
        """
        if binding == "post":
            xml_str = decode_post(saml_response)
        elif binding == "redirect":
            xml_str = decode_redirect(saml_response)
        else:
            raise JamSAMLValidationError(
                message=f"Unknown binding: {binding}",
            )

        root = safe_fromstring(xml_str)
        response_id = root.get("ID", "")
        response_iss = _find_text(root, "Issuer", NS_SAML) or ""
        response_instant = parse_instant(root.get("IssueInstant", ""))
        destination = root.get("Destination")
        in_response_to = root.get("InResponseTo")

        self._check_replay(response_id)

        status_code = _parse_status(root)

        assertion_elem = root.find(f"{{{NS_SAML}}}Assertion")
        if assertion_elem is None:
            enc_assertion_elem = root.find(
                f"{{{NS_SAML}}}EncryptedAssertion",
            )
            if enc_assertion_elem is not None:
                if self._private_key is None:
                    raise JamSAMLValidationError(
                        message=(
                            "private_key is required to decrypt "
                            "EncryptedAssertion."
                        ),
                    )
                assertion_elem = decrypt_assertion(
                    enc_assertion_elem,
                    self._private_key,
                )

        assertion_data = None
        if assertion_elem is not None:
            assertion_data = self._parse_assertion(
                assertion_elem,
                **kwargs,
            )

        result = SAMLResponse(
            id=response_id,
            issuer=response_iss,
            issue_instant=response_instant,
            status_code=status_code,
            destination=destination,
            in_response_to=in_response_to,
            assertion=assertion_data,
        )

        expected_issuer = kwargs.get("issuer")
        if expected_issuer and response_iss != expected_issuer:
            raise JamSAMLInvalidIssuer

        return result

    def _parse_assertion(
        self,
        assertion_elem: ET.Element,
        **kwargs: Any,
    ) -> SAMLAssertionData:
        assertion_id = assertion_elem.get("ID", "")
        issue_instant = parse_instant(assertion_elem.get("IssueInstant", ""))
        issuer = _find_text(assertion_elem, "Issuer", NS_SAML) or ""

        verify_sig = kwargs.get(
            "verify_signature", self._want_assertions_signed
        )
        if verify_sig:
            verify_key = self._verification_key(assertion_elem)
            if verify_key:
                verify_assertion_signature(assertion_elem, verify_key)
            else:
                verify_assertion_signature(assertion_elem)

        subject = _parse_subject(assertion_elem)
        conditions = _parse_conditions(assertion_elem)
        attributes = _parse_attributes(assertion_elem)
        authn = _parse_authn_statement(assertion_elem)

        skew = timedelta(seconds=self._allowed_clock_skew)
        now = datetime.now(timezone.utc)

        if conditions:
            if conditions.not_before and now + skew < conditions.not_before:
                raise JamSAMLNotYetValid
            if (
                conditions.not_on_or_after
                and now - skew >= conditions.not_on_or_after
            ):
                raise JamSAMLExpired

            expected_audience = kwargs.get("audience")
            if expected_audience and conditions.audience_restriction:
                if expected_audience not in conditions.audience_restriction:
                    raise JamSAMLInvalidAudience

        expected_acs = kwargs.get("acs_url") or self._acs_url
        if expected_acs and subject and subject.subject_confirmation_data:
            recipient = subject.subject_confirmation_data.get("Recipient")
            if recipient and recipient != expected_acs:
                raise JamSAMLInvalidRecipient

        expected_issuer = kwargs.get("issuer")
        if expected_issuer and issuer != expected_issuer:
            raise JamSAMLInvalidIssuer

        return SAMLAssertionData(
            id=assertion_id,
            issuer=issuer,
            issue_instant=issue_instant,
            subject=subject,
            conditions=conditions,
            attributes=attributes,
            authn_statement=authn,
        )

    # ── IdP operations ──

    def _build_assertion_xml(
        self,
        subject: str,
        attributes: dict[str, Any],
        issuer: str,
        audience: str,
        assertion_id: str,
        now: datetime,
        *,
        include_authn_statement: bool = True,
        **kwargs: Any,
    ) -> ET.Element:
        """Build a signed SAML Assertion Element.

        Args:
            subject: Subject identifier.
            attributes: User attributes.
            issuer: Issuer entity ID.
            audience: Audience entity ID.
            assertion_id: ID for the assertion.
            now: Current time.
            include_authn_statement: Whether to include AuthnStatement.
            **kwargs: destination, in_response_to, name_id_format,
                      session_index, expires_in, and not_before.

        Returns:
            Signed Assertion ET.Element.
        """
        now_str = fmt_instant(now)
        expires_in = kwargs.get("expires_in")
        if expires_in is None:
            expires_in = self._default_exp
        not_before = kwargs.get("not_before")
        if not_before is None:
            not_before = 0
        not_before_str = fmt_instant(
            datetime.fromtimestamp(
                now.timestamp() + not_before,
                tz=timezone.utc,
            )
        )
        exp_str = fmt_instant(
            datetime.fromtimestamp(
                now.timestamp() + expires_in,
                tz=timezone.utc,
            )
        )

        destination = (
            kwargs.get("destination") or kwargs.get("acs_url") or self._acs_url
        )
        in_response_to = kwargs.get("in_response_to")

        assertion = make_element("Assertion", NS_SAML)
        assertion.set("ID", assertion_id)
        assertion.set("Version", "2.0")
        assertion.set("IssueInstant", now_str)

        sub_element(assertion, "Issuer", NS_SAML, text=issuer)

        subject_elem = make_element("Subject", NS_SAML)
        assertion.append(subject_elem)

        name_id_format = kwargs.get("name_id_format", NAMEID_UNSPECIFIED)
        sub_element(
            subject_elem,
            "NameID",
            NS_SAML,
            text=subject,
            attrib={"Format": name_id_format},
        )

        subj_conf = make_element("SubjectConfirmation", NS_SAML)
        subj_conf.set("Method", CM_BEARER)
        subject_elem.append(subj_conf)

        scd_attrib: dict[str, str] = {"NotOnOrAfter": exp_str}
        if destination:
            scd_attrib["Recipient"] = destination
        if in_response_to:
            scd_attrib["InResponseTo"] = in_response_to
        sub_element(
            subj_conf, "SubjectConfirmationData", NS_SAML, attrib=scd_attrib
        )

        conditions = make_element("Conditions", NS_SAML)
        conditions.set("NotBefore", not_before_str)
        conditions.set("NotOnOrAfter", exp_str)
        assertion.append(conditions)

        aud_restriction = sub_element(
            conditions, "AudienceRestriction", NS_SAML
        )
        sub_element(aud_restriction, "Audience", NS_SAML, text=audience)

        if attributes:
            attr_stmt = make_element("AttributeStatement", NS_SAML)
            assertion.append(attr_stmt)
            for name, value in attributes.items():
                attr = sub_element(
                    attr_stmt, "Attribute", NS_SAML, attrib={"Name": name}
                )
                if isinstance(value, list):
                    for v in value:
                        sub_element(
                            attr, "AttributeValue", NS_SAML, text=str(v)
                        )
                else:
                    sub_element(
                        attr, "AttributeValue", NS_SAML, text=str(value)
                    )

        if include_authn_statement:
            authn_stmt = make_element("AuthnStatement", NS_SAMLP)
            authn_stmt.set("AuthnInstant", now_str)
            session_index = kwargs.get("session_index") or make_id()
            authn_stmt.set("SessionIndex", session_index)
            assertion.append(authn_stmt)

        self._sign_element(assertion)

        return assertion

    def build_response(
        self,
        subject: str,
        attributes: dict[str, Any],
        *,
        issuer: str,
        audience: str,
        **kwargs: Any,
    ) -> str:
        """Build and sign a SAML Response with an Assertion.

        Args:
            subject: Authenticated user identifier.
            attributes: User attributes dict.
            issuer: IdP entity ID.
            audience: SP entity ID.
            **kwargs: in_response_to, name_id_format, session_index,
                      destination, encrypt (bool, default False),
                      expires_in, not_before, and assertion_id.

        Returns:
            Signed (and optionally encrypted) SAML Response XML string.
        """
        if self._private_key is None and self.keychain is None:
            raise JamSAMLEmptyPrivateKey

        response_id = make_id()
        assertion_id = kwargs.pop("assertion_id", None) or make_id()
        now = datetime.now(timezone.utc)
        now_str = fmt_instant(now)

        response = make_element("Response", NS_SAMLP)
        response.set("ID", response_id)
        response.set("Version", "2.0")
        response.set("IssueInstant", now_str)

        in_response_to = kwargs.get("in_response_to")
        if in_response_to:
            response.set("InResponseTo", in_response_to)

        destination = (
            kwargs.get("destination") or kwargs.get("acs_url") or self._acs_url
        )
        if destination:
            response.set("Destination", destination)

        sub_element(response, "Issuer", NS_SAML, text=issuer)

        status = make_element("Status", NS_SAMLP)
        response.append(status)
        sc = sub_element(status, "StatusCode", NS_SAMLP)
        sc.set("Value", STATUS_SUCCESS)

        assertion = self._build_assertion_xml(
            subject,
            attributes,
            issuer,
            audience,
            assertion_id,
            now,
            include_authn_statement=True,
            **kwargs,
        )
        response.append(assertion)

        encrypt = kwargs.get("encrypt", False)
        if encrypt:
            if self._encryption_key is None:
                raise JamSAMLValidationError(
                    message=("encryption_key is required when encrypt=True"),
                )
            enc_assertion = encrypt_assertion(
                assertion,
                self._encryption_key,
            )
            response.remove(assertion)
            response.append(enc_assertion)

        self._mark_consumed(response_id)
        self._mark_consumed(assertion_id)
        return ET.tostring(response, encoding="unicode")

    def parse_authn_request(
        self,
        saml_request: str,
        *,
        binding: str = "redirect",
        **kwargs: Any,
    ) -> SAMLRequest:
        """Parse an incoming AuthnRequest from an SP.

        Args:
            saml_request: Raw SAMLRequest data.
            binding: ``"redirect"`` or ``"post"``.
            **kwargs: issuer (expected issuer for validation).

        Returns:
            Parsed SAMLRequest.
        """
        if binding == "redirect":
            req, relay_state = parse_redirect_request(
                saml_request,
                verify_key=self._public_key,
            )
        elif binding == "post":
            req = decode_post(saml_request)
        else:
            raise JamSAMLValidationError(
                message=f"Unknown binding: {binding}",
            )

        root = safe_fromstring(req)
        request_id = root.get("ID", "")
        destination = root.get("Destination")
        acs_url = root.get("AssertionConsumerServiceURL")
        issue_instant = parse_instant(root.get("IssueInstant", ""))
        protocol_binding = root.get("ProtocolBinding")
        issuer = _find_text(root, "Issuer", NS_SAML)

        self._check_replay(request_id)

        expected_issuer = kwargs.get("issuer")
        if expected_issuer and issuer != expected_issuer:
            raise JamSAMLInvalidIssuer

        return SAMLRequest(
            id=request_id,
            issuer=issuer,
            issue_instant=issue_instant,
            destination=destination,
            acs_url=acs_url,
            binding=protocol_binding,
        )

    # ── Attribute Query ──

    def build_attribute_query(
        self,
        subject: str,
        *,
        issuer: str,
        destination: str,
        attribute_names: list[str] | None = None,
        binding: str = "post",
        **kwargs: Any,
    ) -> str:
        """Build a signed SAML AttributeQuery.

        Args:
            subject: Subject to query attributes for.
            issuer: SP entity ID.
            destination: IdP attribute query endpoint URL.
            attribute_names: Specific attributes to request (None = all).
            binding: ``"post"`` (default) or ``"redirect"``.
            **kwargs: relay_state, name_id_format.

        Returns:
            POST: Base64-encoded signed XML.
            Redirect: Signed redirect URL.
        """
        if self._private_key is None and self.keychain is None:
            raise JamSAMLEmptyPrivateKey

        query_id = make_id()
        now = fmt_instant()

        query = make_element("AttributeQuery", NS_SAMLP)
        query.set("ID", query_id)
        query.set("Version", "2.0")
        query.set("IssueInstant", now)
        query.set("Destination", destination)

        sub_element(query, "Issuer", NS_SAML, text=issuer)

        subject_elem = make_element("Subject", NS_SAML)
        query.append(subject_elem)
        name_id_format = kwargs.get("name_id_format", NAMEID_UNSPECIFIED)
        sub_element(
            subject_elem,
            "NameID",
            NS_SAML,
            text=subject,
            attrib={"Format": name_id_format},
        )

        if attribute_names:
            for name in attribute_names:
                sub_element(query, "Attribute", NS_SAML, attrib={"Name": name})

        self._sign_element(query)

        self._mark_consumed(query_id)
        xml_str = ET.tostring(query, encoding="unicode")

        if binding == "post":
            return encode_post(xml_str)

        relay_state = kwargs.get("relay_state") or ""
        params = {"SAMLRequest": encode_redirect(xml_str)}
        if relay_state:
            params["RelayState"] = relay_state

        return build_redirect_url(
            destination,
            params,
            signing_key=self._signing_key()[0],
        )

    def parse_attribute_query(
        self,
        saml_request: str,
        *,
        binding: str = "redirect",
        **kwargs: Any,
    ) -> SAMLAttributeQuery:
        """Parse an incoming SAML AttributeQuery.

        Args:
            saml_request: Raw AttributeQuery data.
            binding: ``"redirect"`` (default) or ``"post"``.
            **kwargs: issuer (expected issuer).

        Returns:
            Parsed SAMLAttributeQuery.
        """
        if binding == "redirect":
            req, relay_state = parse_redirect_request(
                saml_request,
                verify_key=kwargs.get(
                    "verify_public_key",
                    self._sp_public_key
                    if self.role == "idp"
                    else self._idp_public_key,
                ),
            )
        elif binding == "post":
            req = decode_post(saml_request)
        else:
            raise JamSAMLValidationError(
                message=f"Unknown binding: {binding}",
            )

        root = safe_fromstring(req)
        query_id = root.get("ID", "")
        issue_instant = parse_instant(root.get("IssueInstant", ""))
        destination = root.get("Destination")
        issuer = _find_text(root, "Issuer", NS_SAML)

        self._check_replay(query_id)

        subject_elem = root.find(f"{{{NS_SAML}}}Subject")
        if subject_elem is not None:
            name_id = subject_elem.find(f"{{{NS_SAML}}}NameID")
            subject_text = (name_id.text if name_id is not None else None) or ""
        else:
            subject_text = ""

        attribute_names: list[str] | None = None
        names: list[str] = []
        for attr in root.findall(f"{{{NS_SAML}}}Attribute"):
            name = attr.get("Name")
            if name:
                names.append(name)
        if names:
            attribute_names = names

        expected_issuer = kwargs.get("issuer")
        if expected_issuer and issuer != expected_issuer:
            raise JamSAMLInvalidIssuer

        return SAMLAttributeQuery(
            id=query_id,
            issuer=issuer,
            issue_instant=issue_instant,
            subject=subject_text,
            destination=destination,
            attribute_names=attribute_names,
        )

    def build_attribute_query_response(
        self,
        in_response_to: str,
        subject: str,
        attributes: dict[str, Any],
        *,
        issuer: str,
        audience: str,
        **kwargs: Any,
    ) -> str:
        """Build a SAML Response for an AttributeQuery (no AuthnStatement).

        Args:
            in_response_to: AttributeQuery ID.
            subject: The subject.
            attributes: User attributes dict.
            issuer: IdP entity ID.
            audience: SP entity ID.
            **kwargs: destination, name_id_format.

        Returns:
            Signed SAML Response XML string.
        """
        if self._private_key is None and self.keychain is None:
            raise JamSAMLEmptyPrivateKey

        response_id = make_id()
        assertion_id = make_id()
        now = datetime.now(timezone.utc)
        now_str = fmt_instant(now)

        response = make_element("Response", NS_SAMLP)
        response.set("ID", response_id)
        response.set("Version", "2.0")
        response.set("IssueInstant", now_str)
        response.set("InResponseTo", in_response_to)

        destination = (
            kwargs.get("destination") or kwargs.get("acs_url") or self._acs_url
        )
        if destination:
            response.set("Destination", destination)

        sub_element(response, "Issuer", NS_SAML, text=issuer)

        status = make_element("Status", NS_SAMLP)
        response.append(status)
        sc = sub_element(status, "StatusCode", NS_SAMLP)
        sc.set("Value", STATUS_SUCCESS)

        assertion = self._build_assertion_xml(
            subject,
            attributes,
            issuer,
            audience,
            assertion_id,
            now,
            include_authn_statement=False,
            in_response_to=in_response_to,
            **kwargs,
        )
        response.append(assertion)

        self._mark_consumed(response_id)
        self._mark_consumed(assertion_id)
        return ET.tostring(response, encoding="unicode")

    def parse_attribute_query_response(
        self,
        saml_response: str,
        *,
        binding: str = "post",
        **kwargs: Any,
    ) -> SAMLResponse:
        """Parse a SAML Response from an AttributeQuery.

        Delegates to parse_response.

        Args:
            saml_response: Raw SAMLResponse data.
            binding: ``"post"`` or ``"redirect"``.
            **kwargs: audience, issuer, etc.

        Returns:
            Parsed SAMLResponse.
        """
        return self.parse_response(saml_response, binding=binding, **kwargs)

    # ── SLO: Single Logout ──

    def build_logout_request(
        self,
        name_id: str,
        *,
        issuer: str,
        destination: str,
        session_index: str | None = None,
        **kwargs: Any,
    ) -> str:
        """Build a SAML LogoutRequest.

        Args:
            name_id: User identifier to log out.
            issuer: Entity ID of the sender.
            destination: SLO endpoint of the recipient.
            session_index: Session index (optional).
            **kwargs: binding, relay_state, name_id_format.

        Returns:
            POST: Base64-encoded signed XML.
            Redirect: Signed redirect URL.
        """
        if self._private_key is None and self.keychain is None:
            raise JamSAMLEmptyPrivateKey

        request_id = make_id()
        now = fmt_instant()

        logout_request = make_element("LogoutRequest", NS_SAMLP)
        logout_request.set("ID", request_id)
        logout_request.set("Version", "2.0")
        logout_request.set("IssueInstant", now)
        logout_request.set("Destination", destination)

        sub_element(logout_request, "Issuer", NS_SAML, text=issuer)

        name_id_format = kwargs.get("name_id_format", NAMEID_UNSPECIFIED)
        sub_element(
            logout_request,
            "NameID",
            NS_SAML,
            text=name_id,
            attrib={"Format": name_id_format},
        )

        if session_index:
            sub_element(
                logout_request,
                "SessionIndex",
                NS_SAMLP,
                text=session_index,
            )

        self._sign_element(logout_request)

        self._mark_consumed(request_id)
        xml_str = ET.tostring(logout_request, encoding="unicode")

        binding = kwargs.get("binding", "post")
        if binding == "post":
            return encode_post(xml_str)

        relay_state = kwargs.get("relay_state") or ""
        params = {"SAMLRequest": encode_redirect(xml_str)}
        if relay_state:
            params["RelayState"] = relay_state

        return build_redirect_url(
            destination,
            params,
            signing_key=self._signing_key()[0],
        )

    def parse_logout_request(
        self,
        saml_request: str,
        *,
        binding: str = "redirect",
        **kwargs: Any,
    ) -> SAMLLogoutRequest:
        """Parse a SAML LogoutRequest.

        Args:
            saml_request: Raw LogoutRequest data.
            binding: ``"redirect"`` or ``"post"``.
            **kwargs: issuer, public_key (override verification key).

        Returns:
            Parsed SAMLLogoutRequest.
        """
        if binding == "redirect":
            req, relay_state = parse_redirect_request(
                saml_request,
                verify_key=kwargs.get(
                    "verify_public_key",
                    self._sp_public_key
                    if self.role == "idp"
                    else self._idp_public_key,
                ),
            )
        elif binding == "post":
            req = decode_post(saml_request)
        else:
            raise JamSAMLValidationError(
                message=f"Unknown binding: {binding}",
            )
        root = safe_fromstring(req)
        request_id = root.get("ID", "")
        issue_instant = parse_instant(root.get("IssueInstant", ""))
        destination = root.get("Destination")

        self._check_replay(request_id)

        issuer = _find_text(root, "Issuer", NS_SAML)
        name_id_elem = root.find(f"{{{NS_SAML}}}NameID")
        name_id = (
            name_id_elem.text if name_id_elem is not None else None
        ) or ""
        session_index_elem = root.find(f"{{{NS_SAMLP}}}SessionIndex")
        session_index = (
            session_index_elem.text if session_index_elem is not None else None
        )

        expected_issuer = kwargs.get("issuer")
        if expected_issuer and issuer != expected_issuer:
            raise JamSAMLInvalidIssuer

        return SAMLLogoutRequest(
            id=request_id,
            issuer=issuer,
            issue_instant=issue_instant,
            name_id=name_id,
            session_index=session_index,
            destination=destination,
        )

    def build_logout_response(
        self,
        in_response_to: str,
        *,
        issuer: str,
        destination: str,
        status_code: str = STATUS_SUCCESS,
        **kwargs: Any,
    ) -> str:
        """Build a SAML LogoutResponse.

        Args:
            in_response_to: LogoutRequest ID to respond to.
            issuer: Entity ID of the sender.
            destination: SLO endpoint of the recipient.
            status_code: SAML status code.
            **kwargs: binding, relay_state.

        Returns:
            POST: Base64-encoded signed XML.
            Redirect: Signed redirect URL.
        """
        if self._private_key is None and self.keychain is None:
            raise JamSAMLEmptyPrivateKey

        response_id = make_id()
        now = fmt_instant()

        logout_response = make_element("LogoutResponse", NS_SAMLP)
        logout_response.set("ID", response_id)
        logout_response.set("Version", "2.0")
        logout_response.set("IssueInstant", now)
        logout_response.set("Destination", destination)
        logout_response.set("InResponseTo", in_response_to)

        sub_element(logout_response, "Issuer", NS_SAML, text=issuer)

        status = make_element("Status", NS_SAMLP)
        logout_response.append(status)
        sc = sub_element(status, "StatusCode", NS_SAMLP)
        sc.set("Value", status_code)

        self._sign_element(logout_response)

        self._mark_consumed(response_id)
        xml_str = ET.tostring(logout_response, encoding="unicode")

        binding = kwargs.get("binding", "post")
        if binding == "post":
            return encode_post(xml_str)

        relay_state = kwargs.get("relay_state") or ""
        params = {"SAMLResponse": encode_redirect(xml_str)}
        if relay_state:
            params["RelayState"] = relay_state

        return build_redirect_url(
            destination,
            params,
            signing_key=self._signing_key()[0],
        )

    def parse_logout_response(
        self,
        saml_response: str,
        *,
        binding: str = "redirect",
        **kwargs: Any,
    ) -> SAMLLogoutResponse:
        """Parse a SAML LogoutResponse.

        Args:
            saml_response: Raw LogoutResponse data.
            binding: ``"redirect"`` or ``"post"``.
            **kwargs: issuer, public_key (override verification key).

        Returns:
            Parsed SAMLLogoutResponse.
        """
        if binding == "redirect":
            req, relay_state = parse_redirect_request(
                saml_response,
                verify_key=kwargs.get(
                    "verify_public_key",
                    self._sp_public_key
                    if self.role == "idp"
                    else self._idp_public_key,
                ),
            )
        elif binding == "post":
            req = decode_post(saml_response)
        else:
            raise JamSAMLValidationError(
                message=f"Unknown binding: {binding}",
            )

        root = safe_fromstring(req)
        response_id = root.get("ID", "")
        issue_instant = parse_instant(root.get("IssueInstant", ""))
        destination = root.get("Destination")
        in_response_to = root.get("InResponseTo")
        issuer = _find_text(root, "Issuer", NS_SAML)

        self._check_replay(response_id)

        status_code = _parse_status(root)

        expected_issuer = kwargs.get("issuer")
        if expected_issuer and issuer != expected_issuer:
            raise JamSAMLInvalidIssuer

        return SAMLLogoutResponse(
            id=response_id,
            issuer=issuer,
            issue_instant=issue_instant,
            status_code=status_code,
            destination=destination,
            in_response_to=in_response_to,
        )

    # ── Artifact Binding ──

    def build_artifact(self, source_message_id: str, *, issuer: str) -> str:
        """Create a SAML 2.0 artifact from a message ID.

        Format: 2 bytes type code (0x0001) + 2 bytes endpoint index
                + 40 random bytes → Base64.

        Args:
            source_message_id: The ID of the referenced message (unused
                               in artifact format, stored for reference).
            issuer: Entity ID of the issuer (stored for reference).

        Returns:
            Base64-encoded artifact string.
        """
        raw = bytearray(44)
        raw[0:2] = (0x0001).to_bytes(2, "big")
        raw[2:4] = (0).to_bytes(2, "big")
        raw[4:44] = os.urandom(40)

        return base64.b64encode(bytes(raw)).decode("ascii")

    def build_artifact_resolve(
        self,
        artifact: str,
        *,
        issuer: str,
        destination: str,
        **kwargs: Any,
    ) -> str:
        """Build a signed SAML ArtifactResolve.

        Args:
            artifact: The artifact to resolve.
            issuer: SP entity ID.
            destination: IdP artifact resolution service URL.
            **kwargs: binding ("post", "redirect", or "soap").

        Returns:
            POST: Base64-encoded signed XML.
            Redirect: Signed redirect URL.
            SOAP: Raw XML.
        """
        if self._private_key is None and self.keychain is None:
            raise JamSAMLEmptyPrivateKey

        resolve_id = make_id()
        now = fmt_instant()

        resolve = make_element("ArtifactResolve", NS_SAMLP)
        resolve.set("ID", resolve_id)
        resolve.set("Version", "2.0")
        resolve.set("IssueInstant", now)
        resolve.set("Destination", destination)

        sub_element(resolve, "Issuer", NS_SAML, text=issuer)

        sub_element(resolve, "Artifact", NS_SAMLP, text=artifact)

        self._sign_element(resolve)

        self._mark_consumed(resolve_id)
        xml_str = ET.tostring(resolve, encoding="unicode")

        binding = kwargs.get("binding", "soap")
        if binding == "post":
            return encode_post(xml_str)
        if binding == "redirect":
            relay_state = kwargs.get("relay_state") or ""
            params = {"SAMLRequest": encode_redirect(xml_str)}
            if relay_state:
                params["RelayState"] = relay_state
            return build_redirect_url(
                destination,
                params,
                signing_key=self._signing_key()[0],
            )

        return xml_str

    def parse_artifact_resolve(
        self,
        saml_request: str,
        *,
        binding: str = "post",
        **kwargs: Any,
    ) -> SAMLArtifactResolve:
        """Parse an incoming SAML ArtifactResolve.

        Args:
            saml_request: Raw ArtifactResolve data.
            binding: ``"post"`` (default), ``"redirect"``, or ``"soap"``.
            **kwargs: issuer (expected issuer).

        Returns:
            Parsed SAMLArtifactResolve.
        """
        req = self._decode_artifact_message(saml_request, binding, **kwargs)

        root = safe_fromstring(req)
        resolve_id = root.get("ID", "")
        issue_instant = parse_instant(root.get("IssueInstant", ""))
        issuer = _find_text(root, "Issuer", NS_SAML)

        self._check_replay(resolve_id)

        artifact_elem = root.find(f"{{{NS_SAMLP}}}Artifact")
        artifact = (
            artifact_elem.text if artifact_elem is not None else None
        ) or ""

        expected_issuer = kwargs.get("issuer")
        if expected_issuer and issuer != expected_issuer:
            raise JamSAMLInvalidIssuer

        return SAMLArtifactResolve(
            id=resolve_id,
            issuer=issuer,
            issue_instant=issue_instant,
            artifact=artifact,
        )

    def build_artifact_response(
        self,
        in_response_to: str,
        original_message_xml: str,
        *,
        issuer: str,
        destination: str,
        **kwargs: Any,
    ) -> str:
        """Build a signed SAML ArtifactResponse wrapping the original message.

        Args:
            in_response_to: ArtifactResolve ID.
            original_message_xml: The original SAML message XML to embed.
            issuer: IdP entity ID.
            destination: SP endpoint URL.
            **kwargs: binding, status_code.

        Returns:
            POST: Base64-encoded signed XML.
            Redirect: Signed redirect URL.
            SOAP: Raw XML.
        """
        if self._private_key is None and self.keychain is None:
            raise JamSAMLEmptyPrivateKey

        response_id = make_id()
        now = fmt_instant()

        artifact_response = make_element("ArtifactResponse", NS_SAMLP)
        artifact_response.set("ID", response_id)
        artifact_response.set("Version", "2.0")
        artifact_response.set("IssueInstant", now)
        artifact_response.set("Destination", destination)
        artifact_response.set("InResponseTo", in_response_to)

        sub_element(artifact_response, "Issuer", NS_SAML, text=issuer)

        status = make_element("Status", NS_SAMLP)
        artifact_response.append(status)
        sc = sub_element(status, "StatusCode", NS_SAMLP)
        sc.set(
            "Value",
            kwargs.get("status_code", STATUS_SUCCESS),
        )

        original_root = safe_fromstring(original_message_xml)
        artifact_response.append(original_root)

        self._sign_element(artifact_response)

        self._mark_consumed(response_id)
        xml_str = ET.tostring(artifact_response, encoding="unicode")

        binding = kwargs.get("binding", "soap")
        if binding == "post":
            return encode_post(xml_str)
        if binding == "redirect":
            relay_state = kwargs.get("relay_state") or ""
            params = {"SAMLResponse": encode_redirect(xml_str)}
            if relay_state:
                params["RelayState"] = relay_state
            return build_redirect_url(
                destination,
                params,
                signing_key=self._signing_key()[0],
            )

        return xml_str

    def parse_artifact_response(
        self,
        saml_response: str,
        *,
        binding: str = "post",
        **kwargs: Any,
    ) -> SAMLArtifactResponse:
        """Parse a SAML ArtifactResponse.

        Args:
            saml_response: Raw ArtifactResponse data.
            binding: ``"post"`` (default), ``"redirect"``, or ``"soap"``.
            **kwargs: issuer (expected issuer).

        Returns:
            Parsed SAMLArtifactResponse.
        """
        resp = self._decode_artifact_message(saml_response, binding, **kwargs)

        root = safe_fromstring(resp)
        response_id = root.get("ID", "")
        issue_instant = parse_instant(root.get("IssueInstant", ""))
        in_response_to = root.get("InResponseTo")
        issuer = _find_text(root, "Issuer", NS_SAML)

        self._check_replay(response_id)

        status_code = _parse_status(root)

        children = list(root)
        original_elems = []
        sig_ns = f"{{{NS_DS}}}"
        for child in children:
            tag = child.tag
            if tag == f"{{{NS_SAMLP}}}Status" or tag.startswith(sig_ns):
                continue
            if tag == f"{{{NS_SAMLP}}}Issuer" or tag == f"{{{NS_SAML}}}Issuer":
                continue
            original_elems.append(child)
        original_message = (
            ET.tostring(original_elems[0], encoding="unicode")
            if original_elems
            else None
        )

        expected_issuer = kwargs.get("issuer")
        if expected_issuer and issuer != expected_issuer:
            raise JamSAMLInvalidIssuer

        return SAMLArtifactResponse(
            id=response_id,
            issuer=issuer,
            issue_instant=issue_instant,
            status_code=status_code,
            in_response_to=in_response_to,
            original_message=original_message,
        )

    def resolve_artifact(
        self,
        artifact: str,
        *,
        issuer: str,
        resolve_url: str,
        **kwargs: Any,
    ) -> str:
        """Resolve a SAML artifact via SOAP/HTTP to the IdP resolve endpoint.

        Args:
            artifact: The artifact to resolve.
            issuer: SP entity ID.
            resolve_url: IdP artifact resolution service URL.
            **kwargs: timeout (int, default 10), expected_issuer (IdP
                      entity ID to validate the ArtifactResponse issuer).

        Returns:
            The original SAML message XML from the ArtifactResponse.
        """
        resolve_xml = self.build_artifact_resolve(
            artifact,
            issuer=issuer,
            destination=resolve_url,
            binding="soap",
        )

        soap_envelope = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            f'<SOAP-ENV:Envelope xmlns:SOAP-ENV="{NS_SOAP}">'
            f"<SOAP-ENV:Body>{resolve_xml}</SOAP-ENV:Body>"
            f"</SOAP-ENV:Envelope>"
        )

        req = urllib.request.Request(
            resolve_url,
            data=soap_envelope.encode("utf-8"),
            headers={
                "Content-Type": "application/soap+xml; charset=utf-8",
                "SOAPAction": "http://www.oasis-open.org/committees/security",
            },
        )
        try:
            with urllib.request.urlopen(
                req, timeout=kwargs.get("timeout", 10)
            ) as resp:
                soap_response = resp.read().decode("utf-8")
        except urllib.error.URLError as exc:
            raise JamSAMLSOAPError(
                message=f"SOAP request failed: {exc}",
            ) from exc

        try:
            soap_root = safe_fromstring(soap_response)
        except JamSAMLValidationError as exc:
            raise JamSAMLSOAPError(
                message=f"Malformed SOAP response: {exc}",
            ) from exc
        body = soap_root.find(f"{{{NS_SOAP}}}Body")
        if body is None:
            raise JamSAMLSOAPError(
                message="SOAP response missing Body element.",
            )

        artifact_response_elems = [
            child
            for child in body
            if child.tag == f"{{{NS_SAMLP}}}ArtifactResponse"
        ]
        if not artifact_response_elems:
            raise JamSAMLSOAPError(
                message=("SOAP response does not contain ArtifactResponse."),
            )

        result = self.parse_artifact_response(
            ET.tostring(artifact_response_elems[0], encoding="unicode"),
            binding="soap",
            issuer=kwargs.get("expected_issuer"),
        )

        if result.original_message is None:
            raise JamSAMLSOAPError(
                message="ArtifactResponse contains no embedded message.",
            )

        return result.original_message

    def _decode_artifact_message(
        self,
        raw: str,
        binding: str,
        **kwargs: Any,
    ) -> str:
        """Decode an artifact protocol message (resolve or response).

        Handles SOAP envelope unwrapping, POST Base64, and redirect
        deflate+Base64.
        """
        if binding == "soap":
            root = safe_fromstring(raw)
            body = root.find(f"{{{NS_SOAP}}}Body")
            if body is not None:
                children = list(body)
                if children:
                    return ET.tostring(children[0], encoding="unicode")
            return raw

        if binding == "redirect":
            return parse_redirect_request(
                raw,
                verify_key=kwargs.get(
                    "verify_public_key",
                    self._sp_public_key
                    if self.role == "idp"
                    else self._idp_public_key,
                ),
            )[0]

        if binding == "post":
            return decode_post(raw)

        raise JamSAMLValidationError(
            message=f"Unknown binding: {binding}",
        )

    # ── NameID Management ──

    def build_manage_name_id_request(
        self,
        name_id: str,
        *,
        issuer: str,
        destination: str,
        new_id: str | None = None,
        binding: str = "post",
        **kwargs: Any,
    ) -> str:
        """Build a signed SAML ManageNameIDRequest.

        Args:
            name_id: Current NameID.
            issuer: Entity ID of the requester.
            destination: Recipient endpoint URL.
            new_id: New identifier (None = terminate).
            binding: ``"post"`` (default) or ``"redirect"``.
            **kwargs: relay_state, name_id_format.

        Returns:
            POST: Base64-encoded signed XML.
            Redirect: Signed redirect URL.
        """
        if self._private_key is None and self.keychain is None:
            raise JamSAMLEmptyPrivateKey

        request_id = make_id()
        now = fmt_instant()

        req = make_element("ManageNameIDRequest", NS_SAMLP)
        req.set("ID", request_id)
        req.set("Version", "2.0")
        req.set("IssueInstant", now)
        req.set("Destination", destination)

        sub_element(req, "Issuer", NS_SAML, text=issuer)

        name_id_format = kwargs.get("name_id_format", NAMEID_UNSPECIFIED)
        sub_element(
            req,
            "NameID",
            NS_SAML,
            text=name_id,
            attrib={"Format": name_id_format},
        )

        if new_id is not None:
            sub_element(
                req,
                "NewID",
                NS_SAML,
                text=new_id,
            )

        self._sign_element(req)

        self._mark_consumed(request_id)
        xml_str = ET.tostring(req, encoding="unicode")

        if binding == "post":
            return encode_post(xml_str)

        relay_state = kwargs.get("relay_state") or ""
        params = {"SAMLRequest": encode_redirect(xml_str)}
        if relay_state:
            params["RelayState"] = relay_state

        return build_redirect_url(
            destination,
            params,
            signing_key=self._signing_key()[0],
        )

    def parse_manage_name_id_request(
        self,
        saml_request: str,
        *,
        binding: str = "redirect",
        **kwargs: Any,
    ) -> SAMLManageNameIDRequest:
        """Parse a SAML ManageNameIDRequest.

        Args:
            saml_request: Raw ManageNameIDRequest data.
            binding: ``"redirect"`` (default) or ``"post"``.
            **kwargs: issuer (expected issuer).

        Returns:
            Parsed SAMLManageNameIDRequest.
        """
        if binding == "redirect":
            req, relay_state = parse_redirect_request(
                saml_request,
                verify_key=kwargs.get(
                    "verify_public_key",
                    self._sp_public_key
                    if self.role == "idp"
                    else self._idp_public_key,
                ),
            )
        elif binding == "post":
            req = decode_post(saml_request)
        else:
            raise JamSAMLValidationError(
                message=f"Unknown binding: {binding}",
            )

        root = safe_fromstring(req)
        request_id = root.get("ID", "")
        issue_instant = parse_instant(root.get("IssueInstant", ""))
        destination = root.get("Destination")
        issuer = _find_text(root, "Issuer", NS_SAML)

        self._check_replay(request_id)

        name_id_elem = root.find(f"{{{NS_SAML}}}NameID")
        name_id = (
            name_id_elem.text if name_id_elem is not None else None
        ) or ""

        new_id_elem = root.find(f"{{{NS_SAML}}}NewID")
        new_id = new_id_elem.text if new_id_elem is not None else None

        expected_issuer = kwargs.get("issuer")
        if expected_issuer and issuer != expected_issuer:
            raise JamSAMLInvalidIssuer

        return SAMLManageNameIDRequest(
            id=request_id,
            issuer=issuer,
            issue_instant=issue_instant,
            name_id=name_id,
            new_id=new_id,
            destination=destination,
        )

    def build_manage_name_id_response(
        self,
        in_response_to: str,
        *,
        issuer: str,
        destination: str,
        status_code: str = STATUS_SUCCESS,
        **kwargs: Any,
    ) -> str:
        """Build a signed SAML ManageNameIDResponse.

        Args:
            in_response_to: ManageNameIDRequest ID.
            issuer: Entity ID of the responder.
            destination: Endpoint URL of the requester.
            status_code: SAML status code (default Success).
            **kwargs: binding, relay_state.

        Returns:
            POST: Base64-encoded signed XML.
            Redirect: Signed redirect URL.
        """
        if self._private_key is None and self.keychain is None:
            raise JamSAMLEmptyPrivateKey

        response_id = make_id()
        now = fmt_instant()

        resp = make_element("ManageNameIDResponse", NS_SAMLP)
        resp.set("ID", response_id)
        resp.set("Version", "2.0")
        resp.set("IssueInstant", now)
        resp.set("Destination", destination)
        resp.set("InResponseTo", in_response_to)

        sub_element(resp, "Issuer", NS_SAML, text=issuer)

        status = make_element("Status", NS_SAMLP)
        resp.append(status)
        sc = sub_element(status, "StatusCode", NS_SAMLP)
        sc.set("Value", status_code)

        self._sign_element(resp)

        self._mark_consumed(response_id)
        xml_str = ET.tostring(resp, encoding="unicode")

        if kwargs.get("binding", "post") == "post":
            return encode_post(xml_str)

        relay_state = kwargs.get("relay_state") or ""
        params = {"SAMLResponse": encode_redirect(xml_str)}
        if relay_state:
            params["RelayState"] = relay_state

        return build_redirect_url(
            destination,
            params,
            signing_key=self._signing_key()[0],
        )

    def parse_manage_name_id_response(
        self,
        saml_response: str,
        *,
        binding: str = "redirect",
        **kwargs: Any,
    ) -> SAMLManageNameIDResponse:
        """Parse a SAML ManageNameIDResponse.

        Args:
            saml_response: Raw ManageNameIDResponse data.
            binding: ``"redirect"`` (default) or ``"post"``.
            **kwargs: issuer (expected issuer).

        Returns:
            Parsed SAMLManageNameIDResponse.
        """
        if binding == "redirect":
            req, relay_state = parse_redirect_request(
                saml_response,
                verify_key=kwargs.get(
                    "verify_public_key",
                    self._sp_public_key
                    if self.role == "idp"
                    else self._idp_public_key,
                ),
            )
        elif binding == "post":
            req = decode_post(saml_response)
        else:
            raise JamSAMLValidationError(
                message=f"Unknown binding: {binding}",
            )

        root = safe_fromstring(req)
        response_id = root.get("ID", "")
        issue_instant = parse_instant(root.get("IssueInstant", ""))
        destination = root.get("Destination")
        in_response_to = root.get("InResponseTo")
        issuer = _find_text(root, "Issuer", NS_SAML)

        self._check_replay(response_id)

        status_code = _parse_status(root)

        expected_issuer = kwargs.get("issuer")
        if expected_issuer and issuer != expected_issuer:
            raise JamSAMLInvalidIssuer

        return SAMLManageNameIDResponse(
            id=response_id,
            issuer=issuer,
            issue_instant=issue_instant,
            status_code=status_code,
            destination=destination,
            in_response_to=in_response_to,
        )

    # ── Metadata ──

    def generate_metadata(
        self,
        *,
        entity_id: str | None = None,
        sso_url: str | None = None,
        acs_url: str | None = None,
        role: str | None = None,
    ) -> str:
        """Generate SAML metadata XML.

        Args:
            entity_id: Entity ID (defaults to instance entity_id).
            sso_url: SSO URL (IdP metadata).
            acs_url: ACS URL (SP metadata).
            role: ``"idp"`` or ``"sp"`` (defaults to instance role).

        Returns:
            Metadata XML string.
        """
        eid = entity_id or self._entity_id
        if not eid:
            raise ValueError("entity_id is required for metadata generation")

        r = role or self.role

        if r == "idp":
            ss = sso_url or self._sso_url
            if not ss:
                raise ValueError("sso_url is required for IdP metadata")
            return generate_idp_metadata(
                eid,
                ss,
                certificate=self._certificate,
            )

        ac = acs_url or self._acs_url
        if not ac:
            raise ValueError("acs_url is required for SP metadata")
        return generate_sp_metadata(
            eid,
            ac,
            certificate=self._certificate,
        )

    def parse_metadata(self, metadata_xml: str) -> SAMLMetadata:
        """Parse SAML metadata XML into a SAMLMetadata object.

        Args:
            metadata_xml: Raw metadata XML string.

        Returns:
            SAMLMetadata with entity_id, endpoints, cert, etc.
        """
        return parse_metadata(metadata_xml)


# ── internal helpers ──


def _find_text(parent: ET.Element, tag: str, ns: str) -> str | None:
    elem = parent.find(f"{{{ns}}}{tag}")
    return elem.text if elem is not None else None


def _parse_status(response: ET.Element) -> str:
    status = response.find(f"{{{NS_SAMLP}}}Status")
    if status is None:
        return STATUS_SUCCESS
    sc = status.find(f"{{{NS_SAMLP}}}StatusCode")
    if sc is None:
        return STATUS_SUCCESS
    return sc.get("Value", STATUS_SUCCESS)


def _parse_subject(assertion_elem: ET.Element) -> SAMLSubject | None:
    subj = assertion_elem.find(f"{{{NS_SAML}}}Subject")
    if subj is None:
        return None
    name_id = subj.find(f"{{{NS_SAML}}}NameID")
    name_id_text = (name_id.text if name_id is not None else None) or ""
    name_id_format = (
        name_id.get("Format", NAMEID_UNSPECIFIED)
        if name_id is not None
        else NAMEID_UNSPECIFIED
    )

    subj_conf = subj.find(f"{{{NS_SAML}}}SubjectConfirmation")
    scm = (
        subj_conf.get("Method", CM_BEARER)
        if subj_conf is not None
        else CM_BEARER
    )
    scd = (
        subj_conf.find(f"{{{NS_SAML}}}SubjectConfirmationData")
        if subj_conf is not None
        else None
    )
    scd_data = scd.attrib if scd is not None else None

    return SAMLSubject(
        name_id=name_id_text,
        format=name_id_format,
        subject_confirmation_method=scm,
        subject_confirmation_data=scd_data,
    )


def _parse_conditions(assertion_elem: ET.Element) -> SAMLConditions | None:
    conds = assertion_elem.find(f"{{{NS_SAML}}}Conditions")
    if conds is None:
        return None

    nb = conds.get("NotBefore")
    noa = conds.get("NotOnOrAfter")

    audience_restriction = []
    ar = conds.find(f"{{{NS_SAML}}}AudienceRestriction")
    if ar is not None:
        for aud in ar.findall(f"{{{NS_SAML}}}Audience"):
            if aud.text:
                audience_restriction.append(aud.text)

    return SAMLConditions(
        not_before=parse_instant(nb) if nb else None,
        not_on_or_after=parse_instant(noa) if noa else None,
        audience_restriction=audience_restriction,
    )


def _parse_attributes(assertion_elem: ET.Element) -> dict[str, Any]:
    result: dict[str, Any] = {}
    attr_stmt = assertion_elem.find(f"{{{NS_SAML}}}AttributeStatement")
    if attr_stmt is None:
        return result
    for attr in attr_stmt.findall(f"{{{NS_SAML}}}Attribute"):
        name = attr.get("Name")
        if not name:
            continue
        values = []
        for av in attr.findall(f"{{{NS_SAML}}}AttributeValue"):
            if av.text is not None:
                values.append(av.text)
        if len(values) == 1:
            result[name] = values[0]
        else:
            result[name] = values
    return result


def _parse_authn_statement(
    assertion_elem: ET.Element,
) -> SAMLAuthnStatement | None:
    authn = assertion_elem.find(f"{{{NS_SAML}}}AuthnStatement")
    if authn is None:
        authn = assertion_elem.find(f"{{{NS_SAMLP}}}AuthnStatement")
    if authn is None:
        return None
    instant = parse_instant(authn.get("AuthnInstant", ""))
    session_index = authn.get("SessionIndex")
    return SAMLAuthnStatement(
        authn_instant=instant,
        session_index=session_index,
    )

# -*- coding: utf-8 -*-

from __future__ import annotations

from datetime import datetime, timezone
import logging
import xml.etree.ElementTree as ET


logger = logging.getLogger(__name__)


__all__ = [
    "NS_SAMLP",
    "NS_SAML",
    "NS_DS",
    "NS_MD",
    "NS_SOAP",
    "NAMEID_UNSPECIFIED",
    "NAMEID_EMAIL",
    "CM_BEARER",
    "BINDING_HTTP_POST",
    "BINDING_HTTP_REDIRECT",
    "BINDING_HTTP_ARTIFACT",
    "STATUS_SUCCESS",
    "STATUS_REQUESTER",
    "STATUS_RESPONDER",
    "SIG_RSA_SHA256",
    "DIGEST_SHA256",
    "C14N_INCLUSIVE",
    "C14N_EXCLUSIVE",
    "TRANSFORM_ENVELOPED_SIG",
    "NS_XENC",
    "ENC_AES256_GCM",
    "ENC_RSA_OAEP",
    "ENC_ELEMENT",
    "register_namespaces",
    "make_element",
    "canonicalize_xml",
    "fmt_instant",
    "parse_instant",
    "make_id",
    "safe_fromstring",
]

NS_SAMLP = "urn:oasis:names:tc:SAML:2.0:protocol"
NS_SAML = "urn:oasis:names:tc:SAML:2.0:assertion"
NS_DS = "http://www.w3.org/2000/09/xmldsig#"
NS_MD = "urn:oasis:names:tc:SAML:2.0:metadata"
NS_SOAP = "http://schemas.xmlsoap.org/soap/envelope/"

NAMEID_UNSPECIFIED = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
NAMEID_EMAIL = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

CM_BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"

BINDING_HTTP_POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
BINDING_HTTP_REDIRECT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
BINDING_HTTP_ARTIFACT = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact"

STATUS_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
STATUS_REQUESTER = "urn:oasis:names:tc:SAML:2.0:status:Requester"
STATUS_RESPONDER = "urn:oasis:names:tc:SAML:2.0:status:Responder"

SIG_RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
DIGEST_SHA256 = "http://www.w3.org/2001/04/xmlenc#sha256"
C14N_INCLUSIVE = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
C14N_EXCLUSIVE = "http://www.w3.org/2001/10/xml-exc-c14n#"
TRANSFORM_ENVELOPED_SIG = (
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
)

NS_XENC = "http://www.w3.org/2001/04/xmlenc#"
ENC_AES256_GCM = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
ENC_RSA_OAEP = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
ENC_ELEMENT = "http://www.w3.org/2001/04/xmlenc#Element"

_NAMESPACES_REGISTERED = False


def register_namespaces() -> None:
    """Register SAML and DS namespace prefixes with ElementTree."""
    global _NAMESPACES_REGISTERED
    if _NAMESPACES_REGISTERED:
        return
    ET.register_namespace("samlp", NS_SAMLP)
    ET.register_namespace("saml", NS_SAML)
    ET.register_namespace("ds", NS_DS)
    ET.register_namespace("md", NS_MD)
    ET.register_namespace("xenc", NS_XENC)
    ET.register_namespace("soap", NS_SOAP)
    _NAMESPACES_REGISTERED = True


def make_element(
    tag: str, ns: str, attrib: dict[str, str] | None = None
) -> ET.Element:
    """Create an Element with the given namespace-qualified tag."""
    return ET.Element(f"{{{ns}}}{tag}", attrib or {})


def sub_element(
    parent: ET.Element,
    tag: str,
    ns: str,
    text: str | None = None,
    attrib: dict[str, str] | None = None,
) -> ET.Element:
    """Add a child Element with namespace-qualified tag and optional text."""
    elem = ET.SubElement(parent, f"{{{ns}}}{tag}", attrib or {})
    if text is not None:
        elem.text = text
    return elem


def canonicalize_xml(elem: ET.Element) -> bytes:
    """Inclusive XML canonicalization (C14N) of an Element.

    Note: uses standard (non-exclusive) C14N for Python 3.10 compatibility.
    """
    result = ET.canonicalize(ET.tostring(elem, encoding="utf-8"))
    if isinstance(result, str):
        return result.encode("utf-8")
    return result


def fmt_instant(dt: datetime | None = None) -> str:
    """Format a datetime as SAML-style UTC string (``2024-01-15T12:00:00Z``)."""
    if dt is None:
        dt = datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_instant(text: str) -> datetime:
    """Parse a SAML-style UTC string into a datetime."""
    text = text.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    return datetime.fromisoformat(text)


def make_id() -> str:
    """Generate a unique SAML identifier (``_<hex>``)."""
    from uuid import uuid4

    return "_" + uuid4().hex


def safe_fromstring(xml_str: str) -> ET.Element:
    """Parse XML string with XXE and entity expansion protection.

    Rejects XML containing DTD/DOCTYPE declarations (required for XXE).
    Python 3.8+ already limits entity expansion by default in ElementTree.

    Args:
        xml_str: XML string to parse.

    Returns:
        Root element.

    Raises:
        JamSAMLValidationError: If XML is malformed or contains unsafe entities.
    """
    from jam.exceptions.saml import JamSAMLValidationError

    if "<!DOCTYPE" in xml_str.upper() or "<!ENTITY" in xml_str.upper():
        logger.warning(
            "Rejected SAML XML containing DTD or entity declarations"
        )
        raise JamSAMLValidationError(
            message="XML with DTD/entity declarations is rejected.",
        )

    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as exc:
        logger.warning("Rejected malformed SAML XML")
        raise JamSAMLValidationError(
            message=f"Malformed SAML XML: {exc}"
        ) from exc
    logger.debug("Parsed SAML XML with root_tag=%s", root.tag)
    return root

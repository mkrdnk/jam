# -*- coding: utf-8 -*-

from __future__ import annotations

import base64
import logging
import xml.etree.ElementTree as ET

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509 import load_pem_x509_certificate

from jam.exceptions.saml import JamSAMLValidationError
from jam.saml.xml import (
    C14N_INCLUSIVE,
    DIGEST_SHA256,
    NS_DS,
    SIG_RSA_SHA256,
    TRANSFORM_ENVELOPED_SIG,
    canonicalize_xml,
    make_element,
    sub_element,
)


logger = logging.getLogger(__name__)


__all__ = [
    "sign_assertion",
    "verify_assertion_signature",
    "extract_public_key_from_keyinfo",
    "load_private_key",
    "load_public_key",
]


def load_private_key(pem_str: str) -> rsa.RSAPrivateKey:
    """Load an RSA private key from a PEM string.

    Args:
        pem_str: PEM-encoded private key.

    Returns:
        RSAPrivateKey.

    Raises:
        JamSAMLValidationError: If key is not RSA.
    """
    key = serialization.load_pem_private_key(
        pem_str.encode("utf-8"),
        password=None,
    )
    if not isinstance(key, rsa.RSAPrivateKey):
        logger.warning("Rejected non-RSA SAML private signing key")
        raise JamSAMLValidationError(
            message="SAML signing requires an RSA private key.",
        )
    return key


def load_public_key(pem_str: str) -> rsa.RSAPublicKey:
    """Load an RSA public key from a PEM string or X.509 certificate.

    Args:
        pem_str: PEM-encoded public key or certificate.

    Returns:
        RSAPublicKey.

    Raises:
        JamSAMLValidationError: If key is not RSA.
    """
    try:
        key = serialization.load_pem_public_key(pem_str.encode("utf-8"))
    except ValueError:
        cert = load_pem_x509_certificate(pem_str.encode("utf-8"))
        key = cert.public_key()
    if not isinstance(key, rsa.RSAPublicKey):
        logger.warning("Rejected non-RSA SAML public verification key")
        raise JamSAMLValidationError(
            message="SAML requires an RSA public key.",
        )
    return key


def _strip_pem_headers(pem_str: str) -> str:
    return "".join(
        line.strip()
        for line in pem_str.strip().split("\n")
        if not line.startswith("-----")
    )


def sign_assertion(
    assertion: ET.Element,
    key: rsa.RSAPrivateKey,
    cert_pem: str | None = None,
) -> ET.Element:
    """Sign a SAML Assertion with an enveloped XML signature.

    The signature is added as a child of the Assertion element.
    Uses RSA-SHA256 and Exclusive XML Canonicalization.

    Args:
        assertion: The Assertion Element to sign (must have an ID attribute).
        key: RSA private key for signing.
        cert_pem: Optional PEM certificate for X509Data in KeyInfo.

    Returns:
        The assertion Element with Signature child appended.

    Raises:
        JamSAMLValidationError: If assertion has no ID.
    """
    assertion_id = assertion.get("ID")
    if not assertion_id:
        logger.warning("Cannot sign SAML assertion without an ID")
        raise JamSAMLValidationError(
            message="Assertion must have an ID attribute for signing.",
        )

    sig = make_element("Signature", NS_DS)
    signed_info = make_element("SignedInfo", NS_DS)
    sig.append(signed_info)

    cm = sub_element(signed_info, "CanonicalizationMethod", NS_DS)
    cm.set("Algorithm", C14N_INCLUSIVE)

    sm = sub_element(signed_info, "SignatureMethod", NS_DS)
    sm.set("Algorithm", SIG_RSA_SHA256)

    ref = sub_element(signed_info, "Reference", NS_DS)
    ref.set("URI", f"#{assertion_id}")

    transforms = sub_element(ref, "Transforms", NS_DS)
    t1 = sub_element(transforms, "Transform", NS_DS)
    t1.set("Algorithm", TRANSFORM_ENVELOPED_SIG)
    t2 = sub_element(transforms, "Transform", NS_DS)
    t2.set("Algorithm", C14N_INCLUSIVE)

    dm = sub_element(ref, "DigestMethod", NS_DS)
    dm.set("Algorithm", DIGEST_SHA256)

    digest = hashes.Hash(hashes.SHA256())
    digest.update(canonicalize_xml(assertion))
    digest_value = base64.b64encode(digest.finalize()).decode("ascii")

    dve = sub_element(ref, "DigestValue", NS_DS)
    dve.text = digest_value

    assertion.append(sig)

    c14n_si = canonicalize_xml(signed_info)
    signature_bytes = key.sign(
        c14n_si,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    signature_value = base64.b64encode(signature_bytes).decode("ascii")

    sve = sub_element(sig, "SignatureValue", NS_DS)
    sve.text = signature_value

    if cert_pem:
        key_info = make_element("KeyInfo", NS_DS)
        sig.append(key_info)
        x509_data = make_element("X509Data", NS_DS)
        key_info.append(x509_data)
        x509_cert = make_element("X509Certificate", NS_DS)
        x509_data.append(x509_cert)
        x509_cert.text = _strip_pem_headers(cert_pem)

    logger.debug(
        "Signed SAML assertion with algorithm=RSA-SHA256 and certificate=%s",
        cert_pem is not None,
    )
    return assertion


def verify_assertion_signature(
    assertion: ET.Element,
    key: rsa.RSAPublicKey | None = None,
) -> bool:
    """Verify the enveloped XML signature on a SAML Assertion.

    Verifies both the digest (content integrity) and the RSA signature.

    Args:
        assertion: The Assertion Element containing a Signature child.
        key: RSA public key. If None, extracted from KeyInfo in the signature.

    Returns:
        True if signature is valid.

    Raises:
        JamSAMLValidationError: If signature is missing, malformed, or invalid.
    """
    sig = assertion.find(f"{{{NS_DS}}}Signature")
    if sig is None:
        logger.warning("Rejected SAML assertion without XML signature")
        raise JamSAMLValidationError(
            message="No XML signature found on assertion.",
        )

    signed_info = sig.find(f"{{{NS_DS}}}SignedInfo")
    sig_value_elem = sig.find(f"{{{NS_DS}}}SignatureValue")
    if (
        signed_info is None
        or sig_value_elem is None
        or sig_value_elem.text is None
    ):
        logger.warning("Rejected SAML assertion with invalid signature structure")
        raise JamSAMLValidationError(
            message="Invalid signature structure.",
        )

    ref = signed_info.find(f"{{{NS_DS}}}Reference")
    digest_value_elem = (
        ref.find(f"{{{NS_DS}}}DigestValue") if ref is not None else None
    )
    if (
        ref is None
        or digest_value_elem is None
        or digest_value_elem.text is None
    ):
        logger.warning("Rejected SAML assertion with invalid signature reference")
        raise JamSAMLValidationError(
            message="Invalid signature reference structure.",
        )

    expected_digest = digest_value_elem.text
    sig_value_text = sig_value_elem.text

    assertion.remove(sig)

    digest = hashes.Hash(hashes.SHA256())
    digest.update(canonicalize_xml(assertion))
    actual_digest = base64.b64encode(digest.finalize()).decode("ascii")

    assertion.append(sig)

    if actual_digest != expected_digest:
        logger.warning("Rejected SAML assertion with mismatched digest")
        raise JamSAMLValidationError(
            message="Assertion digest mismatch -- content has been modified.",
        )

    if key is None:
        key = extract_public_key_from_keyinfo(sig)

    c14n_si = canonicalize_xml(signed_info)
    sig_bytes = base64.b64decode(sig_value_text)

    try:
        key.verify(
            sig_bytes,
            c14n_si,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature:
        logger.warning("Rejected SAML assertion with invalid signature")
        raise JamSAMLValidationError(
            message="Assertion signature is invalid.",
        )

    logger.debug("Verified SAML assertion signature with algorithm=RSA-SHA256")
    return True


def extract_public_key_from_keyinfo(sig: ET.Element) -> rsa.RSAPublicKey:
    """Extract the RSA public key from an XML Signature's KeyInfo/X509Data.

    Args:
        sig: The Signature Element containing KeyInfo.

    Returns:
        RSAPublicKey.

    Raises:
        JamSAMLValidationError: If KeyInfo is missing or no certificate found.
    """
    key_info = sig.find(f"{{{NS_DS}}}KeyInfo")
    if key_info is None:
        raise JamSAMLValidationError(
            message="No KeyInfo in signature -- provide a public key explicitly.",
        )

    x509_data = key_info.find(f"{{{NS_DS}}}X509Data")
    if x509_data is not None:
        x509_cert = x509_data.find(f"{{{NS_DS}}}X509Certificate")
        if x509_cert is not None and x509_cert.text:
            pem = (
                "-----BEGIN CERTIFICATE-----\n"
                + x509_cert.text.strip()
                + "\n-----END CERTIFICATE-----"
            )
            return load_public_key(pem)

    raise JamSAMLValidationError(
        message="Cannot extract public key from signature KeyInfo.",
    )

---
title: SAML
---

SAML 2.0 (Security Assertion Markup Language) support.

The module implements both roles:

* **Service Provider (SP)** - accepts logins from external IdPs.
* **Identity Provider (IdP)** - issues SAML assertions.

!!! warning
    The SAML module is not implemented in `jam.Jam` / `jam.aio.Jam`. The reason is listed here: [makridenko.ru](https://makridenko.ru/posts/2026/05/25/some-think-about-jam)

Supported features:

* HTTP-POST, HTTP-Redirect and HTTP-Artifact bindings.
* XML-DSig signatures (RSA-SHA256) with embedded certificates.
* Assertion encryption (AES-256-GCM + RSA-OAEP) via `EncryptedAssertion`.
* Single Logout (SLO).
* Attribute Query.
* NameID Management.
* Metadata generation and parsing.
* Replay protection and clock skew tolerance.

Works with zero extra dependencies (`xml.etree` + `cryptography`).

## Setup

Module: `jam.saml.SAML`

There is no `Jam` instance integration yet, so the module is used directly
or through the `jam.saml.create_instance` factory.

Args:

* `role`: `str = "sp"` - `"sp"` (Service Provider) or `"idp"` (Identity Provider).
* `private_key`: `str | None` - PEM string or path to the private key file (used for signing and decryption).
* `public_key`: `str | None` - PEM string or path to the public key / certificate (used for verification).
* `certificate`: `str | None` - PEM certificate string (included in metadata and signatures).
* `entity_id`: `str | None` - Entity ID of this party.
* `acs_url`: `str | None` - Assertion Consumer Service URL (SP role).
* `sso_url`: `str | None` - Single Sign-On URL (IdP role).
* `idp_public_key`: `str | None` - IdP public key for signature verification (SP role).
* `sp_public_key`: `str | None` - SP public key for signature verification (IdP role).
* `encryption_key`: `str | None` - SP public key for assertion encryption (IdP role).
* `default_exp`: `int = 300` - Default assertion lifetime in seconds.
* `allowed_clock_skew`: `int = 120` - Clock skew tolerance in seconds.
* `want_assertions_signed`: `bool = True` - Require signed assertions (SP role).
* `id_store`: `dict | None` - Dict for replay protection. Auto-created if `None`.
* `replay_ttl`: `int = 300` - Seconds before a consumed ID is eligible for cleanup.

```python
from jam.saml import SAML

idp = SAML(
    role="idp",
    private_key="path/to/idp_private_key.pem",
    certificate="path/to/idp_cert.pem",
    entity_id="https://idp.example.com",
    sso_url="https://idp.example.com/sso",
)

sp = SAML(
    role="sp",
    private_key="path/to/sp_private_key.pem",
    entity_id="https://sp.example.com",
    acs_url="https://sp.example.com/acs",
    idp_public_key="path/to/idp_cert.pem",
)
```

## Service Provider

### Init

Module: `jam.saml.SAML` with `role="sp"`.

```python
from jam.saml import SAML

sp = SAML(
    role="sp",
    entity_id="https://sp.example.com",
    acs_url="https://sp.example.com/acs",
    idp_public_key="path/to/idp_cert.pem",
)
```

### Prepare AuthnRequest

Method: `sp.prepare_authn_request`

Args:

* `idp_sso_url`: `str` - IdP single sign-on endpoint URL.
* `acs_url`: `str | None` - SP assertion consumer service URL (defaults to the instance `acs_url`).
* `binding`: `str = "redirect"` - `"redirect"` or `"post"`.
* `**kwargs` - `relay_state`, `issuer`, `force_authn`, etc.

Returns:

`str` - Redirect: IdP URL with a signed AuthnRequest. POST: Base64-encoded SAMLRequest for an HTML form.

Redirect binding:

```python
url = sp.prepare_authn_request(
    idp_sso_url="https://idp.example.com/sso",
    acs_url="https://sp.example.com/acs",
    binding="redirect",
)
print(url)
>>> https://idp.example.com/sso?SAMLRequest=...&SigAlg=http%3A%2F%2Fwww.w3.org%2F2001%2F04%2Fxmldsig-more%23rsa-sha256&Signature=...
```

POST binding (embed the result in an HTML form field named `SAMLRequest`):

```python
saml_request = sp.prepare_authn_request(
    idp_sso_url="https://idp.example.com/sso",
    acs_url="https://sp.example.com/acs",
    binding="post",
)
```

### Parse response

Method: `sp.parse_response`

Args:

* `saml_response`: `str` - Raw SAMLResponse data (Base64 for POST, query-string for Redirect).
* `binding`: `str = "post"` - `"post"` or `"redirect"`.
* `**kwargs`:
  * `audience`: `str` - Expected audience (SP entity ID).
  * `issuer`: `str` - Expected issuer (IdP entity ID).
  * `acs_url`: `str` - Expected Recipient (ACS URL).
  * `verify_signature`: `bool` - Override `want_assertions_signed`.

Returns:

`SAMLResponse` - Parsed response with the assertion data.

```python
from jam.saml.binding import encode_post

saml_response = sp.parse_response(
    encoded_response,
    binding="post",
    audience="https://sp.example.com",
    issuer="https://idp.example.com",
)

print(saml_response.status_code)
>>> urn:oasis:names:tc:SAML:2.0:status:Success
print(saml_response.assertion.subject.name_id)
>>> user@example.com
print(saml_response.assertion.attributes)
>>> {"email": "user@example.com", "role": "admin"}
```

Encrypted assertions are decrypted automatically when the SP has a `private_key`:

```python
sp = SAML(
    role="sp",
    private_key="path/to/sp_private_key.pem",
    idp_public_key="path/to/idp_cert.pem",
)

result = sp.parse_response(encoded_response, binding="post")
```

## Identity Provider

### Init

Module: `jam.saml.SAML` with `role="idp"`.

```python
from jam.saml import SAML

idp = SAML(
    role="idp",
    private_key="path/to/idp_private_key.pem",
    certificate="path/to/idp_cert.pem",
    entity_id="https://idp.example.com",
    sso_url="https://idp.example.com/sso",
    sp_public_key="path/to/sp_cert.pem",
)
```

### Parse AuthnRequest

Method: `idp.parse_authn_request`

Args:

* `saml_request`: `str` - Raw SAMLRequest data.
* `binding`: `str = "redirect"` - `"redirect"` or `"post"`.
* `**kwargs` - `issuer` (expected issuer for validation).

Returns:

`SAMLRequest` - Parsed request.

```python
request = idp.parse_authn_request(
    query_string,
    binding="redirect",
    issuer="https://sp.example.com",
)

print(request.id)
>>> _abc123...
print(request.acs_url)
>>> https://sp.example.com/acs
```

### Build response

Method: `idp.build_response`

Args:

* `subject`: `str` - The authenticated user identifier.
* `attributes`: `dict[str, Any]` - User attributes (email, roles, etc.).
* `issuer`: `str` - IdP entity ID.
* `audience`: `str` - SP entity ID (the intended audience).
* `**kwargs`:
  * `in_response_to`: `str` - AuthnRequest ID.
  * `name_id_format`: `str` - NameID format.
  * `session_index`: `str` - Session index.
  * `destination`: `str` - ACS URL (defaults to the instance `acs_url`).
  * `encrypt`: `bool = False` - Encrypt the assertion with `encryption_key`.

Returns:

`str` - Signed (and optionally encrypted) SAML Response XML.

```python
xml_str = idp.build_response(
    subject="user@example.com",
    attributes={"email": "user@example.com", "role": "admin"},
    issuer="https://idp.example.com",
    audience="https://sp.example.com",
    in_response_to=request.id,
)
```

Encrypt the assertion (the SP must have the matching `private_key`):

```python
idp = SAML(
    role="idp",
    private_key="path/to/idp_private_key.pem",
    encryption_key="path/to/sp_cert.pem",
)

xml_str = idp.build_response(
    subject="user@example.com",
    attributes={"email": "user@example.com"},
    issuer="https://idp.example.com",
    audience="https://sp.example.com",
    encrypt=True,
)
```

## Single Logout

SLO is supported in both directions. Both `build_*` and `parse_*` methods
accept `binding="post"` or `binding="redirect"`.

### Build LogoutRequest

Method: `saml.build_logout_request`

Args:

* `name_id`: `str` - User identifier to log out.
* `issuer`: `str` - Entity ID of the sender.
* `destination`: `str` - SLO endpoint of the recipient.
* `session_index`: `str | None` - Session index (optional).
* `**kwargs` - `binding`, `relay_state`, `name_id_format`.

Returns:

`str` - POST: Base64-encoded signed XML. Redirect: signed redirect URL.

```python
result = sp.build_logout_request(
    name_id="user@example.com",
    issuer="https://sp.example.com",
    destination="https://idp.example.com/slo",
    session_index="_session_abc",
    binding="post",
)
```

### Parse LogoutRequest

Method: `saml.parse_logout_request`

Args:

* `saml_request`: `str` - Raw LogoutRequest data.
* `binding`: `str = "redirect"` - `"redirect"` or `"post"`.
* `**kwargs` - `issuer` (expected issuer).

Returns:

`SAMLLogoutRequest` - Parsed request.

```python
logout_request = idp.parse_logout_request(
    encoded,
    binding="post",
    issuer="https://sp.example.com",
)
print(logout_request.name_id)
>>> user@example.com
print(logout_request.session_index)
>>> _session_abc
```

### Build LogoutResponse

Method: `saml.build_logout_response`

Args:

* `in_response_to`: `str` - LogoutRequest ID to respond to.
* `issuer`: `str` - Entity ID of the sender.
* `destination`: `str` - SLO endpoint of the recipient.
* `status_code`: `str = "urn:oasis:names:tc:SAML:2.0:status:Success"` - SAML status code.
* `**kwargs` - `binding`, `relay_state`.

Returns:

`str` - POST: Base64-encoded signed XML. Redirect: signed redirect URL.

```python
result = idp.build_logout_response(
    in_response_to=logout_request.id,
    issuer="https://idp.example.com",
    destination="https://sp.example.com/slo",
    binding="post",
)
```

### Parse LogoutResponse

Method: `saml.parse_logout_response`

Args:

* `saml_response`: `str` - Raw LogoutResponse data.
* `binding`: `str = "redirect"` - `"redirect"` or `"post"`.
* `**kwargs` - `issuer` (expected issuer).

Returns:

`SAMLLogoutResponse` - Parsed response.

```python
logout_response = sp.parse_logout_response(
    encoded,
    binding="post",
    issuer="https://idp.example.com",
)
print(logout_response.status_code)
>>> urn:oasis:names:tc:SAML:2.0:status:Success
```

## Attribute Query

Lets an SP request specific user attributes from the IdP.

### Build AttributeQuery

Method: `sp.build_attribute_query`

Args:

* `subject`: `str` - Subject to query attributes for.
* `issuer`: `str` - SP entity ID.
* `destination`: `str` - IdP attribute query endpoint URL.
* `attribute_names`: `list[str] | None` - Specific attributes to request (`None` = all).
* `binding`: `str = "post"` - `"post"` or `"redirect"`.

Returns:

`str` - POST: Base64-encoded signed XML. Redirect: signed redirect URL.

```python
encoded = sp.build_attribute_query(
    subject="user@example.com",
    issuer="https://sp.example.com",
    destination="https://idp.example.com/attr",
    attribute_names=["email", "role"],
    binding="post",
)
```

### Parse AttributeQuery

Method: `idp.parse_attribute_query`

Args:

* `saml_request`: `str` - Raw AttributeQuery data.
* `binding`: `str = "redirect"` - `"redirect"` or `"post"`.
* `**kwargs` - `issuer` (expected issuer).

Returns:

`SAMLAttributeQuery` - Parsed query.

```python
query = idp.parse_attribute_query(encoded, binding="post")
print(query.subject)
>>> user@example.com
print(query.attribute_names)
>>> ["email", "role"]
```

### Build AttributeQueryResponse

Method: `idp.build_attribute_query_response`

Args:

* `in_response_to`: `str` - AttributeQuery ID.
* `subject`: `str` - The subject.
* `attributes`: `dict[str, Any]` - User attributes.
* `issuer`: `str` - IdP entity ID.
* `audience`: `str` - SP entity ID.

Returns:

`str` - Signed SAML Response XML.

```python
xml_str = idp.build_attribute_query_response(
    in_response_to=query.id,
    subject="user@example.com",
    attributes={"email": "user@example.com", "role": "admin"},
    issuer="https://idp.example.com",
    audience="https://sp.example.com",
)
```

### Parse AttributeQueryResponse

Method: `sp.parse_attribute_query_response`

Same signature and return type as `sp.parse_response`.

```python
result = sp.parse_attribute_query_response(
    encoded,
    binding="post",
    audience="https://sp.example.com",
    issuer="https://idp.example.com",
)
print(result.assertion.attributes)
>>> {"email": "user@example.com", "role": "admin"}
```

## Artifact Binding

The SP receives an artifact instead of the actual message, then resolves it
through a direct SOAP back-channel request to the IdP.

### Create an artifact

Method: `saml.build_artifact`

Args:

* `source_message_id`: `str` - ID of the referenced message.
* `issuer`: `str` - Entity ID of the issuer.

Returns:

`str` - Base64-encoded artifact.

```python
artifact = idp.build_artifact(
    source_message_id=response_id,
    issuer="https://idp.example.com",
)
print(artifact)
>>> AQAAEAAA...
```

### Build ArtifactResolve

Method: `sp.build_artifact_resolve`

Args:

* `artifact`: `str` - The artifact to resolve.
* `issuer`: `str` - SP entity ID.
* `destination`: `str` - IdP artifact resolution service URL.
* `**kwargs` - `binding` (`"post"`, `"redirect"`, or `"soap"`).

Returns:

`str` - POST: Base64. Redirect: signed URL. SOAP: raw XML.

```python
resolve_xml = sp.build_artifact_resolve(
    artifact=artifact,
    issuer="https://sp.example.com",
    destination="https://idp.example.com/artifact",
    binding="soap",
)
```

### Parse ArtifactResolve

Method: `idp.parse_artifact_resolve`

Args:

* `saml_request`: `str` - Raw ArtifactResolve data.
* `binding`: `str = "post"` - `"post"`, `"redirect"`, or `"soap"`.
* `**kwargs` - `issuer` (expected issuer).

Returns:

`SAMLArtifactResolve` - Parsed resolve request.

```python
resolve = idp.parse_artifact_resolve(soap_envelope, binding="soap")
print(resolve.artifact)
>>> AQAAEAAA...
```

### Build ArtifactResponse

Method: `idp.build_artifact_response`

Args:

* `in_response_to`: `str` - ArtifactResolve ID.
* `original_message_xml`: `str` - The original SAML message XML to embed.
* `issuer`: `str` - IdP entity ID.
* `destination`: `str` - SP endpoint URL.
* `**kwargs` - `binding`, `status_code`.

Returns:

`str` - POST: Base64. Redirect: signed URL. SOAP: raw XML.

```python
response_xml = idp.build_artifact_response(
    in_response_to=resolve.id,
    original_message_xml=original_response_xml,
    issuer="https://idp.example.com",
    destination="https://sp.example.com/acs",
    binding="soap",
)
```

### Parse ArtifactResponse

Method: `sp.parse_artifact_response`

Args:

* `saml_response`: `str` - Raw ArtifactResponse data.
* `binding`: `str = "post"` - `"post"`, `"redirect"`, or `"soap"`.
* `**kwargs` - `issuer` (expected issuer).

Returns:

`SAMLArtifactResponse` - Parsed response with the embedded `original_message`.

```python
artifact_response = sp.parse_artifact_response(
    soap_response,
    binding="soap",
)
print(artifact_response.original_message)
>>> <samlp:Response ...>
```

### Resolve artifact over HTTP

Method: `sp.resolve_artifact`

Sends the ArtifactResolve as a SOAP request to the IdP's artifact resolution
service and returns the original message.

Args:

* `artifact`: `str` - The artifact to resolve.
* `issuer`: `str` - SP entity ID.
* `resolve_url`: `str` - IdP artifact resolution service URL.
* `**kwargs` - `timeout` (int, default 10), `expected_issuer` (IdP entity ID for validation).

Returns:

`str` - The original SAML message XML from the ArtifactResponse.

```python
original_message = sp.resolve_artifact(
    artifact=artifact,
    issuer="https://sp.example.com",
    resolve_url="https://idp.example.com/artifact",
    timeout=15,
)
```

## NameID Management

Change or terminate a NameID with the other party.

### Build ManageNameIDRequest

Method: `saml.build_manage_name_id_request`

Args:

* `name_id`: `str` - Current NameID.
* `issuer`: `str` - Entity ID of the requester.
* `destination`: `str` - Recipient endpoint URL.
* `new_id`: `str | None` - New identifier (`None` = terminate).
* `binding`: `str = "post"` - `"post"` or `"redirect"`.

Returns:

`str` - POST: Base64-encoded signed XML. Redirect: signed redirect URL.

Change the identifier:

```python
encoded = sp.build_manage_name_id_request(
    name_id="user@example.com",
    new_id="newuser@example.com",
    issuer="https://sp.example.com",
    destination="https://idp.example.com/nameid",
    binding="post",
)
```

Terminate the identifier (no `new_id`):

```python
encoded = sp.build_manage_name_id_request(
    name_id="user@example.com",
    issuer="https://sp.example.com",
    destination="https://idp.example.com/nameid",
    binding="post",
)
```

### Parse ManageNameIDRequest

Method: `idp.parse_manage_name_id_request`

Args:

* `saml_request`: `str` - Raw ManageNameIDRequest data.
* `binding`: `str = "redirect"` - `"redirect"` or `"post"`.
* `**kwargs` - `issuer` (expected issuer).

Returns:

`SAMLManageNameIDRequest` - Parsed request.

```python
request = idp.parse_manage_name_id_request(encoded, binding="post")
print(request.name_id)
>>> user@example.com
print(request.new_id)
>>> newuser@example.com
```

### Build ManageNameIDResponse

Method: `saml.build_manage_name_id_response`

Args:

* `in_response_to`: `str` - ManageNameIDRequest ID.
* `issuer`: `str` - Entity ID of the responder.
* `destination`: `str` - Endpoint URL of the requester.
* `status_code`: `str` - SAML status code (default Success).
* `**kwargs` - `binding`, `relay_state`.

Returns:

`str` - POST: Base64-encoded signed XML. Redirect: signed redirect URL.

```python
encoded = idp.build_manage_name_id_response(
    in_response_to=request.id,
    issuer="https://idp.example.com",
    destination="https://sp.example.com/nameid",
    binding="post",
)
```

### Parse ManageNameIDResponse

Method: `sp.parse_manage_name_id_response`

Args:

* `saml_response`: `str` - Raw ManageNameIDResponse data.
* `binding`: `str = "redirect"` - `"redirect"` or `"post"`.
* `**kwargs` - `issuer` (expected issuer).

Returns:

`SAMLManageNameIDResponse` - Parsed response.

```python
response = sp.parse_manage_name_id_response(encoded, binding="post")
print(response.status_code)
>>> urn:oasis:names:tc:SAML:2.0:status:Success
```

## Metadata

### Generate metadata

Method: `saml.generate_metadata`

Args:

* `entity_id`: `str | None` - Entity ID (defaults to the instance `entity_id`).
* `sso_url`: `str | None` - SSO URL (IdP metadata).
* `acs_url`: `str | None` - ACS URL (SP metadata).
* `role`: `str | None` - `"idp"` or `"sp"` (defaults to the instance role).

Returns:

`str` - SAML metadata XML.

```python
idp_metadata = idp.generate_metadata(
    entity_id="https://idp.example.com",
    sso_url="https://idp.example.com/sso",
)

sp_metadata = sp.generate_metadata(
    entity_id="https://sp.example.com",
    acs_url="https://sp.example.com/acs",
)
```

### Parse metadata

Method: `saml.parse_metadata`

Args:

* `metadata_xml`: `str` - Raw metadata XML string.

Returns:

`SAMLMetadata` - Parsed metadata.

```python
metadata = sp.parse_metadata(idp_metadata)
print(metadata.entity_id)
>>> https://idp.example.com
print(metadata.sso_url)
>>> https://idp.example.com/sso
```

## Security

### Signature verification

Assertions and protocol messages are signed with RSA-SHA256 and an embedded
certificate. The SP verifies assertions using the `idp_public_key`; the IdP
verifies requests using `sp_public_key`. When no key is configured, the
certificate embedded in the signature `KeyInfo` is used.

Set `want_assertions_signed=False` on the SP to skip assertion signature
verification:

```python
sp = SAML(
    role="sp",
    want_assertions_signed=False,
)
```

### Clock skew

Expired or not-yet-valid assertions are rejected. The `allowed_clock_skew`
(default 120 seconds) tolerates small clock differences between the parties.

### Replay protection

Every incoming message ID is checked against the `id_store` before being
consumed, which raises `JamSAMLReplayDetected` on duplicate IDs. Pass your own
dict to share state between instances or processes:

```python
sp = SAML(
    role="sp",
    id_store=shared_store,
)
```

### XXE protection

Incoming XML is parsed with `safe_fromstring`, which rejects DTD/entity
declarations, preventing XXE and entity-expansion attacks.

## Exceptions

| Exception | Description |
|---|---|
| `JamSAMLError` | Base SAML error. |
| `JamSAMLExpired` | The assertion has expired. |
| `JamSAMLNotYetValid` | The assertion is not yet valid. |
| `JamSAMLInvalidAudience` | Audience validation failed. |
| `JamSAMLInvalidIssuer` | Issuer validation failed. |
| `JamSAMLInvalidRecipient` | SubjectConfirmationData Recipient does not match the expected ACS URL. |
| `JamSAMLReplayDetected` | The message ID has already been consumed (replay attack). |
| `JamSAMLSOAPError` | SOAP / artifact resolution failed. |
| `JamSAMLValidationError` | Generic signature or XML validation failure. |
| `JamSAMLEmptyPrivateKey` | Signing requires a `private_key`. |
| `JamSAMLEmptyPublicKey` | Verification requires a `public_key`. |
| `JamSAMLUnsupportedAlgorithm` | Unsupported SAML algorithm. |

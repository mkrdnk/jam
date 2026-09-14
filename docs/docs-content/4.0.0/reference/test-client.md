---
title: Test client
---

`TestJam` and `TestAsyncJam` are in-memory instances for testing applications
that depend on Jam. They use the real high-level `issue`, `authenticate` and
`authorize` implementations. Only external boundaries are replaced:

* JWT, JWS, JWE and PASETO do not use cryptographic keys;
* sessions are stored in memory and isolated between instances;
* OTP values and OAuth2 responses are deterministic;
* authorization can be allowed, denied or controlled by a callback.

This makes them suitable for application unit tests. Use a regular `Jam`
instance with test keys and storage for integration tests of cryptography or
specific storage backends.

For example, you have a service for generating JWT tokens.

!!! tip
    For async services, you can use `TestAsyncJam` instead of `TestJam`.

```python
from jam import Jam
from jam.exceptions import JamError


class AuthService:
    def __init__(self, jam: Jam) -> None:
        self.jam = jam

    # Generate token
    def generate_token(self, user) -> str:
        return self.jam.issue(user, via="jwt", exp=3600)

    # Validate token and return a principal or None
    def validate_token(self, token):
        try:
            return self.jam.authenticate(token, via="jwt")
        except JamError:
            return None
```

And you need to write tests for it:

```python
import pytest
from jam.tests import TestJam

from your_app.services import AuthService


@pytest.fixture
def auth_service() -> AuthService:
    return AuthService(jam=TestJam())

def test_auth_user(auth_service):
    user = {"id": 1, "username": "test_user"}
    token = auth_service.generate_token(user)  # Generate token
    assert token is not None

    validated = auth_service.validate_token(token)  # Validate token
    assert validated is not None
    assert validated.subject["id"] == user["id"]

    # if you want to test invalid token
    from jam.tests.fakers import invalid_token
    invalid_payload = auth_service.validate_token(invalid_token())
    assert invalid_payload is None
```

The test instance has the same module-oriented API as a configured production
instance:

```python
jam = TestJam(oauth2_providers=["github"])

token = jam.jwt.encode(payload={"role": "admin"})
payload = jam.jwt.decode(token)["payload"]

session_id = jam.session.create("auth", {"user_id": 1})
assert jam.session.get(session_id) == {"user_id": 1}

assert jam.otp.now() == "123456"
oauth_token = jam.oauth2["github"].fetch_token("code")
```

Authorization allows access by default. Pass a boolean for a deny-by-default
test, or a callback for a specific scenario:

```python
jam = TestJam(authorization=False)
assert jam.authorize({"id": "user-1"}, "post:delete") is False

jam = TestJam(
    authorization=lambda principal, permission, context: (
        permission == "post:read"
    )
)
assert jam.authorize({"id": "user-1"}, "post:read") is True

# Calls are available for assertions.
assert jam.policy.calls[0][1] == "post:read"
```

Stateless modules of `TestAsyncJam` remain synchronous, just like those of
`AsyncJam`; high-level credential operations, sessions and OAuth2 are
awaitable:

```python
jam = TestAsyncJam(oauth2_providers=["github"])

token = await jam.issue({"id": "user-1"}, via="jwt")
principal = await jam.authenticate(token)
session_id = await jam.session.create("auth", {"user_id": "user-1"})
oauth_token = await jam.oauth2["github"].fetch_token("code")
```

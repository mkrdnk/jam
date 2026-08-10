---
title: Test client
---

For convenient testing of your services that use Jam, you can easily replace the main Jam instance with a test instance that has the same interface but works according to its own rules (for example, always succeeds).

For example, you have a service for generating JWT tokens.

!!! tip
    For async services, you can use `TestAsyncJam` instead of `TestJam`.

```python
from jam import Jam
from jam.exceptions import JamError


class AuthService:
    def __init__(
        self,
        jam: Jam
    ) -> None:
        self.jam = jam

    # Generate token
    def generate_token(self, user) -> str:
        return self.jam.issue(user, via="jwt", exp=3600)

    # Validate token and return payload or None
    def validate_token(self, token) -> dict | None:
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
    return AuthService(
        jam=TestJam()  # Use TestJam instance here
    )

def test_auth_user(auth_service):
    user = {"id": 1, "username": "test_user"}
    token = auth_service.generate_token(user)  # Generate token
    assert token is not None

    validated = auth_service.validate_token(token)  # Validate token
    assert validated is not None
    assert validated["id"] == user["id"]

    # if you want to test invalid token
    from jam.tests.fakers import invalid_token
    invalid_payload = auth_service.validate_token(invalid_token())
    assert invalid_payload is None
```

`TestJam` always succeeds: `authorize` returns `True`, tokens are fake but
well-formed. `TestAsyncJam` mirrors the same methods as awaitables.

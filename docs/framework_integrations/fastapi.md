# FastAPI

Install the extra:

```bash
pip install "jamlib[fastapi]"
```

`JamAuth` provides required, optional, and permission-aware dependencies.
HTTP Bearer authentication is included in the generated OpenAPI schema.

```python
from typing import Annotated

from fastapi import Depends, FastAPI

from jam import Jam
from jam.authz import Principal
from jam.ext.fastapi import JamAuth


jam = Jam("config.toml")
auth = JamAuth(jam)
app = FastAPI()


@app.get("/me")
def me(
    principal: Annotated[Principal, Depends(auth)],
):
    return principal.subject


@app.get("/landing")
def landing(
    principal: Annotated[Principal | None, Depends(auth.optional)],
):
    return {"authenticated": principal is not None}


@app.patch("/posts/{post_id}")
def edit_post(
    post_id: str,
    principal: Annotated[
        Principal,
        Depends(auth.require("post:edit")),
    ],
):
    return {"post_id": post_id, "editor": principal.subject}
```

Required authentication returns `401` with `WWW-Authenticate: Bearer`.
Authorization failure returns `403`. Dynamic policy context can be derived
from the request:

```python
from jam.authz import AuthorizationContext


def context(request, principal):
    return AuthorizationContext(resource={"id": request.path_params["post_id"]})


can_edit = auth.require("post:edit", context=context)
```

Additional cookie, header, or query sources use the shared source API:

```python
from jam.ext.fastapi import CredentialSource

auth = JamAuth(
    jam,
    sources=[
        CredentialSource.bearer(),
        CredentialSource.cookie("session"),
    ],
)
```

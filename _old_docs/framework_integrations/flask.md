# Flask

Install the extra:

```bash
pip install "jamlib[flask]"
```

The extension supports both direct initialization and the application-factory
pattern.

```python
from flask import Flask

from jam import Jam
from jam.ext.flask import JamAuth, current_principal


jam = Jam("config.toml")
auth = JamAuth(jam=jam)


def create_app():
    app = Flask(__name__)
    auth.init_app(app)

    @app.get("/me")
    @auth.login_required
    def me():
        return current_principal.subject

    @app.patch("/posts/<post_id>")
    @auth.permission_required("post:edit")
    def edit_post(post_id):
        return {"post_id": post_id}

    return app
```

The current request exposes:

- `current_principal`;
- `g.principal`, `g.authentication`, and `g.jam`;
- `get_jam()` for extension-friendly access to the configured instance.

Configure multiple credential sources in priority order:

```python
from jam.ext.flask import CredentialSource, JamAuth

auth = JamAuth(
    jam=jam,
    sources=[
        CredentialSource.bearer(),
        CredentialSource.cookie("session"),
    ],
)
```

`permission_required()` accepts a zero-argument `context` callback for dynamic
authorization policy values.

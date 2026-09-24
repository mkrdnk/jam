# Production deployment

This example packages a FastAPI service with a persistent Jam KeyChain,
non-root container user, health checks, key bootstrap, and an explicit
rotation procedure. Adapt the container orchestration details to your
platform.

## Application configuration

Create `config.toml`:

```toml
[jam.keychains.jwt]
type = "FileStorage"
path = "/var/lib/jam/jwt-keys"
algorithm = "RS256"

[jam.jose.jwt]
alg = "RS256"
keychain = "jwt"

[[jam.authz.rules]]
effect = "allow"
permissions = ["profile:read"]
```

No private key appears in the image or configuration. The KeyChain directory
is mounted at runtime and must be owned by the process user.

!!! tip "Other configuration formats"
    Production configuration may also be a Python dictionary, YAML, or JSON.
    File configuration supports environment substitution. Supply secrets
    through the deployment platform rather than baking them into an image.

Create `app.py`:

```python
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, status

from jam import Jam
from jam.authz import Principal
from jam.ext.fastapi import JamAuth


jam = Jam(config="/app/config.toml")
auth = JamAuth(jam, via="jwt")
app = FastAPI(title="Jam production service")


@app.get("/health/live")
def liveness() -> dict[str, str]:
    return {"status": "alive"}


@app.get("/health/ready")
def readiness() -> dict[str, str]:
    if jam.keychains["jwt"].current() is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="JWT signing key is not initialized.",
        )
    return {"status": "ready"}


@app.get("/me")
def me(
    principal: Annotated[
        Principal,
        Depends(auth.require("profile:read")),
    ],
):
    return {"subject": principal.subject}
```

Readiness checks dependencies required to serve traffic; liveness only shows
that the process can answer. Do not put credentials, key material, or detailed
internal failures in either response.

## Build a non-root image

Create `requirements.txt` and lock exact versions in your normal dependency
workflow:

```text
jamlib[fastapi,cli]>=4.2,<4.3
uvicorn>=0.41,<1
```

Create `Dockerfile`:

```dockerfile
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    JAM_DEBUG=False

RUN groupadd --gid 10001 app \
    && useradd --uid 10001 --gid app --create-home app

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --requirement requirements.txt

COPY app.py config.toml ./
RUN mkdir -p /var/lib/jam/jwt-keys \
    && chown -R app:app /app /var/lib/jam \
    && chmod 700 /var/lib/jam/jwt-keys

USER 10001:10001
EXPOSE 8000

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
```

Run vulnerability scanning and produce an SBOM in CI. Prefer a lockfile with
hashes over floating dependency ranges in the final build.

## Mount and bootstrap key storage

For a local container demonstration, prepare a bind mount with the same UID as
the container:

```bash
mkdir -p runtime/jwt-keys
sudo chown 10001:10001 runtime/jwt-keys
chmod 700 runtime/jwt-keys

docker build -t jam-service .
docker run --rm \
  -v "$PWD/runtime/jwt-keys:/var/lib/jam/jwt-keys" \
  jam-service \
  jam keychain --config /app/config.toml add jwt initial

docker run --rm \
  -v "$PWD/runtime/jwt-keys:/var/lib/jam/jwt-keys" \
  jam-service \
  jam keychain --config /app/config.toml activate jwt initial
```

Start the service:

```bash
docker run --rm -p 8000:8000 \
  --read-only \
  --tmpfs /tmp \
  -v "$PWD/runtime/jwt-keys:/var/lib/jam/jwt-keys" \
  jam-service
```

The same persistent storage must be visible to every process that issues or
verifies these JWTs. Confirm that the platform preserves owner-only
permissions and filesystem locking semantics.

## Rotate without downtime

Run rotation as a controlled administrative job using the same configuration
and key volume:

```bash
docker run --rm \
  -v "$PWD/runtime/jwt-keys:/var/lib/jam/jwt-keys" \
  jam-service \
  jam keychain --config /app/config.toml \
  rotate jwt --key-id 2026-04
```

New tokens use `2026-04`; retired keys continue verifying existing tokens.
Keep them for at least the maximum token lifetime. Revoke a key immediately
only when credentials signed by it must stop working.

## Deployment checklist

- Terminate TLS at a trusted proxy and configure forwarded headers explicitly.
- Run as a non-root user with a read-only root filesystem.
- Back up key storage and test restoration without exposing private material.
- Allow only one controlled rotation writer.
- Keep credential lifetimes short and monitor authentication failures.
- Leave Jam sensitive-data redaction enabled.
- Rate-limit login and token issuance endpoints.
- Use shared session, replay, and state stores when running multiple replicas.
- Return generic authentication failures to clients and detailed safe metadata
  to structured logs.
- Test rotation, rollback, expired credentials, and compromised-key revocation
  before the first production release.

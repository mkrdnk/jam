# SAML SSO with Django SP and IdP applications

This example runs two Django projects:

- a Service Provider (SP) on `127.0.0.1:8000`;
- an Identity Provider (IdP) on `127.0.0.1:8001`.

The SP creates a signed AuthnRequest. The IdP validates it and returns a signed
SAMLResponse through an auto-submitted HTML form. The SP validates the
assertion and turns it into a Jam `Principal`.

## Create the projects and keys

```bash
mkdir django-saml
cd django-saml
python -m venv .venv
source .venv/bin/activate

pip install django "jamlib[django,cli]"

mkdir sp_app idp_app
django-admin startproject sp_project sp_app
django-admin startproject idp_project idp_app

jam keys rsa --private-out idp-private.pem --public-out idp-public.pem
jam keys rsa --private-out sp-private.pem --public-out sp-public.pem
chmod 600 idp-private.pem sp-private.pem
```

In a real federation, exchange public keys or signed metadata through a
trusted administrative channel. Never copy an IdP private key to an SP.

## Configure both SAML parties

Create `idp.toml` in the `django-saml` directory:

```toml
[jam.saml]
role = "idp"
entity_id = "http://127.0.0.1:8001"
sso_url = "http://127.0.0.1:8001/sso/"
audience = "http://127.0.0.1:8000"
private_key = "idp-private.pem"
public_key = "sp-public.pem"
default_exp = 300
```

Create `sp.toml`:

```toml
[jam.saml]
role = "sp"
entity_id = "http://127.0.0.1:8000"
expected_issuer = "http://127.0.0.1:8001"
acs_url = "http://127.0.0.1:8000/acs/"
private_key = "sp-private.pem"
idp_public_key = "idp-public.pem"
want_assertions_signed = true
```

!!! tip "Other configuration formats"
    Both projects can use Python dictionaries, YAML, or JSON instead of TOML.
    Keep entity IDs, endpoint URLs, and trusted keys consistent across both
    parties.

Add the local hosts to both generated settings files:

```python
ALLOWED_HOSTS = ["127.0.0.1", "localhost"]
```

Jam's SAML API is used directly by these Django views. The
`jam.ext.django.JamMiddleware` integration is intended for Bearer credentials
and Jam Session cookies and is not required for the SAML POST binding.

## Create the Django Service Provider

Create `sp_app/sp_project/views.py`:

```python
from pathlib import Path

from django.conf import settings
from django.http import HttpRequest, HttpResponseRedirect, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from jam import Jam


ROOT = Path(settings.BASE_DIR).parent
sp = Jam(config=str(ROOT / "sp.toml"))


@require_GET
def login(request: HttpRequest) -> HttpResponseRedirect:
    url = sp.saml.prepare_authn_request(
        idp_sso_url="http://127.0.0.1:8001/sso/",
        binding="redirect",
        relay_state="/account/",
    )
    return HttpResponseRedirect(url)


@csrf_exempt
@require_POST
def assertion_consumer_service(request: HttpRequest) -> JsonResponse:
    relay_state = request.POST.get("RelayState")
    if relay_state not in (None, "", "/account/"):
        return JsonResponse(
            {"error": "Invalid RelayState."},
            status=400,
        )

    principal = sp.authenticate(
        request.POST["SAMLResponse"],
        via="saml",
    )
    return JsonResponse(
        {
            "subject": principal.subject,
            "claims": principal.claims,
            "next": relay_state or "/",
        }
    )
```

Replace `sp_app/sp_project/urls.py`:

```python
from django.urls import path

from . import views


urlpatterns = [
    path("login/", views.login, name="saml-login"),
    path("acs/", views.assertion_consumer_service, name="saml-acs"),
]
```

The ACS is exempt from Django's CSRF middleware because the cross-site POST is
the SAML binding itself. This does not make it unauthenticated: Jam verifies
the XML signature, issuer, audience, recipient, time conditions, and replay
IDs. Do not apply `csrf_exempt` to unrelated views.

## Create the Django Identity Provider

Create `idp_app/idp_project/views.py`:

```python
from html import escape
from pathlib import Path

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.views.decorators.http import require_GET

from jam import Jam
from jam.saml.binding import encode_post


ROOT = Path(settings.BASE_DIR).parent
idp = Jam(config=str(ROOT / "idp.toml"))

# The demo assumes this user already authenticated at the IdP.
DEMO_USER = {
    "id": "user-1",
    "email": "alice@example.com",
    "role": "editor",
}


@require_GET
def single_sign_on(request: HttpRequest) -> HttpResponse:
    authn_request = idp.saml.parse_authn_request(
        request.GET.urlencode(),
        binding="redirect",
        issuer="http://127.0.0.1:8000",
    )
    if authn_request.acs_url != "http://127.0.0.1:8000/acs/":
        return JsonResponse(
            {"error": "Unregistered ACS URL."},
            status=400,
        )

    xml_response = idp.saml.build_response(
        subject=DEMO_USER["id"],
        attributes={
            "email": DEMO_USER["email"],
            "role": DEMO_USER["role"],
            "permissions": ["documents:read"],
        },
        issuer="http://127.0.0.1:8001",
        audience="http://127.0.0.1:8000",
        destination=authn_request.acs_url,
        in_response_to=authn_request.id,
        expires_in=300,
    )
    saml_response = encode_post(xml_response)
    relay_state = request.GET.get("RelayState", "")

    html = f"""
    <!doctype html>
    <html>
      <body onload="document.forms[0].submit()">
        <form method="post" action="{escape(authn_request.acs_url)}">
          <input type="hidden" name="SAMLResponse"
                 value="{escape(saml_response)}">
          <input type="hidden" name="RelayState"
                 value="{escape(relay_state)}">
          <noscript><button type="submit">Continue</button></noscript>
        </form>
      </body>
    </html>
    """
    return HttpResponse(html)
```

Replace `idp_app/idp_project/urls.py`:

```python
from django.urls import path

from . import views


urlpatterns = [
    path("sso/", views.single_sign_on, name="saml-sso"),
]
```

The fixed `DEMO_USER` replaces the IdP's login screen only to keep the protocol
flow visible. A real IdP must authenticate the browser before issuing an
assertion and should require MFA according to its policy.

## Run the SSO flow

Run both development servers from the `django-saml` directory:

```bash
python sp_app/manage.py runserver 127.0.0.1:8000
python idp_app/manage.py runserver 127.0.0.1:8001
```

Open [http://127.0.0.1:8000/login/](http://127.0.0.1:8000/login/). The browser
follows:

```text
Django SP /login/ -> Django IdP /sso/ -> Django SP /acs/
```

The ACS response displays the authenticated subject and assertion claims. A
production SP should map the SAML NameID to a local Django user and establish
a normal Django login session.

Use HTTPS, persistent shared replay storage, metadata-driven trust,
certificate rotation, strict ACS allowlists, validated local `RelayState`
targets, and short assertion lifetimes in production.

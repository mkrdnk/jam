---
title: OAuth2
---

## Use in instance

### Configuration

Args:

* `providers`: `hashmap`
  * `client_id`: `str` - Client ID in your app.
  * `client_secret`: `str` - Client secret in your app.
  * `auth_url`: `str` - Authorization URL.
  * `token_url`: `str` - Token URL.
  * `redirect_url`: `str` - Redirect URL.

Example:

```toml
[jam.oauth2.providers.linkedin]  # OAuth2 client
client_id = "$LINKEDIN_CLIENT_ID"
client_secret = "$LINKEDIN_CLIENT_SECRET"
auth_url = "https://www.linkedin.com/oauth/v2/authorization"
token_url = "https://www.linkedin.com/oauth/v2/accessToken"
redirect_url = "https://example.com/callback/linkedin"

[jam.oauth2.providers.github]  # builtin providers
client_id = "$GITHUB_CLIENT_ID"
client_secret = "$GITHUB_CLIENT_SECRET"
redirect_url = "https://example.com/callback/github"
```


### Usage

Configured providers are exposed as `jam.oauth2`, a dict of
`provider_name -> OAuth2Client`:

```python
from jam import Jam

jam = Jam(config="config.toml")

github = jam.oauth2["github"]
```

### Get auth url

Method: `jam.oauth2[provider].get_authorization_url`

Args:

* `scope`: `list[str]` - Scope for provider.
* `**extra_params` - Extra query params (e.g. `access_type="offline"`, `state="xyz"`).

Returns:

`str`: URL for authorization.

```python
url = jam.oauth2["github"].get_authorization_url(scope=["gist"])
```

### Fetch token

Method: `jam.oauth2[provider].fetch_token`

Args:

* `code`: `str` - OAuth2 code.
* `grant_type`: `str = authorization_code` - Type of oauth2 grant.

Returns:

`dict[str, Any]` - Tokens.

```python
tokens = jam.oauth2["github"].fetch_token(code="HGvdskHG")
```

### Refresh token

Method: `jam.oauth2[provider].refresh_token`

Args:

* `refresh_token`: `str` - Refresh token.
* `grant_type`: `str = "refresh_token"` - Grant type.

Returns:

`dict[str, Any]`: Tokens.

```python
tokens = jam.oauth2["github"].refresh_token(refresh_token=token)
```

### Client credentials flow

Method: `jam.oauth2[provider].client_credentials_flow`

Args:

* `scope`: `list[str]` - Scope for provider.

Returns:

`dict[str, Any]`: Data.

```python
tokens = jam.oauth2["github"].client_credentials_flow(scope=["gist"])
```

## Use out of instance

### Built

#### Custom provider

Module: `jam.oauth2.client.OAuth2Client`

Args:

* `client_id`: `str` - Client ID from oauth2 provider.
* `client_secret`: `str` - Client secret from oauth2 provider.
* `auth_url`: `str` - URL for authentication.
* `token_url`: `str` - URL for token exchange.
* `redirect_url`: `str` - Redirect URI for oauth2 flow.
* `serializer`: `BaseEncoder | type[BaseEncoder] = JsonEncoder` - JSON Serializer.

```python
from jam.oauth2 import OAuth2Client


custom_service = OAuth2Client(
    client_id="ID",
    client_secret="SECRET",
    auth_url="https://example.com/oauth2/auth",
    token_url="https://example.com/oauth2/token",
    redirect_url="https://example.com/oauth2/callback",
)
```

#### Builtin providers

Modules:

* `jam.oauth2.GitHubOAuth2Client`
* `jam.oauth2.GitLabOAuth2Client`
* `jam.oauth2.GoogleOAuth2Client`
* `jam.oauth2.YandexOAuth2Client`

Args:

* `client_id`: `str` - Client ID from oauth2 provider.
* `client_secret`: `str` - Client secret from oauth2 provider.
* `redirect_url`: `str` - Redirect URL for oauth2 flow.


```python
from jam.oauth2 import GitHubOAuth2Client

github_oauth2 = GitHubOAuth2Client(
    client_id="ID",
    client_secret="SECRET",
    redirect_url="https://example.com/oauth2/callback",
)
```


### Get auth url

Method: `oauth2.get_authorization_url`

Args:

* `scope`: `list[str]` - Scope for the oauth2 flow.

Returns:

`str` - Authorization URL for the oauth2 flow.

```python
url = oauth2.get_authorization_url(scope=["user", "email", "avatar"])
```

### Fetch token

Method: `oauth2.fetch_token`

Args:

* `code`: `str` - Authorization code from oauth2 provider.
* `grant_type`: `str = "authorization_code"` - Grant type for oauth2 flow.

Returns:

`dict` - Token response from oauth2 provider.

```python
tokens = oauth2.fetch_token(code="KJSKJDSLY7DJSK")
```

### Refresh token

Method: `oauth2.refresh_token`

Args:

* `refresh_token`: `str` - Refresh token from oauth2 provider.
* `grant_type`: `str = "refresh_token"` - Grant type for oauth2 flow.

Returns:

`dict` - Token response from oauth2 provider.

```python
tokens = oauth2.refresh_token(refresh_token=token)
```

### Client credentials

Method: `oauth2.client_credentials_flow`

Args:

* `scope`: `list[str]` - Scope for the oauth2 flow.

Returns:

`dict` - Token response from oauth2 provider.

```python
tokens = oauth2.client_credentials_flow(scope=["user", "email", "avatar"])
```

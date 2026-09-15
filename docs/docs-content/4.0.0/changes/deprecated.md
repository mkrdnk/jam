---
title: Deprecated methods
---

<!--Everything is relevant 👌-->

- `jam.Jam.jwt_make_payload`: The JWT specification has been introduced, so signing is now done via JWS
- `jam.Jam.jwt_create`: Use `jam.Jam.jwt_encode`
- `jam.jwt.JWT`: Use `jam.jose.JWT`
- `jam.Jam.jwt_encode`, `jam.Jam.jwt_decode`, `jam.Jam.session_*`, `jam.Jam.otp_*`,
  `jam.Jam.oauth2_*`, `jam.Jam.paseto_*`, `jam.Jam.jws_*`, `jam.Jam.jwe_*` (sync facade):
  removed in 4.0.0. Use `jam.issue` / `jam.authenticate` or the module
  attributes (`jam.jwt`, `jam.session`, ...). The same methods remain available
  as awaitables on `jam.aio.Jam`. See [3.0.0 -> 4.0.0](jam300_to_400.md).
- `jam.sessions.create_instance` param `sessions_type`: deprecated alias for `session_type`.

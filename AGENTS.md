# jamlib contributor guide

## Project

`jamlib` is a typed Python authentication and authorization library. It
contains JOSE (JWT/JWS/JWE/JWK), PASETO, Macaroons, server-side sessions,
OAuth2 clients, OTP, SAML, authorization policies, key management, token
lists, framework integrations, and synchronous/asynchronous facades.

- Supported Python: 3.10 and newer.
- Package source: `src/jam/`.
- Tests: `tests/`.
- Public package entry points: `jam.Jam` and `jam.aio.AsyncJam`.
- CLI entry point: `jam` -> `jam.cli:cli`.
- Runtime dependencies should stay minimal; most integrations are optional
  extras declared in `pyproject.toml`.

Treat the code, tests, and `pyproject.toml` as the source of truth. Some
documentation and compatibility aliases describe older APIs.

## Development commands

```bash
uv sync --group tests --all-extras   # install project, dev tools, tests, extras
uv run pytest -x                     # full test suite, stop on first failure
uv run pytest tests/modules/jose/    # targeted module tests
uv run pytest tests/instance/        # Jam/AsyncJam facade tests
uv run ruff check src/               # lint and import order
uv run ruff format --check src/      # verify formatting
uv run ruff format src/              # apply formatting
uv run pyrefly check                 # type-check src/jam (not mypy/pyright)
uv build                             # verify packaging changes
```

Run the narrowest relevant tests while iterating, then the full suite for
cross-cutting changes. CI runs `pytest -x` on Linux and macOS across Python
3.10-3.14. Release CI also builds the distribution.

## Architecture

### Facades and module assembly

- `src/jam/__core__.py` contains `_JamCore`: shared configuration parsing,
  module assembly, payload preparation, authorization plumbing, and pure
  operations used by both facades.
- `src/jam/__base__.py` / `src/jam/instance.py` define the synchronous
  `BaseJam` contract and concrete `Jam` implementation.
- `src/jam/aio/__base__.py` / `src/jam/aio/instance.py` define
  `BaseAsyncJam` and `AsyncJam`. Only operations that may cross an I/O
  boundary are async; cryptography, OTP, and policy checks remain sync.
- `src/jam/__init__.py` and package-level `__init__.py` files define the
  supported public import surface through imports and `__all__`.

`_JamCore.__build_instance` owns top-level config wiring. The effective root
configuration currently contains these sections:

```text
serializer
keychains.<name>
macaroon
jose.jwt | jose.jws | jose.jwe
session
oauth2.<provider>
paseto
otp
authz
```

Do not duplicate this assembly logic in a facade. When a high-level behavior
changes, inspect both `Jam` and `AsyncJam` and keep their validation, errors,
and return values aligned.

### Package layout

- `jose/`, `paseto/`, `macaroons/`, `saml/`, `otp/`: credential and protocol
  implementations.
- `sessions/`, `lists/`, `keychain/`, `oauth2/`: storage or service modules;
  async counterparts that perform I/O live under `aio/`.
- `authz/`: `Principal`, authorization context/constraints, policy contracts,
  rule compilation, and deny-by-default policy evaluation.
- `ext/`: framework-neutral HTTP authentication in `_base.py` plus Django,
  DRF/DMR, FastAPI, Flask, Litestar, and Starlette adapters.
- `exceptions/`: the public exception hierarchy.
- `utils/`: configuration, cryptographic helpers, validation, redaction, and
  small shared utilities.
- `tests/`: mirrors these areas; reusable downstream testing helpers live in
  `src/jam/tests/` and are part of the installed package.

Avoid importing optional dependencies at module import time when the feature
is not in use. Follow the existing local-import pattern in factories and
integration modules to prevent optional-dependency failures and circular
imports.

## Interfaces and extension points

There is no single extension mechanism. Follow the contract used by the
specific package you are changing.

- Public behavioral contracts generally live in `__base__.py` as `Base*`
  classes using `ABC` and `@abstractmethod`. Abstract methods document the
  contract and raise `NotImplementedError`.
- Concrete implementations must preserve compatible signatures, return
  types, validation, and sync/async behavior. Add the implementation to the
  package export surface when it is public.
- Use `Protocol` for structural, behavior-only contracts that do not provide
  shared state or implementation. `AuthorizationConstraint` is the canonical
  example.
- Not every contract is an ABC. `BaseSubject` deliberately validates
  subclasses in `__init_subclass__`; subject subclasses must be dataclasses
  and must declare their own `id` annotation.
- Backends selected by short names use registries or factories. Examples are
  `sessions.REGISTRY`, `paseto.REGISTRY`, `lists.build_list`, OAuth2
  `BUILTIN_PROVIDERS`/`build_clients`, and the Macaroon factory. Update the
  relevant registry/factory, exports, and tests together.
- Custom classes named in configuration are imported by
  `utils.config_maker.__module_loader__` from a full dotted path such as
  `my_package.module.CustomClass`. The loader only imports and returns the
  attribute; the caller/factory owns config copying, contract validation, and
  instantiation.

When adding a new module or backend:

1. Start from the closest `Base*` contract and neighboring implementation.
2. Keep constructor parameter names compatible with configuration keys.
3. Register it in the actual factory/registry used by `_JamCore`.
4. Export only intended public names from the package.
5. Add direct contract tests and high-level `Jam`/`AsyncJam` wiring tests.
6. Add or update the optional extra if a new third-party dependency is needed.

## Configuration and `ConfigMeta`

`src/jam/utils/config_maker.py` is the central configuration implementation.
`__config_maker__` accepts either an already selected dictionary or a YAML,
TOML, or JSON path. File configs support environment substitution using
`${VAR}`, `${VAR:-default}`, and `$VAR`. Parsed file configs may be cached;
callers receive copies so they can safely remove routing keys before passing a
section onward.

Pointer handling is currently format-specific: TOML walks a dotted path,
YAML looks up the pointer as one top-level key (or returns the whole document
when that key is absent), and JSON returns the parsed document. Passing a dict
also returns that dict's shallow copy without applying a pointer. Do not assume
a dotted module pointer behaves identically for every format; preserve and
test the observed behavior, or deliberately normalize all formats as part of
the change.

`ConfigMeta` in `src/jam/utils/config_meta.py` makes selected module classes
directly constructible from configuration:

```python
class Example(BaseExample, metaclass=ConfigMeta):
    _CONFIG_POINTER = "jam.example"

    def __init__(
        self,
        required: str,
        option: int = 1,
        config: str | dict[str, Any] | None = None,
        pointer: str | None = None,
    ) -> None:
        ...
```

Its contract is precise:

- If `config` is absent/`None`, construction proceeds normally.
- If `config` is present, the metaclass resolves it with the explicit
  `pointer` or the class `_CONFIG_POINTER`.
- Only keys matching named `__init__` parameters are injected. Unrelated
  config keys are ignored.
- Explicit positional or keyword arguments override config values.
- `config` and `pointer` are consumed by the metaclass and are not forwarded
  to the constructor.
- A dict passed to a module is expected to be that module's selected section;
  `_JamCore` commonly copies a nested section and passes it this way.

Therefore, classes using `ConfigMeta` should have explicit, keyword-compatible
constructor parameters and should retain the public `config` and `pointer`
placeholders in their signatures. Do not reparse config inside `__init__`.
Set `_CONFIG_POINTER` to the file-config section for direct construction.
Classes inheriting from a base that already uses `ConfigMeta` inherit the
metaclass; classes whose base does not use it must declare it explicitly. Do
not design `ConfigMeta` constructors around variadic positional arguments;
injection is based on named parameters from `inspect.signature`.

Configuration changes need tests for both direct dict construction and file
config/pointer behavior. Preserve explicit-argument precedence, do not mutate
the caller's dict, and clear or isolate the config cache in tests that modify
files or environment variables.

## Errors, authentication, and security

- Public failures derive from `JamError` and expose a human-readable message,
  stable machine-readable `error_code`, and optional `details`.
- Use `JamConfigurationError` for invalid setup and a domain-specific
  `JamValidationError`/`JamError` subclass for invalid credentials or protocol
  data. Preserve exception chaining when translating lower-level failures.
- Authorization and credential validation must fail closed. Do not turn
  malformed, unverifiable, expired, revoked, or constraint-failing credentials
  into successful principals.
- Never log raw tokens, passwords, secrets, private keys, session contents, or
  OAuth credentials. The package installs `SensitiveDataFilter`, but callers
  must still log only safe metadata such as mechanism, counts, and exception
  class names.
- Preserve protocol ordering and authenticated-data boundaries. Changes to
  cryptographic code require positive tests plus tampering, wrong-key,
  malformed-input, and boundary tests relevant to that protocol.
- Keep framework adapters thin: extract credentials, delegate to the supplied
  `Jam`/`AsyncJam`, translate expected `JamError`s, and do not implement a
  second authentication path in an integration.

## Compatibility

This is a library, so constructors, public imports, config keys, serialized
formats, exception types/codes, and sync/async semantics are compatibility
surfaces.

- Preserve documented aliases and deprecation paths unless the task explicitly
  removes them. For example, session code still accepts the deprecated
  `sessions_type` alias for `session_type`.
- Copy configuration before `pop` or normalization; never mutate user-owned
  mappings.
- Update `__all__` when adding or removing public API.
- Keep `Jam` and `AsyncJam` behavior symmetric except at genuine I/O points.
- Do not change the project version, changelog, lockfile, or generated docs
  unless the task requires it.

## Code style

The authoritative settings are in `pyproject.toml`.

- Target Python 3.10; do not introduce syntax unavailable there.
- Maximum line length is 80. Ruff formats with double quotes.
- Import groups follow Ruff/isort; `jam` is first-party and import sections
  have two blank lines after them.
- Use Google-style docstrings for public modules, classes, methods, functions,
  arguments, returns, and meaningful raises. Describe behavior and invariants,
  not the implementation line by line.
- Add precise annotations. Use `collections.abc` for runtime collection
  protocols and reserve `Any` for genuinely dynamic/configuration boundaries.
- Keep private naming consistent with the surrounding package. Existing
  double-underscore module helpers are established internal APIs; do not add
  new ones without a reason.
- Ruff excludes tests and package `__init__.py` files, and Pyrefly currently
  checks only `src/jam`; still keep excluded code formatted, typed where
  practical, and covered by tests.

## Testing expectations

- Put tests beside the corresponding area under `tests/modules/`,
  `tests/instance/`, `tests/extensions/`, or `tests/utils/`.
- Use `pytest` and `pytest-asyncio`; async tests should be truly async and
  exercise async backends rather than wrapping sync behavior.
- Use `fakeredis` for Redis behavior. Tests must not require external Redis,
  network access, real OAuth providers, or real framework servers.
- Cover success, invalid input, missing configuration, and security failure
  paths. Assert domain exceptions and stable error codes where they are part
  of the contract.
- For config-driven modules, test direct construction and construction through
  the high-level facade. For backend additions, test factory/registry
  selection. For shared facade changes, test both sync and async variants.
- Keep tests deterministic: inject clocks, ID factories, keys, and temporary
  paths where the implementation supports them; clean up environment changes.

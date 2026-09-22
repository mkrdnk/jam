# Contributing to jamlib

Thank you for contributing to jamlib. The project is a typed authentication
and authorization library, so compatibility and secure failure behavior are
part of every public contract. Small fixes are welcome; for substantial API or
architecture changes, open an issue first so the intended behavior can be
agreed before implementation.

The code, tests, and `pyproject.toml` are the source of truth. Some historical
documentation and compatibility aliases describe older APIs.

## Development setup

jamlib supports Python 3.10 and newer. Install
[uv](https://docs.astral.sh/uv/), clone the repository, and create the complete
development environment:

```bash
git clone https://github.com/mkrdnk/jam.git
cd jam
uv sync --group tests --all-extras
```

You can also enable the repository hooks:

```bash
uv run pre-commit install
```

The hooks keep `uv.lock` consistent and run Ruff. Only commit a lockfile change
when the contribution changes dependencies or otherwise requires it.

## Repository structure

| Path | Purpose |
| --- | --- |
| `src/jam/` | Package source |
| `src/jam/aio/` | Async facades and I/O-capable async backends |
| `src/jam/ext/` | Framework integrations |
| `src/jam/tests/` | Reusable downstream testing helpers shipped with the package |
| `tests/` | Project test suite, organized like the package |
| `docs/` | Versioned documentation and its React application |

The public package entry points are `jam.Jam` and `jam.aio.AsyncJam`. Individual
protocol and storage modules are also public where their package `__init__.py`
exports them.

## Architecture and extension contracts

jamlib has several extension patterns rather than one universal plugin API.
Start with the closest existing implementation and preserve the contract used
by that package.

### Base classes

Most behavioral contracts are `Base*` abstract classes in `__base__.py` files.
They use `ABC` and `@abstractmethod` to define supported signatures, return
types, and sync or async behavior. Abstract methods document the contract and
raise `NotImplementedError`.

When adding an implementation:

1. Inherit from the closest `Base*` class.
2. Keep constructor parameter names compatible with configuration keys.
3. Preserve method signatures, validation, return values, and exception types.
4. Export the class from the package only if it is intended to be public.
5. Add direct contract tests and high-level facade wiring tests.

Use a `Protocol` when an extension is purely structural and does not need
shared state or an implementation. `AuthorizationConstraint` is the canonical
example.

`BaseSubject` is a special contract rather than an ABC. Subject subclasses must
be dataclasses and must declare their own `id` annotation:

```python
from dataclasses import dataclass

from jam import BaseSubject


@dataclass
class User(BaseSubject):
    id: str
    email: str
```

### Facades and module assembly

`src/jam/__core__.py` contains `_JamCore`, which owns shared configuration
parsing, module assembly, payload preparation, and authorization plumbing.
`BaseJam` and `Jam` provide the synchronous facade; `BaseAsyncJam` and
`AsyncJam` provide its asynchronous counterpart.

Do not duplicate assembly logic in a facade. Add shared pure behavior and
configuration wiring to `_JamCore`, then keep both facades aligned. Only work
that can cross an I/O boundary should be async. Cryptography, OTP, payload
preparation, and authorization policy checks remain synchronous.

The root configuration currently assembles these sections:

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

A change to high-level behavior normally needs tests for both `Jam` and
`AsyncJam`, even if the implementation itself is shared.

### Configuration and `ConfigMeta`

`src/jam/utils/config_maker.py` parses dictionaries and YAML, TOML, or JSON
files. File configuration supports `${VAR}`, `${VAR:-default}`, and `$VAR`
environment substitution. Callers receive copies of parsed sections; always
copy user-owned mappings before removing routing keys or normalizing values.

Pointer behavior is currently format-specific: TOML walks a dotted path, YAML
looks up the pointer as one top-level key (and otherwise returns the complete
document), and JSON returns the parsed document. A dictionary is treated as an
already selected section. Preserve these semantics unless the contribution
deliberately changes and tests all formats.

Concrete modules that use `ConfigMeta` can be constructed directly from a
selected dictionary or a configuration file:

```python
class Example(BaseExample, metaclass=ConfigMeta):
    _CONFIG_POINTER = "jam.example"

    def __init__(
        self,
        required: str,
        option: int = 1,
        config: str | dict[str, object] | None = None,
        pointer: str | None = None,
    ) -> None:
        ...
```

`ConfigMeta` has a precise contract:

- `config=None` performs normal construction;
- an explicit `pointer` overrides the class `_CONFIG_POINTER`;
- only keys matching named `__init__` parameters are injected;
- explicit positional and keyword arguments override configuration values;
- `config` and `pointer` are consumed by the metaclass and are not forwarded;
- unrelated configuration keys are ignored.

Classes using `ConfigMeta` should therefore expose explicit,
keyword-compatible constructor parameters plus the public `config` and
`pointer` placeholders. Do not parse configuration again in `__init__`, and do
not design these constructors around variadic positional arguments. A subclass
inherits `ConfigMeta` when its base already uses it; otherwise declare the
metaclass explicitly.

Configuration changes need tests for direct dictionary construction and file
configuration with pointers. Test explicit-argument precedence, verify the
caller's mapping is not mutated, and isolate the configuration cache in tests
that modify files or environment variables.

### Registries, factories, and custom modules

Backends selected by short configuration names are assembled by package-level
registries or factories. Existing examples include:

- `sessions.REGISTRY`;
- `paseto.REGISTRY`;
- `lists.build_list` and its async counterpart;
- OAuth2 `BUILTIN_PROVIDERS` and `build_clients`;
- the Macaroon factory.

Register a new backend in the factory actually used by `_JamCore`, update the
public exports where appropriate, and test selection through both the factory
and the facade. If the backend introduces a third-party dependency, keep it
optional and add the smallest suitable extra in `pyproject.toml`.

Configuration may name a custom class by a full dotted path such as
`my_package.module.CustomClass`. `__module_loader__` only imports and returns
that attribute. The caller or factory remains responsible for copying config,
validating the contract, and instantiating the class.

Avoid importing optional dependencies at package import time. Follow the
existing local-import pattern in factories and integration modules to prevent
unused extras from becoming mandatory and to avoid circular imports.

### Public API and compatibility

This is a library, so compatibility includes more than function signatures.
Treat these as public surfaces:

- imports and package `__all__` values;
- constructors and return types;
- configuration keys and documented aliases;
- serialized credential and storage formats;
- exception classes and stable error codes;
- synchronous versus asynchronous behavior.

Preserve documented aliases and deprecation paths unless the change explicitly
removes them. When adding a public symbol, update the relevant package export.
Do not change the project version, changelog, generated documentation, or
release artifacts unless the contribution specifically requires it.

### Errors and security-sensitive behavior

Public errors derive from `JamError` and expose a human-readable message, a
stable `error_code`, and optional details. Use `JamConfigurationError` for
invalid setup and the appropriate `JamValidationError` or domain-specific
subclass for invalid credentials and protocol data. Preserve exception
chaining when translating lower-level failures.

Authentication and authorization must fail closed. Malformed, unverifiable,
expired, revoked, or constraint-failing credentials must never produce a
successful principal. Preserve protocol operation ordering and authenticated
data boundaries.

Never log or commit raw tokens, passwords, secrets, private keys, session
contents, or OAuth credentials. Security-sensitive changes need positive tests
plus the relevant wrong-key, tampering, malformed-input, expiration, and
boundary cases.

Keep web-framework adapters thin: extract credentials, delegate to the supplied
`Jam` or `AsyncJam`, and translate expected `JamError` instances. Do not create
a second authentication implementation inside an adapter.

## Code style

The authoritative settings are in `pyproject.toml`.

- Target Python 3.10; do not introduce newer syntax.
- Keep lines at or below 80 characters.
- Use precise type annotations and `collections.abc` collection protocols.
- Reserve `Any` for genuinely dynamic or configuration boundaries.
- Use Google-style docstrings for public APIs.
- Let Ruff manage formatting, double quotes, and import order.

Check source code with:

```bash
uv run ruff check src/
uv run ruff format --check src/
uv run pyrefly check
```

To apply formatting locally, run `uv run ruff format src/`. Avoid unrelated
formatting changes.

## Tests

Put tests beside the corresponding area:

- `tests/modules/` for protocols, storage modules, and backends;
- `tests/instance/` for `Jam` and `AsyncJam` facade behavior;
- `tests/extensions/` for framework integrations;
- `tests/utils/` for configuration and shared utilities.

Use `pytest` and `pytest-asyncio`. Async tests should exercise actual async
backends instead of wrapping synchronous behavior. Use `fakeredis` for Redis
tests; the suite must not require a network, a real Redis server, an OAuth
provider, or a framework server.

Cover successful behavior, invalid input, missing configuration, and relevant
security failures. Assert domain exceptions and stable error codes when they
are part of the contract. Keep tests deterministic by injecting clocks, ID
factories, keys, and temporary paths where supported.

Run the narrowest relevant tests while developing, for example:

```bash
uv run pytest tests/modules/jose/
uv run pytest tests/instance/
```

Before opening a pull request, run the full suite and build the distribution:

```bash
uv run pytest -x
uv build
```

CI runs the test suite on Linux and macOS across supported Python versions.

## Documentation changes

Documentation is a separate React application with versioned Markdown. Read
`docs/README.md` before changing it. It explains version selection, navigation,
generated files, API reference generation, and Markdown conventions.

For a documentation contribution, install and validate the site from the
`docs/` directory:

```bash
npm ci
npm run build
```

Examples must not contain real credentials or usable secrets. Prefer complete,
runnable examples that explain security-relevant defaults and failures.

## Pull requests

Keep each pull request focused and explain both the behavior change and why it
is needed. Include the commands used to validate it. Before submitting, check
that:

- relevant direct and facade tests were added or updated;
- sync and async behavior remain aligned;
- public imports, configuration, errors, and serialized formats remain
  compatible, or the intended incompatibility is clearly documented;
- factories, registries, and `__all__` exports were updated together;
- optional features still import without their extra dependencies;
- Ruff, Pyrefly, the full test suite, and the package build pass;
- user-facing behavior is documented;
- no credentials, keys, generated release output, or unrelated changes are
  included.


# Contributing

If you want to help develop Jam, there are a few rules to follow.

## Code style

- Python >= 3.10
- Line length: 80 characters, indented 4 spaces
- Import order: stdlib → third-party → library modules (handled by ruff/isort)
- Docstrings: Google convention (handled by ruff/pydocstyle)

```python
# Built-in libraries
from typing import Literal

# Third-party libraries
from cryptography.hazmat.primitives import hashes

# Library modules
from jam.jwt import Token


class SomeClass:
    """Long class description."""

    def __init__(self, some_value: str) -> None:
        """Class constructor.

        Args:
            some_value (str): Some value
        """
        self.sv = some_value

    def some_method(self, something: int) -> int:
        """Method description.

        Args:
            something (int): Argument description

        Raises:
            ValueError: if something < 1

        Returns:
            int: Something plus one
        """
        if something < 1:
            raise ValueError("something < 1")

        return something + 1
```

## Development Tools

- **ruff** — linter + formatter (`uv run ruff check`, `uv run ruff format`)
- **pytest** — tests (`uv run pytest`)
- **pyrefly** — type checking (`uv run pyrefly check`)
- **pre-commit** — `uv run pre-commit run --all-files`

## Gitflow

### Commits

The project must have `pre-commit`

* `[+]` Adding new functionality
* `[-]` Removing something, e.g. removing a function or deleting a file
* `[*]` Changing the logic
* `[~]` Changes that do not affect the logic, documentation, linters, etc

The keys in the commit body are also used:

* `R`(reason): Reason for change, deletion, etc
* `FB`(fix by): How it was made or fixed
* `N`(note): A note of some kind

Example of a correct commit:

```
[*] Changed JWT decryption logic
R: Used a third-party heavy dependency that slowed down the code
FB: Removed the dependency and wrote independently
```

### Branches

All branches are created from `master` and adhere to strict branch naming:

* New feature: `feature/<id-issue-if-it-is>-<pair-words-about-feature>`
* Bug fixes: `fix/<id-issue-if-it-is>-<pair-words-about-bug>`
* Refactoring: `refactor/<id-issue-if-it-is>-<what-exactly-you-do>`
* Writing documentation: `docs/<what-exactly-you-do>`

Examples:

* `feature/validate-redis-session`
* `fix/18-jwt-making`

### Pull requests

The title of the pull request must contain a keyword:

* `FEAT` — Adding a new feature
* `BUGFIX` — Bug fix
* `HOTFIX` — Urgent bug fix
* `DOCS` — Edits/additions to documentation

Example:

```markdown
FEAT Validation of a redis session

## What was done

- Brief description of what was done

## Test report

- How you tested
```

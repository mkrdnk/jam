from importlib.metadata import version

import jam


def test_package_version_matches_distribution_metadata() -> None:
    """The public version comes from the installed distribution metadata."""
    assert jam.__version__ == version("jamlib")

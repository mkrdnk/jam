# Installation


Jam requires Python 3.10 or later.

Install the released package from [PyPI](https://pypi.org/project/jamlib/):

```bash
pip install jamlib
```

Install optional dependencies only for the modules you use:

```bash
pip install "jamlib[yaml]"      # YAML configuration
pip install "jamlib[redis]"     # Redis sessions and lists
pip install "jamlib[oauth2]"    # async OAuth2 clients
pip install "jamlib[fastapi]"   # FastAPI integration
```

The available extras are `cli`, `redis`, `json`, `oauth2`, `yaml`, `toml`,
`litestar`, `starlette`, `fastapi`, and `flask`.

To install the latest development version from GitHub:

```bash
pip install git+https://github.com/mkrdnk/jam.git@master
```

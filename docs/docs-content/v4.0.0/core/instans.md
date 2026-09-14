# Installation

```bash
pip install jamlib
```

```python
from jam import Jam

jam = Jam()

@app.get("/")
async def home():
    payload = {"sub": "123", "name": "Alice"}
    token = jam.jwt.encode(payload)
    data = jam.jwt.decode(token)
    return {"user": data["name"]}
```

Inline code: `auth = JamAuth(jam)`

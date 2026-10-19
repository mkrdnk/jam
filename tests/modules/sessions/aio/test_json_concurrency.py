"""Whole-operation locking survives cancellation and concurrent close."""

import asyncio
from threading import Event, get_ident

import pytest

from jam.aio.sessions.json import JSONSessions
from jam.exceptions import JamError, JamSessionNotFound


@pytest.mark.asyncio
async def test_concurrent_creates_updates_and_rotation(tmp_path):
    backend = JSONSessions(json_path=str(tmp_path / "sessions.json"))
    tokens = await asyncio.gather(
        *(backend.create("auth", {"n": i}) for i in range(30))
    )
    await asyncio.gather(
        *(
            backend.update(token, {"n": i + 100})
            for i, token in enumerate(tokens)
        )
    )
    values = await asyncio.gather(*(backend.get(token) for token in tokens))
    assert values == [{"n": i + 100} for i in range(30)]
    results = await asyncio.gather(
        backend.rework(tokens[0]),
        backend.rework(tokens[0]),
        return_exceptions=True,
    )
    assert sum(isinstance(value, str) for value in results) == 1
    assert sum(isinstance(value, JamSessionNotFound) for value in results) == 1
    await backend.clear("auth")
    assert all(
        value is None
        for value in await asyncio.gather(
            *(backend.get(token) for token in tokens)
        )
    )
    await backend.aclose()
    await backend.aclose()
    with pytest.raises(JamError) as error:
        await backend.get(tokens[0])
    assert error.value.error_code == "sessions.closed"


@pytest.mark.asyncio
async def test_cancelled_worker_keeps_lock_until_complete(
    tmp_path, monkeypatch
):
    backend = JSONSessions(json_path=str(tmp_path / "sessions.json"))
    token = await backend.create("auth", {})
    started, release = Event(), Event()
    main_thread = get_ident()
    original = backend._session.update

    def slow_update(*args):
        assert get_ident() != main_thread
        started.set()
        assert release.wait(5)
        return original(*args)

    monkeypatch.setattr(backend._session, "update", slow_update)
    task = asyncio.create_task(backend.update(token, {"done": True}))
    try:
        assert await asyncio.to_thread(started.wait, 5)
        # The loop is responsive although the storage worker is still blocked.
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        close = asyncio.create_task(backend.aclose())
        await asyncio.sleep(0)
        assert not close.done()
        assert not backend._lock.acquire(blocking=False)
    finally:
        release.set()
    await asyncio.wait_for(close, 5)
    assert backend._closed

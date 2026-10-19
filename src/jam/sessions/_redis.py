"""Shared Redis session scripts and TTL validation."""

from enum import Enum

from jam.exceptions import JamConfigurationError, JamError, JamSessionNotFound


class _UnsetTTL(Enum):
    VALUE = "unset"


UNSET_TTL = _UnsetTTL.VALUE


def _validate_ttl(ttl: int | None) -> int | None:
    """Validate the session TTL before any storage mutation."""
    if ttl is not None and (
        isinstance(ttl, bool) or not isinstance(ttl, int) or ttl < 0
    ):
        raise JamConfigurationError(
            message="Session TTL must be a non-negative integer or None.",
            error_code="configuration.session.invalid_ttl",
        )
    return ttl


# All scripts address one hash; serialization happens before invoking Redis.
# Lua does not roll back writes on error. Remove a new field if TTL setup
# fails, and retain the old field until rotation has fully succeeded.
SESSION_WRITE = """
local key, operation, old, new = KEYS[1], ARGV[1], ARGV[2], ARGV[3]
local value, ttl = ARGV[4], tonumber(ARGV[5])
if operation ~= 'create' then
    local previous = redis.call('HGET', key, old)
    if not previous then return 0 end
    if operation == 'rework' then value = previous end
end
if operation ~= 'update' and
   (new == old or redis.call('HEXISTS', key, new) == 1) then
    return -1
end
redis.call('HSET', key, new, value)
if ttl > 0 then
    local result = redis.pcall('HEXPIRE', key, ttl, 'FIELDS', 1, new)
    if result.err then
        redis.call('HDEL', key, new)
        return redis.error_reply(result.err)
    end
end
if operation == 'rework' then redis.call('HDEL', key, old) end
return 1
"""


def _check_write_result(result: object) -> None:
    """Translate script outcomes without including session credentials."""
    if result == 0:
        raise JamSessionNotFound
    if result == -1:
        raise JamError(
            message="Session ID factory produced an existing identifier.",
            error_code="sessions.id_collision",
        )
    if result != 1:
        raise JamError(
            message="Unexpected Redis session write result.",
            error_code="sessions.storage_error",
        )

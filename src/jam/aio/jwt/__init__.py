# -*- coding: utf-8 -*-

"""
Async JWT module.
"""

from typing import Any, Optional, Union

from jam.jwt.__base__ import BaseJWT
from jam.jwt.__types__ import KeyLike
from jam.encoders import BaseEncoder, JsonEncoder


def create_instance(
    alg: str,
    secret: Optional[KeyLike] = None,
    secret_key: Optional[KeyLike] = None,  # Backward compatibility
    password: Optional[Union[str, bytes]] = None,
    serializer: Union[BaseEncoder, type[BaseEncoder]] = JsonEncoder,
    **kwargs: Any
) -> BaseJWT:
    """Create async-compatible JWT instance.
    
    Note: JWT encoding/decoding itself is synchronous, but this allows
    for async-compatible list checking if lists are configured.
    
    Args:
        alg: Algorithm (HS256, RS256, etc.)
        secret: Secret key (or use secret_key for backward compatibility)
        secret_key: Alias for secret (deprecated, use 'secret')
        password: Password for encrypted keys
        serializer: JSON encoder/decoder
        **kwargs: Additional params (e.g., custom_module, list configuration)
    
    Returns:
        JWT instance or custom module
    """
    from jam.jwt import create_instance as sync_create_instance
    
    # Handle backward compatibility: secret_key -> secret
    if secret is None and secret_key is not None:
        secret = secret_key
    elif secret is None:
        raise ValueError("Either 'secret' or 'secret_key' must be provided")
    
    # Use sync create_instance - JWT encoding/decoding is synchronous
    # Lists will be handled at the instance level if needed
    return sync_create_instance(
        alg=alg,
        secret=secret,
        password=password,
        serializer=serializer,
        **kwargs
    )


__all__ = ["create_instance"]

# -*- coding: utf-8 -*-

import pytest

from jam.utils import generate_rsa_key_pair


@pytest.fixture(scope="module")
def saml_configs() -> tuple[dict, dict]:
    """Return matching IdP and SP facade configurations."""
    keys = generate_rsa_key_pair()
    idp = {
        "saml": {
            "role": "idp",
            "private_key": keys["private"],
            "entity_id": "https://idp.test",
            "audience": "https://sp.test",
        }
    }
    sp = {
        "saml": {
            "role": "sp",
            "entity_id": "https://sp.test",
            "expected_issuer": "https://idp.test",
            "idp_public_key": keys["public"],
        }
    }
    return idp, sp

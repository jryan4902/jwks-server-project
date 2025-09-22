'''
Jake Gonzales
Sep 21st
Assisted with copilot
file to run tests against the app
'''

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from fastapi.testclient import TestClient

from app.keystore import keystore
from app.main import ALGORITHM, app

client = TestClient(app)


def _jwk_to_public_key(jwk: Dict[str, str]) -> rsa.RSAPublicKey:
    # Convert base64url 'n' and 'e' to integers
    import base64

    def b64url_to_int(s: str) -> int:
        pad = "=" * (-len(s) % 4)
        return int.from_bytes(base64.urlsafe_b64decode(s + pad), "big")

    n = b64url_to_int(jwk["n"])
    e = b64url_to_int(jwk["e"])
    return RSAPublicNumbers(e=e, n=n).public_key()


def test_jwks_returns_only_unexpired_keys():
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    data = resp.json()
    assert "keys" in data
    keys = data["keys"]
    assert isinstance(keys, list)
    # There should be no expired keys in JWKS
    active_kids = {k.kid for k in keystore.get_active_keys()}
    expired_kids = {k.kid for k in keystore.get_expired_keys()}
    returned_kids = {k["kid"] for k in keys}
    assert returned_kids.issubset(active_kids)
    assert returned_kids.isdisjoint(expired_kids)


def test_auth_returns_valid_jwt_with_active_key_in_header_and_verifies_with_jwks():
    # Request a token without 'expired' parameter -> active key
    resp = client.post("/auth")
    assert resp.status_code == 200
    token = resp.json()["token"]

    # Header must contain 'kid'
    header = jwt.get_unverified_header(token)
    assert "kid" in header
    kid = header["kid"]

    # JWKS must contain that kid
    jwks = client.get("/.well-known/jwks.json").json()["keys"]
    match = [j for j in jwks if j["kid"] == kid]
    assert len(match) == 1

    # Verify signature using the JWKS public key
    pubkey = _jwk_to_public_key(match[0])
    # PyJWT can accept cryptography key objects directly
    decoded = jwt.decode(token, key=pubkey, algorithms=[ALGORITHM])
    assert decoded["sub"] == "demo-user"
    # Ensure token is not expired relative to now
    assert decoded["exp"] > int(datetime.now(timezone.utc).timestamp())


def test_auth_with_expired_param_uses_expired_key_and_expired_exp():
    # Request a token with 'expired' parameter present
    resp = client.post("/auth?expired")
    assert resp.status_code == 200
    token = resp.json()["token"]

    header = jwt.get_unverified_header(token)
    assert "kid" in header
    kid = header["kid"]

    # This kid must not appear in JWKS (since it's expired)
    jwks = client.get("/.well-known/jwks.json").json()["keys"]
    assert kid not in {j["kid"] for j in jwks}

    # Retrieve expired key directly from keystore and build public key
    expired_key = keystore.get_by_kid(kid)
    assert expired_key is not None
    assert expired_key.expires_at <= datetime.now(timezone.utc)

    # Validate signature while ignoring expiration
    decoded_noexp = jwt.decode(
        token,
        key=expired_key.public_key,
        algorithms=[ALGORITHM],
        options={"verify_exp": False},
    )
    assert decoded_noexp["sub"] == "demo-user"

    # With expiration verification enabled, it must raise
    from jwt import ExpiredSignatureError, InvalidTokenError

    error = None
    try:
        jwt.decode(token, key=expired_key.public_key, algorithms=[ALGORITHM])
    except ExpiredSignatureError as e:
        error = e
    except InvalidTokenError as e:  
        error = e
    assert error is not None


def test_jwks_structure_fields_present():
    resp = client.get("/.well-known/jwks.json")
    assert resp.status_code == 200
    data = resp.json()
    assert "keys" in data
    for jwk in data["keys"]:
        for field in ("kty", "kid", "use", "alg", "n", "e"):
            assert field in jwk
        assert jwk["kty"] == "RSA"
        assert jwk["use"] == "sig"
        assert jwk["alg"] == ALGORITHM

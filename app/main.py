"""
Jake Gonzales 
Sep 19
Assisted with copilot

"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import jwt
from fastapi import FastAPI, Query, Request
from fastapi.responses import JSONResponse

from .keystore import KeyPair, keystore
from .util import public_key_to_jwk

ALGORITHM = "RS256"

app = FastAPI(title="JWKS Server", version="1.0.0")


@app.get("/.well-known/jwks.json")
def jwks() -> Dict[str, List[Dict[str, str]]]:
    """
    GET:/.well-known/jwks.json
    Reads all valid (non-expired) private keys from the DB.
    Creates a JWKS response from those private keys.
    """
    keys = keystore.get_active_keys()
    jwks_keys = [public_key_to_jwk(k.public_key, k.kid, alg=ALGORITHM) for k in keys]
    return {"keys": jwks_keys}


@app.post("/auth")
async def auth(request: Request, expired: Optional[str] = Query(default=None)) -> JSONResponse:
    """
    POST:/auth
    Reads a private key from the DB.
    If the "expired" query parameter is not present, read a valid (unexpired) key.
    If the "expired" query parameter is present, read an expired key.
    Sign a JWT with that private key and return the JWT.

    Accepts:
    - Empty POST (for backward compatibility)
    - JSON payload: {"username": "userABC", "password": "password123"}
    - HTTP Basic Auth

    NOTE: This is mock authentication - no actual validation occurs.
    """
    # Try to read JSON body if present (ignore if empty or invalid)
    try:
        body = await request.json()
        username = body.get("username", "demo-user")
    except Exception:
        username = "demo-user"

    # If the 'expired' query parameter is present, use an expired key
    use_expired = expired is not None

    keypair: KeyPair = (
        keystore.get_latest_expired_key() if use_expired else keystore.get_latest_active_key()
    )

    now = datetime.now(timezone.utc)
    exp = keypair.expires_at

    # Minimal demo payload
    payload: Dict[str, Any] = {
        "sub": username,  # Use username from request or default
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }

    # Serialize the private key for PyJWT
    private_pem = keypair.private_pem()

    token = jwt.encode(
        payload,
        private_pem,
        algorithm=ALGORITHM,
        headers={"kid": keypair.kid},
    )

    return JSONResponse(content={"token": token})

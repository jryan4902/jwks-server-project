'''
Jake Gonzales 
Sep 19
Assisted with copilot

'''

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import jwt
from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse

from .keystore import KeyPair, keystore
from .util import public_key_to_jwk

ALGORITHM = "RS256"

app = FastAPI(title="JWKS Server", version="1.0.0")


@app.get("/.well-known/jwks.json")
def jwks() -> Dict[str, List[Dict[str, str]]]:
    keys = keystore.get_active_keys()
    jwks_keys = [
        public_key_to_jwk(k.public_key, k.kid, alg=ALGORITHM) for k in keys
    ]
    return {"keys": jwks_keys}


@app.post("/auth")
def auth(expired: Optional[str] = Query(default=None)) -> JSONResponse:
    # If the 'expired' query parameter is present (regardless of its value), issue a token
    # signed with an expired key and with an expired 'exp' claim.
    use_expired = expired is not None

    keypair: KeyPair = (
        keystore.get_latest_expired_key()
        if use_expired
        else keystore.get_latest_active_key()
    )

    now = datetime.now(timezone.utc)
    exp = keypair.expires_at  # Tokens expire at the same time as their signing key.

    # Minimal demo payload. In real apps, include claims relevant to your auth.
    payload: Dict[str, Any] = {
        "sub": "demo-user",
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }

    headers = {"kid": keypair.kid, "alg": ALGORITHM}

    try:
        token = jwt.encode(
            payload, keypair.private_pem(), algorithm=ALGORITHM, headers=headers
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Token generation failed: {e}")

    return JSONResponse({"token": token})

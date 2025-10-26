"""
Jake Gonzales 
Sep 19
Assisted with copilot

"""

from __future__ import annotations

import base64
from typing import Dict

from cryptography.hazmat.primitives.asymmetric import rsa


def _int_to_base64url(n: int) -> str:
    # Convert integer to big-endian bytes then to base64url (no padding)
    byte_length = (n.bit_length() + 7) // 8
    data = n.to_bytes(byte_length, "big")
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def public_key_to_jwk(public_key: rsa.RSAPublicKey, kid: str, alg: str = "RS256") -> Dict[str, str]:
    numbers = public_key.public_numbers()
    n = _int_to_base64url(numbers.n)
    e = _int_to_base64url(numbers.e)
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": alg,
        "n": n,
        "e": e,
    }

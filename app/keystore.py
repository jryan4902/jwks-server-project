from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@dataclass(frozen=True)
class KeyPair:
    kid: str
    private_key: rsa.RSAPrivateKey
    expires_at: datetime  # timezone-aware, UTC

    @property
    def public_key(self) -> rsa.RSAPublicKey:
        return self.private_key.public_key()

    def private_pem(self) -> bytes:
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )


class KeyStore:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._keys: List[KeyPair] = []
        self._ensure_bootstrap_keys()

    def _ensure_bootstrap_keys(self) -> None:
        # Create one expired and one active key for demo/testing purposes.
        now = datetime.now(timezone.utc)

        expired_key = self._generate_keypair(expires_at=now - timedelta(hours=1))
        active_key = self._generate_keypair(expires_at=now + timedelta(hours=2))

        with self._lock:
            self._keys = [expired_key, active_key]

    def _generate_keypair(self, *, expires_at: datetime) -> KeyPair:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        kid = str(uuid.uuid4())
        return KeyPair(kid=kid, private_key=private_key, expires_at=expires_at)

    def get_active_keys(self, *, at: Optional[datetime] = None) -> List[KeyPair]:
        ts = at or datetime.now(timezone.utc)
        with self._lock:
            return [k for k in self._keys if k.expires_at > ts]

    def get_expired_keys(self, *, at: Optional[datetime] = None) -> List[KeyPair]:
        ts = at or datetime.now(timezone.utc)
        with self._lock:
            return [k for k in self._keys if k.expires_at <= ts]

    def get_latest_active_key(self) -> KeyPair:
        active = self.get_active_keys()
        if not active:
            # If no active keys exist, create a new one valid for 2 hours.
            new_key = self._generate_keypair(
                expires_at=datetime.now(timezone.utc) + timedelta(hours=2)
            )
            with self._lock:
                self._keys.append(new_key)
            return new_key
        return max(active, key=lambda k: k.expires_at)

    def get_latest_expired_key(self) -> KeyPair:
        expired = self.get_expired_keys()
        if not expired:
            # If no expired keys exist, create one that expired 1 hour ago.
            new_expired = self._generate_keypair(
                expires_at=datetime.now(timezone.utc) - timedelta(hours=1)
            )
            with self._lock:
                self._keys.append(new_expired)
            return new_expired
        return max(expired, key=lambda k: k.expires_at)

    def get_by_kid(self, kid: str) -> Optional[KeyPair]:
        with self._lock:
            for k in self._keys:
                if k.kid == kid:
                    return k
        return None


# Singleton keystore for app usage
keystore = KeyStore()

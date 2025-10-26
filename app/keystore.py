'''
Jake Gonzales 
Sep 19
Assisted with copilot

'''

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from . import database


@dataclass(frozen=True)
class KeyPair:
    kid: str  # String representation of the database row ID
    private_key: rsa.RSAPrivateKey
    expires_at: datetime  # timezone-aware, UTC

    @property
    def public_key(self) -> rsa.RSAPublicKey:
        return self.private_key.public_key()

    def private_pem(self) -> bytes:
        """Serialize private key to PEM format for storage."""
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )


class KeyStore:
    def __init__(self) -> None:
        # Initialize database
        database.init_db()
        self._ensure_bootstrap_keys()

    def _ensure_bootstrap_keys(self) -> None:
        """Create one expired and one active key for demo/testing purposes."""
        now = datetime.now(timezone.utc)

        # Check if we already have keys in the database
        valid_keys = database.get_valid_keys(int(now.timestamp()))
        expired_keys = database.get_expired_keys(int(now.timestamp()))

        # Generate expired key if none exists
        if not expired_keys:
            self._generate_and_save_keypair(
                expires_at=now - timedelta(hours=1)
            )

        # Generate active key if none exists
        if not valid_keys:
            self._generate_and_save_keypair(
                expires_at=now + timedelta(hours=2)
            )

    def _generate_and_save_keypair(self, *, expires_at: datetime) -> KeyPair:
        """Generate a new keypair and save it to the database."""
        # Generate RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Serialize to PEM format
        key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        
        # Save to database and get the kid
        kid = database.save_key(key_pem, int(expires_at.timestamp()))
        
        return KeyPair(
            kid=str(kid),
            private_key=private_key,
            expires_at=expires_at
        )

    def _load_keypair_from_db(
        self, kid: int, key_pem: bytes, exp: int
    ) -> KeyPair:
        """Deserialize a keypair from database storage."""
        private_key = serialization.load_pem_private_key(
            key_pem,
            password=None
        )
        return KeyPair(
            kid=str(kid),
            private_key=private_key,
            expires_at=datetime.fromtimestamp(exp, tz=timezone.utc)
        )

    def get_active_keys(self, *, at: Optional[datetime] = None) -> List[KeyPair]:
        """Get all non-expired keys from the database."""
        ts = at or datetime.now(timezone.utc)
        rows = database.get_valid_keys(int(ts.timestamp()))
        return [self._load_keypair_from_db(kid, key, exp) for kid, key, exp in rows]

    def get_expired_keys(self, *, at: Optional[datetime] = None) -> List[KeyPair]:
        """Get all expired keys from the database."""
        ts = at or datetime.now(timezone.utc)
        rows = database.get_expired_keys(int(ts.timestamp()))
        return [self._load_keypair_from_db(kid, key, exp) for kid, key, exp in rows]

    def get_latest_active_key(self) -> KeyPair:
        """Get the latest active (non-expired) key."""
        active = self.get_active_keys()
        if not active:
            # If no active keys exist, create a new one valid for 2 hours
            return self._generate_and_save_keypair(
                expires_at=datetime.now(timezone.utc) + timedelta(hours=2)
            )
        return max(active, key=lambda k: k.expires_at)

    def get_latest_expired_key(self) -> KeyPair:
        """Get the latest expired key."""
        expired = self.get_expired_keys()
        if not expired:
            # If no expired keys exist, create one that expired 1 hour ago
            return self._generate_and_save_keypair(
                expires_at=datetime.now(timezone.utc) - timedelta(hours=1)
            )
        return max(expired, key=lambda k: k.expires_at)

    def get_by_kid(self, kid: str) -> Optional[KeyPair]:
        """Get a specific key by its kid."""
        try:
            kid_int = int(kid)
        except ValueError:
            return None
        
        row = database.get_key_by_kid(kid_int)
        if row is None:
            return None
        
        return self._load_keypair_from_db(row[0], row[1], row[2])


# Singleton keystore for app usage
keystore = KeyStore()
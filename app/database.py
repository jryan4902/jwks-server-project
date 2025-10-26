"""
Jake Gonzales
Oct 26th
Assisted with copilot
file to execute databse
"""

import sqlite3
from pathlib import Path
from typing import List, Optional, Tuple

DB_PATH = Path(__file__).parent.parent / "totally_not_my_privateKeys.db"


def init_db() -> None:
    """Initialize the database and create the keys table if it doesn't exist."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS keys(
            kid INTEGER PRIMARY KEY AUTOINCREMENT,
            key BLOB NOT NULL,
            exp INTEGER NOT NULL
        )
    """
    )
    conn.commit()
    conn.close()


def save_key(key_pem: bytes, exp: int) -> int:
    """Save a private key to the database using parameterized query.

    Args:
        key_pem: Private key in PEM format
        exp: Expiration timestamp (Unix timestamp)

    Returns:
        kid: The auto-generated key ID
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO keys (key, exp) VALUES (?, ?)", (key_pem, exp))
    kid = cursor.lastrowid
    conn.commit()
    conn.close()
    return kid


def get_key_by_kid(kid: int) -> Optional[Tuple[int, bytes, int]]:
    """Retrieve a key by its kid using parameterized query.

    Returns:
        Tuple of (kid, key_pem, exp) or None if not found
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT kid, key, exp FROM keys WHERE kid = ?", (kid,))
    row = cursor.fetchone()
    conn.close()
    return row


def get_valid_keys(current_time: int) -> List[Tuple[int, bytes, int]]:
    """Get all non-expired keys using parameterized query.

    Args:
        current_time: Current Unix timestamp

    Returns:
        List of tuples (kid, key_pem, exp)
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ?", (current_time,))
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_expired_keys(current_time: int) -> List[Tuple[int, bytes, int]]:
    """Get all expired keys using parameterized query.

    Args:
        current_time: Current Unix timestamp

    Returns:
        List of tuples (kid, key_pem, exp)
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT kid, key, exp FROM keys WHERE exp <= ?", (current_time,))
    rows = cursor.fetchall()
    conn.close()
    return rows

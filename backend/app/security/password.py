"""
CIPHER AI - Password Security & Argon2id Hashing Engine
OWASP-compliant Argon2id password hashing, strength validation, and timing-safe verification.
"""

import re
from typing import Optional, Tuple
from argon2 import PasswordHasher, Type
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError

# Recommended OWASP parameters for Argon2id:
# Memory: 19 MiB (19456 KiB), Iterations: 2, Parallelism: 1
hasher = PasswordHasher(
    time_cost=2,
    memory_cost=19456,
    parallelism=1,
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)

# Pre-computed dummy hash to prevent timing attacks on nonexistent accounts
_DUMMY_HASH = hasher.hash("CipherSecOpsDummyPasswordForTimingMitigation2026!")


def hash_password(password: str) -> str:
    """
    Hashes a plaintext password using Argon2id with unique cryptographic salt.
    Plaintext password is never persisted or logged.
    """
    return hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifies candidate plaintext password against an Argon2id hash.
    Returns True if valid, False otherwise without raising exceptions.
    """
    try:
        return hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except Exception:
        return False


def verify_dummy_password(candidate: str = "wrong_password") -> None:
    """
    Executes constant-time Argon2 verification against a dummy hash.
    Invoked when a requested account does not exist, eliminating timing discrepancies
    that attackers could use for account enumeration.
    """
    try:
        hasher.verify(_DUMMY_HASH, candidate)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        pass
    except Exception:  # nosec B110 - intentional constant-time dummy verification for timing attack mitigation
        pass


def validate_password_policy(password: str) -> Tuple[bool, Optional[str]]:
    """
    Validates password against enterprise cybersecurity standards:
    - Minimum 8 characters
    - At least one uppercase letter [A-Z]
    - At least one lowercase letter [a-z]
    - At least one decimal digit [0-9]
    - At least one special symbol
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if len(password) > 128:
        return False, "Password cannot exceed 128 characters."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one numerical digit."
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{}|;:,.<>?/~`]", password):
        return False, "Password must contain at least one special symbol."
    return True, None

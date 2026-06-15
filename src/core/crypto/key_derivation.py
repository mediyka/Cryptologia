"""Key derivation and password verification utilities.

Primary mode follows Sprint 2: Argon2id for authentication hashes and
PBKDF2-HMAC-SHA256 for vault encryption keys.  A PBKDF2 authentication
fallback is provided so the Windows project can still start when the optional
argon2-cffi wheel is unavailable for a very new Python version.
"""

import base64
import hashlib
import logging
import os
from typing import Optional

try:  # Preferred Sprint 2 implementation: argon2-cffi
    from argon2 import PasswordHasher, Type  # type: ignore
    from argon2.exceptions import VerifyMismatchError  # type: ignore
    ARGON2_AVAILABLE = True
except Exception:  # pragma: no cover - depends on local environment
    PasswordHasher = None  # type: ignore
    Type = None  # type: ignore

    class VerifyMismatchError(Exception):
        pass

    ARGON2_AVAILABLE = False

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from core.security.memory_guard import SecureMemory
from core.security.side_channel_protection import SideChannelProtection

logger = logging.getLogger("KeyDerivation")


class KeyDerivationService:
    """Derives authentication hashes and AES-256 encryption keys."""

    MAX_TIME_COST = 10
    MAX_MEMORY_COST = 262144  # 256 MB
    MAX_PARALLELISM = 8
    MAX_PBKDF2_ITERATIONS = 500000
    FALLBACK_PREFIX = "pbkdf2-auth"

    def __init__(self, config: Optional[dict] = None):
        cfg = config or {}
        self.side_channel = SideChannelProtection(cfg)

        time_cost = self._validate_param(cfg.get("argon2_time", 3), 1, self.MAX_TIME_COST, "time_cost")
        memory_cost = self._validate_param(cfg.get("argon2_memory", 65536), 1024, self.MAX_MEMORY_COST, "memory_cost")
        parallelism = self._validate_param(cfg.get("argon2_parallelism", 4), 1, self.MAX_PARALLELISM, "parallelism")
        self.pbkdf2_iterations = self._validate_param(
            cfg.get("pbkdf2_iterations", 100000),
            10000,
            self.MAX_PBKDF2_ITERATIONS,
            "pbkdf2_iterations",
        )

        self.argon2_available = ARGON2_AVAILABLE
        self.argon2_hasher = None
        if ARGON2_AVAILABLE:
            self.argon2_hasher = PasswordHasher(
                time_cost=time_cost,
                memory_cost=memory_cost,
                parallelism=parallelism,
                hash_len=32,
                salt_len=16,
                type=Type.ID,
            )
        else:
            logger.warning(
                "argon2-cffi is not installed. Falling back to PBKDF2 for "
                "authentication hashes. Install argon2-cffi for full Sprint 2 compliance."
            )

    def _validate_param(self, value, min_val, max_val, name):
        if not isinstance(value, int):
            logger.warning("Invalid type for %s, using minimum value.", name)
            return min_val
        if value < min_val:
            logger.warning("%s too low (%s), clamping to %s", name, value, min_val)
            return min_val
        if value > max_val:
            logger.warning("%s too high (%s), clamping to %s", name, value, max_val)
            return max_val
        return value

    def generate_salt(self) -> bytes:
        """Generate a 16-byte salt."""
        return os.urandom(16)

    def create_auth_hash(self, password: str) -> str:
        """Create a password verification hash.

        Uses Argon2id when argon2-cffi is available.  Otherwise uses a marked
        PBKDF2-HMAC-SHA256 fallback so the application can still run on systems
        where the Argon2 wheel cannot be installed.
        """
        if self.argon2_hasher is not None:
            return self.argon2_hasher.hash(password)
        return self._create_pbkdf2_auth_hash(password)

    def verify_password(self, password: str, stored_hash: str) -> bool:
        """Verify a password against either Argon2id or fallback PBKDF2 hash."""
        try:
            if stored_hash.startswith(self.FALLBACK_PREFIX + "$"):
                verified = self._verify_pbkdf2_auth_hash(password, stored_hash)
                self.side_channel.compare(b"verified", b"verified" if verified else b"mismatch")
                return verified

            if self.argon2_hasher is None:
                logger.error("Stored password hash is Argon2, but argon2-cffi is not installed.")
                self.side_channel.compare(b"verified", b"error")
                return False

            verified = self.argon2_hasher.verify(stored_hash, password)
            return self.side_channel.compare(b"verified", b"verified") and bool(verified)
        except VerifyMismatchError:
            self.side_channel.compare(b"verified", b"mismatch")
            return False
        except Exception as e:
            logger.error("Verification error: %s", e)
            self.side_channel.compare(b"verified", b"error")
            return False

    def derive_encryption_key(self, password: str, salt: bytes) -> bytes:
        """Derive the 32-byte AES-256 vault key via PBKDF2-HMAC-SHA256."""
        self.side_channel.apply_crypto_jitter()
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.pbkdf2_iterations,
            backend=default_backend(),
        )
        password_bytes = password.encode("utf-8")
        try:
            return kdf.derive(password_bytes)
        finally:
            SecureMemory.wipe_immutable_bytes(password_bytes)

    def _create_pbkdf2_auth_hash(self, password: str) -> str:
        salt = os.urandom(16)
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            self.pbkdf2_iterations,
            dklen=32,
        )
        return "$".join(
            [
                self.FALLBACK_PREFIX,
                "v1",
                str(self.pbkdf2_iterations),
                base64.b64encode(salt).decode("ascii"),
                base64.b64encode(digest).decode("ascii"),
            ]
        )

    def _verify_pbkdf2_auth_hash(self, password: str, stored_hash: str) -> bool:
        try:
            prefix, version, iterations, salt_b64, digest_b64 = stored_hash.split("$", 4)
            if prefix != self.FALLBACK_PREFIX or version != "v1":
                return False
            salt = base64.b64decode(salt_b64)
            expected = base64.b64decode(digest_b64)
            actual = hashlib.pbkdf2_hmac(
                "sha256",
                password.encode("utf-8"),
                salt,
                int(iterations),
                dklen=len(expected),
            )
            return self.side_channel.compare(actual, expected)
        except Exception as e:
            logger.error("PBKDF2 auth hash verification error: %s", e)
            return False

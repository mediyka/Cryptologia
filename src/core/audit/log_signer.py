import hmac
import hashlib
import logging
from typing import Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519
except Exception:
    InvalidSignature = None
    serialization = None
    ed25519 = None

from core.crypto.key_storage import SecureMemoryCache

logger = logging.getLogger("AuditLogSigner")

AUDIT_SIGNING_CONTEXT = "audit-signing"


class AuditLogSigner:

    """Описывает публичный класс AuditLogSigner."""
    def __init__(self, key_manager=None, signing_key: Optional[bytes] = None):
        self.key_manager = key_manager
        self.algorithm = "HMAC-SHA256"
        self._seed_cache = SecureMemoryCache()
        self._private_key = None
        self._public_key_hex = ""

        seed = signing_key or self._derive_seed()
        self._seed_cache.store_key(seed)
        self._initialize_ed25519(seed)

    def _derive_seed(self) -> bytes:
        if self.key_manager and hasattr(self.key_manager, "derive_audit_signing_key"):
            return self.key_manager.derive_audit_signing_key(32)

        if self.key_manager and hasattr(self.key_manager, "derive_key"):
            return self.key_manager.derive_key(AUDIT_SIGNING_CONTEXT, 32)

        if self.key_manager and getattr(self.key_manager, "storage", None):
            base_key = self.key_manager.storage.get_key()
            if base_key:
                hkdf = HKDF(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=b"cryptosafe-manager:v1",
                    info=AUDIT_SIGNING_CONTEXT.encode("utf-8"),
                )
                return hkdf.derive(base_key)

        logger.warning("Using process-local fallback audit signing key")
        from secrets import token_bytes

        return token_bytes(32)

    def _initialize_ed25519(self, seed: bytes):
        if ed25519 is None or serialization is None:
            logger.warning("Ed25519 primitives unavailable, using HMAC-SHA256 audit signatures")
            self._private_key = None
            self._public_key_hex = ""
            self.algorithm = "HMAC-SHA256"
            return

        try:
            self._private_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed[:32])
            public_key = self._private_key.public_key()
            self._public_key_hex = public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            ).hex()
            self.algorithm = "Ed25519"
        except Exception as exc:
            logger.warning("Ed25519 unavailable, falling back to HMAC-SHA256: %s", exc)
            self._private_key = None
            self._public_key_hex = ""
            self.algorithm = "HMAC-SHA256"

    def sign(self, data: bytes) -> bytes:
        """Описывает публичное действие sign."""
        if self._private_key is not None:
            signature = self._private_key.sign(data)
            self._ratchet_key(signature)
            return signature

        key = self._seed_cache.get_key()
        signature = hmac.digest(key, data, "sha256")
        self._ratchet_key(signature)
        return signature

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Описывает публичное действие verify."""
        if self._private_key is not None:
            try:
                self._private_key.public_key().verify(signature, data)
                return True
            except Exception as exc:
                if InvalidSignature is None or isinstance(exc, InvalidSignature):
                    return False
                raise

        key = self._seed_cache.get_key()
        expected = hmac.digest(key, data, "sha256")
        return hmac.compare_digest(expected, signature)

    def get_public_key_hex(self) -> str:
        """Возвращает данные для public key hex."""
        return self._public_key_hex

    def verify_with_public_key(self, data: bytes, signature: bytes, public_key_hex: str) -> bool:
        """Проверяет with public key."""
        if public_key_hex and ed25519 is not None:
            try:
                public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
                public_key.verify(signature, data)
                return True
            except Exception as exc:
                if InvalidSignature is None or isinstance(exc, InvalidSignature):
                    return False
                return False
        return self.verify(data, signature)

    def _ratchet_key(self, signature: bytes):
        seed = self._seed_cache.get_key()
        if not seed:
            return
        next_seed = hashlib.sha256(seed + signature + b":audit-forward-security").digest()
        self._seed_cache.store_key(next_seed)
        self._initialize_ed25519(next_seed)

    def clear(self):
        """Описывает публичное действие clear."""
        self._seed_cache.clear_key()
        self._private_key = None

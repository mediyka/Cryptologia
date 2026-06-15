import logging

from core.security.memory_guard import SecureMemory

logger = logging.getLogger("KeyStorage")


class SecureMemoryCache:
    """
    Secure in-memory key cache backed by the Sprint 7 memory guard.

    The cache stores keys in a tracked locked allocation when the platform
    allows it, and wipes the backing allocation before releasing it.
    """

    def __init__(self, config: dict = None):
        self._key = None
        self._locked = False
        self._memory = SecureMemory(config)

    def store_key(self, key: bytes):
        """Описывает публичное действие store key."""
        if self._key:
            self.clear_key()
        if not isinstance(key, (bytes, bytearray, memoryview)):
            raise TypeError("Key must be bytes-like.")
        key_bytes = bytearray(key)
        self._key = self._memory.allocate_secure(len(key_bytes))
        self._key[:] = key_bytes
        allocation = self._memory.get_allocation(self._key)
        self._locked = bool(allocation and allocation.locked)
        self._memory.secure_zero(key_bytes)

    def get_key(self) -> bytes:
        """Возвращает данные для key."""
        if self._key:
            return bytes(self._key)
        return None

    def clear_key(self):
        """Очищает key."""
        if self._key:
            self._memory.free_secure(self._key)
            self._key = None
            self._locked = False
            logger.info("Encryption key cleared from memory.")

    def _secure_zero_memory(self, buffer: bytearray):
        if buffer:
            self._memory.secure_zero(buffer)

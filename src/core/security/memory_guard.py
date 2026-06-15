import ctypes
import logging
import secrets
import sys
import threading
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("MemoryGuard")

CANARY_SIZE = 16
DEFAULT_GUARD_SIZE = 16


@dataclass
class SecureAllocation:
    """Описывает публичный класс SecureAllocation."""
    buffer: bytearray
    size: int
    locked: bool
    canary_before: bytes
    canary_after: bytes
    guard_size: int
    label: str = "sensitive"


class SecureMemory:
    """Небольшой кроссплатформенный помощник безопасной памяти с отказоустойчивой очисткой."""

    def __init__(self, config: Optional[dict] = None):
        self.config = config or {}
        self.enabled = bool(self.config.get("memory_protection_enabled", True))
        self.lock_memory_enabled = bool(self.config.get("memory_lock_enabled", True))
        self.multi_pass_wipe_count = max(1, int(self.config.get("memory_wipe_passes", 1) or 1))
        self.guard_pages_enabled = bool(self.config.get("memory_guard_pages_enabled", True))
        self.canary_enabled = bool(self.config.get("memory_canary_enabled", True))
        self._allocations: dict[int, SecureAllocation] = {}
        self._lock = threading.RLock()

    def allocate_secure(self, size: int) -> bytearray:
        """Описывает публичное действие allocate secure."""
        if size < 0:
            raise ValueError("Secure allocation size must be non-negative")
        guard_size = DEFAULT_GUARD_SIZE if self.guard_pages_enabled else 0
        canary_before = secrets.token_bytes(CANARY_SIZE) if self.canary_enabled else b""
        canary_after = secrets.token_bytes(CANARY_SIZE) if self.canary_enabled else b""

        # Python не позволяет выставить настоящие защитные страницы для bytearray,
        # но буферы с отступами разводят чувствительные значения в памяти
        # и позволяют canary-меткам находить явную порчу вокруг рабочей области.
        buffer = bytearray(guard_size + CANARY_SIZE + size + CANARY_SIZE + guard_size)
        before_start = guard_size
        data_start = before_start + CANARY_SIZE
        after_start = data_start + size
        if self.canary_enabled:
            buffer[before_start:data_start] = canary_before
            buffer[after_start:after_start + CANARY_SIZE] = canary_after

        view = SecureByteArray(buffer, data_start, size, self)
        if self.enabled and self.lock_memory_enabled:
            view._locked = self.lock_buffer(buffer)
        allocation = SecureAllocation(
            buffer=buffer,
            size=size,
            locked=view._locked,
            canary_before=canary_before,
            canary_after=canary_after,
            guard_size=guard_size,
        )
        with self._lock:
            self._allocations[id(view)] = allocation
        return view

    def secure_zero(self, buffer, passes: int = 1) -> bool:
        """Описывает публичное действие secure zero."""
        if buffer is None:
            return False
        passes = max(self.multi_pass_wipe_count, int(passes or 1))
        try:
            size = len(buffer)
        except TypeError:
            return False
        if size == 0:
            return True

        if isinstance(buffer, SecureByteArray):
            for _ in range(passes):
                for index in range(buffer._size):
                    buffer._backing[buffer._offset + index] = 0
            return True

        wiped = False
        for _ in range(passes):
            try:
                ptr = (ctypes.c_char * size).from_buffer(buffer)
                ctypes.memset(ptr, 0, size)
                wiped = True
            except Exception:
                try:
                    for index in range(size):
                        buffer[index] = 0
                    wiped = True
                except Exception as exc:
                    logger.debug("Secure wipe failed: %s", exc)
                    return False
        return wiped

    def free_secure(self, buffer) -> bool:
        """Описывает публичное действие free secure."""
        if buffer is None:
            return False

        allocation = self.get_allocation(buffer)
        target = allocation.buffer if allocation else buffer
        ok = self.verify_canary(buffer)
        self.unlock_buffer(target)
        wiped = self.secure_zero(target)
        with self._lock:
            self._allocations.pop(id(buffer), None)
        return bool(ok and wiped)

    def wipe_all(self) -> int:
        """Описывает публичное действие wipe all."""
        with self._lock:
            allocations = list(self._allocations.items())
        count = 0
        for allocation_id, allocation in allocations:
            self.unlock_buffer(allocation.buffer)
            if self.secure_zero(allocation.buffer):
                count += 1
            with self._lock:
                self._allocations.pop(allocation_id, None)
        return count

    def get_allocation(self, buffer) -> Optional[SecureAllocation]:
        """Возвращает данные для allocation."""
        with self._lock:
            return self._allocations.get(id(buffer))

    def verify_canary(self, buffer) -> bool:
        """Проверяет canary."""
        allocation = self.get_allocation(buffer)
        if not allocation or not self.canary_enabled:
            return True
        if not isinstance(buffer, SecureByteArray):
            return True
        before_start = allocation.guard_size
        data_start = before_start + CANARY_SIZE
        after_start = data_start + allocation.size
        before = allocation.buffer[before_start:data_start]
        after = allocation.buffer[after_start:after_start + CANARY_SIZE]
        intact = bytes(before) == allocation.canary_before and bytes(after) == allocation.canary_after
        if not intact:
            logger.error("Secure memory canary mismatch for %s", allocation.label)
            try:
                from core.events import event_bus

                event_bus.publish("SecureMemoryCanaryMismatch", {"label": allocation.label, "size": allocation.size})
            except Exception:
                pass
        return intact

    def lock_buffer(self, buffer) -> bool:
        """Описывает публичное действие lock buffer."""
        if not self.enabled or not self.lock_memory_enabled or not buffer:
            return False
        address = self._buffer_address(buffer)
        if address is None:
            return False
        return self.lock_address(address, len(buffer))

    def unlock_buffer(self, buffer) -> bool:
        """Описывает публичное действие unlock buffer."""
        if not buffer:
            return False
        address = self._buffer_address(buffer)
        if address is None:
            return False
        return self.unlock_address(address, len(buffer))

    def lock_address(self, address: int, size: int) -> bool:
        """Описывает публичное действие lock address."""
        try:
            if sys.platform == "win32":
                return bool(ctypes.windll.kernel32.VirtualLock(ctypes.c_void_p(address), ctypes.c_size_t(size)))
            libc = ctypes.CDLL("libc.so.6" if sys.platform.startswith("linux") else None)
            return libc.mlock(ctypes.c_void_p(address), ctypes.c_size_t(size)) == 0
        except Exception as exc:
            logger.debug("Memory lock unavailable: %s", exc)
            return False

    def unlock_address(self, address: int, size: int) -> bool:
        """Описывает публичное действие unlock address."""
        try:
            if sys.platform == "win32":
                return bool(ctypes.windll.kernel32.VirtualUnlock(ctypes.c_void_p(address), ctypes.c_size_t(size)))
            libc = ctypes.CDLL("libc.so.6" if sys.platform.startswith("linux") else None)
            return libc.munlock(ctypes.c_void_p(address), ctypes.c_size_t(size)) == 0
        except Exception as exc:
            logger.debug("Memory unlock failed: %s", exc)
            return False

    @staticmethod
    def _buffer_address(buffer) -> Optional[int]:
        try:
            return ctypes.addressof((ctypes.c_char * len(buffer)).from_buffer(buffer))
        except Exception:
            return None

    @staticmethod
    def wipe_immutable_bytes(value: bytes) -> bool:
        """Описывает публичное действие wipe immutable bytes."""
        if not isinstance(value, bytes):
            return False
        try:
            data_offset = sys.getsizeof(b"") - 1
            ctypes.memset(id(value) + data_offset, 0, len(value))
            return True
        except Exception as exc:
            logger.debug("Immutable bytes wipe failed: %s", exc)
            return False

    @staticmethod
    def wipe_compact_ascii_string(value: str) -> bool:
        """Описывает публичное действие wipe compact ascii string."""
        if not isinstance(value, str) or not value.isascii():
            return False
        try:
            data_offset = sys.getsizeof("") - 1
            ctypes.memset(id(value) + data_offset, 0, len(value))
            return True
        except Exception as exc:
            logger.debug("Immutable string wipe failed: %s", exc)
            return False


class SecureByteArray(bytearray):
    """Рабочий bytearray-срез, связанный с заблокированным буфером с отступами."""

    def __new__(cls, backing: bytearray, offset: int, size: int, memory: SecureMemory):
        obj = super().__new__(cls, size)
        return obj

    def __init__(self, backing: bytearray, offset: int, size: int, memory: SecureMemory):
        self._backing = backing
        self._offset = offset
        self._size = size
        self._memory = memory
        self._locked = False

    def __len__(self):
        return self._size

    def __getitem__(self, key):
        return self._backing[self._translate_key(key)]

    def __setitem__(self, key, value):
        if isinstance(key, slice):
            translated = self._translate_key(key)
            expected = len(range(*key.indices(self._size)))
            if len(value) != expected:
                raise ValueError("secure buffer slice assignment must preserve length")
            self._backing[translated] = value
            return
        self._backing[self._translate_key(key)] = value

    def __iter__(self):
        for index in range(self._size):
            yield self._backing[self._offset + index]

    def __bytes__(self):
        return bytes(self._backing[self._offset:self._offset + self._size])

    def __eq__(self, other):
        return bytes(self) == bytes(other)

    def __bool__(self):
        return self._size > 0

    def clear(self):
        """Описывает публичное действие clear."""
        self._memory.secure_zero(self)

    def wipe(self):
        """Описывает публичное действие wipe."""
        self._memory.free_secure(self)

    def to_bytearray(self) -> bytearray:
        """Описывает публичное действие to bytearray."""
        return bytearray(bytes(self))

    def _translate_key(self, key):
        if isinstance(key, slice):
            start, stop, step = key.indices(self._size)
            return slice(self._offset + start, self._offset + stop, step)
        if key < 0:
            key += self._size
        if key < 0 or key >= self._size:
            raise IndexError("secure buffer index out of range")
        return self._offset + key


class SecretBuffer:
    """Контекстно управляемая изменяемая копия чувствительных байтов."""

    def __init__(self, data: bytes, memory: Optional[SecureMemory] = None):
        self.memory = memory or get_secure_memory()
        self.buffer = self.memory.allocate_secure(len(data))
        self.buffer[:] = data

    def bytes(self) -> bytes:
        """Описывает публичное действие bytes."""
        return bytes(self.buffer)

    def wipe(self):
        """Описывает публичное действие wipe."""
        self.memory.free_secure(self.buffer)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.wipe()

    def __del__(self):
        try:
            self.wipe()
        except Exception:
            pass


class StackCanary:
    """Canary-метка с максимально возможной проверкой для критичных Python-областей."""

    def __init__(self):
        self._value = secrets.token_bytes(CANARY_SIZE)
        self._expected = bytes(self._value)

    def verify(self) -> bool:
        """Описывает публичное действие verify."""
        return secrets.compare_digest(self._value, self._expected)

    def corrupt_for_test(self):
        """Описывает публичное действие corrupt for test."""
        self._value = b"\x00" * CANARY_SIZE


class SensitiveScope:
    """Контекстный менеджер, очищающий зарегистрированные временные буферы при выходе."""

    def __init__(self, memory: Optional[SecureMemory] = None, label: str = "critical"):
        self.memory = memory or get_secure_memory()
        self.label = label
        self.canary = StackCanary()
        self._buffers = []

    def buffer(self, data: bytes) -> SecretBuffer:
        """Описывает публичное действие buffer."""
        secret = SecretBuffer(data, memory=self.memory)
        self._buffers.append(secret)
        return secret

    def register(self, buffer):
        """Описывает публичное действие register."""
        self._buffers.append(buffer)
        return buffer

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        canary_ok = self.canary.verify()
        for item in reversed(self._buffers):
            try:
                if isinstance(item, SecretBuffer):
                    item.wipe()
                else:
                    self.memory.secure_zero(item)
            except Exception as error:
                logger.debug("Sensitive scope wipe failed: %s", error)
        self._buffers.clear()
        if not canary_ok:
            try:
                from core.events import event_bus

                event_bus.publish("SecureMemoryCanaryMismatch", {"label": self.label, "scope": True})
            except Exception:
                pass


_secure_memory = SecureMemory()


def get_secure_memory() -> SecureMemory:
    """Возвращает данные для secure memory."""
    return _secure_memory


def sensitive_scope(label: str = "critical", memory: Optional[SecureMemory] = None) -> SensitiveScope:
    """Описывает публичную операцию sensitive scope."""
    return SensitiveScope(memory=memory, label=label)

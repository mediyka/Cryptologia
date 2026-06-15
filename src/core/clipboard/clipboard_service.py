import atexit
import ctypes
import logging
import sys
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional, Set

from core.events import event_bus
from core.state_manager import state_manager
from core.security.memory_guard import get_secure_memory, SecureMemory

from .platform_adapter import ClipboardAdapter, get_default_clipboard_adapter

logger = logging.getLogger("ClipboardService")

MIN_TIMEOUT_SECONDS = 5
MAX_TIMEOUT_SECONDS = 300
DEFAULT_TIMEOUT_SECONDS = 30
SUSPICIOUS_CLEAR_DELAY_SECONDS = 5
NEVER_AUTO_CLEAR = "never"
SUPPORTED_DATA_TYPES = {"password", "username", "notes", "text", "totp", "encrypted_blob"}
MAX_CLIPBOARD_CHARS = 100_000
LOCK_CLEAR_EVENTS = ("UserLoggedOut", "VaultLocked", "ApplicationLocked", "SessionLocked", "UserSessionExpired")


@dataclass(frozen=True)
class ClipboardStatus:
    """Описывает публичный класс ClipboardStatus."""
    active: bool
    data_type: Optional[str] = None
    source_entry_id: Optional[str] = None
    remaining_seconds: float = 0.0
    preview: str = ""
    clear_reason: Optional[str] = None
    copy_blocked: bool = False
    suspicious_count: int = 0


class SecureClipboardItem:

    """Описывает публичный класс SecureClipboardItem."""
    def __init__(self, data: str, data_type: str, source_entry_id: Optional[str]):
        self.data_type = data_type
        self.source_entry_id = source_entry_id
        self.created_at = time.monotonic()
        self._memory = get_secure_memory()
        self._mask = bytearray(secrets.token_bytes(32))
        encoded = bytearray(data, "utf-8")
        try:
            self._data = self._xor(encoded)
        finally:
            self._zero_bytes(encoded)
        self._locked_buffers = []
        self._memory_lock_attempted = False
        self._lock_memory()

    def reveal(self) -> str:
        """Описывает публичное действие reveal."""
        plaintext = self._xor_bytes(self._data)
        try:
            return plaintext.decode("utf-8")
        finally:
            self._zero_bytes(plaintext)

    def preview(self) -> str:
        """Описывает публичное действие preview."""
        value = self.reveal()
        if not value:
            return ""
        if self.data_type == "password":
            prefix = value[:3] if len(value) > 3 else value[:1]
            return prefix + "*" * min(max(len(value) - len(prefix), 4), 10)
        return value[:24] + ("..." if len(value) > 24 else "")

    def secure_wipe(self):
        """Описывает публичное действие secure wipe."""
        self._unlock_memory()
        self._zero_bytes(self._data)
        self._zero_bytes(self._mask)
        self._data = bytearray()
        self._mask = bytearray()

    def _xor(self, data: bytes) -> bytearray:
        return bytearray(byte ^ self._mask[index % len(self._mask)] for index, byte in enumerate(data))

    def _xor_bytes(self, data: bytearray) -> bytearray:
        return bytearray(byte ^ self._mask[index % len(self._mask)] for index, byte in enumerate(data))

    def _lock_memory(self):
        self._memory_lock_attempted = True
        for buffer in (self._data, self._mask):
            if not buffer:
                continue
            address = self._buffer_address(buffer)
            if address is None:
                continue
            size = len(buffer)
            if self._memory.lock_address(address, size):
                self._locked_buffers.append((address, size))

    def _unlock_memory(self):
        while self._locked_buffers:
            address, size = self._locked_buffers.pop()
            self._memory.unlock_address(address, size)

    @staticmethod
    def _buffer_address(buffer: bytearray) -> Optional[int]:
        try:
            return ctypes.addressof((ctypes.c_char * len(buffer)).from_buffer(buffer))
        except Exception:
            return None

    @staticmethod
    def _platform_lock(address: int, size: int) -> bool:
        try:
            if sys.platform == "win32":
                kernel32 = ctypes.windll.kernel32
                return bool(kernel32.VirtualLock(ctypes.c_void_p(address), ctypes.c_size_t(size)))

            libc = ctypes.CDLL("libc.so.6" if sys.platform.startswith("linux") else None)
            return libc.mlock(ctypes.c_void_p(address), ctypes.c_size_t(size)) == 0
        except Exception as exc:
            logger.debug("Clipboard memory lock unavailable: %s", exc)
            return False

    @staticmethod
    def _platform_unlock(address: int, size: int):
        try:
            if sys.platform == "win32":
                kernel32 = ctypes.windll.kernel32
                kernel32.VirtualUnlock(ctypes.c_void_p(address), ctypes.c_size_t(size))
                return

            libc = ctypes.CDLL("libc.so.6" if sys.platform.startswith("linux") else None)
            libc.munlock(ctypes.c_void_p(address), ctypes.c_size_t(size))
        except Exception as exc:
            logger.debug("Clipboard memory unlock failed: %s", exc)

    @staticmethod
    def _zero_bytes(buffer: bytearray):
        if not buffer:
            return
        get_secure_memory().secure_zero(buffer)

    @staticmethod
    def _zero_compact_ascii_string(value: str):
        if not isinstance(value, str) or not value.isascii():
            return
        try:
            SecureMemory.wipe_compact_ascii_string(value)
        except Exception as exc:
            logger.debug("Clipboard string wipe failed: %s", exc)


class ClipboardService:

    """Описывает публичный класс ClipboardService."""
    def __init__(
        self,
        platform_adapter: Optional[ClipboardAdapter] = None,
        event_system=None,
        config: Any = None,
        state=None,
        register_exit_handler: bool = True,
    ):
        self.platform = platform_adapter or get_default_clipboard_adapter()
        self.events = event_system or event_bus
        self.config = config if config is not None else {}
        self.state = state or state_manager
        self.current_content: Optional[SecureClipboardItem] = None
        self._timer: Optional[threading.Timer] = None
        self._expires_at: Optional[float] = None
        self._observers: Set[Callable[[ClipboardStatus], None]] = set()
        self._copy_blocked = False
        self._copy_block_reason: Optional[str] = None
        self._suspicious_count = 0
        self._lock = threading.RLock()
        self._exit_handler = self._clear_on_exit
        self._exit_handler_registered = False
        self._subscribe_to_security_events()
        if register_exit_handler:
            atexit.register(self._exit_handler)
            self._exit_handler_registered = True

    def add_observer(self, observer: Callable[[ClipboardStatus], None]):
        """Добавляет observer."""
        with self._lock:
            self._observers.add(observer)

    def remove_observer(self, observer: Callable[[ClipboardStatus], None]):
        """Удаляет observer."""
        with self._lock:
            self._observers.discard(observer)

    def copy_to_clipboard(
        self,
        data: str,
        data_type: str = "password",
        source_entry_id: Optional[str] = None,
    ) -> bool:
        """Скопировать чувствительный текст и опубликовать ClipboardCopied."""
        try:
            self._validate_copy_request(data, data_type)
        except Exception as exc:
            self._publish_clipboard_error(
                "validation_failed",
                data_type=data_type,
                source_entry_id=source_entry_id,
                message=str(exc),
            )
            raise

        with self._lock:
            self._clear_clipboard_locked("replaced", publish_event=True)
            item = SecureClipboardItem(data, data_type, source_entry_id)

            copied = self.platform.copy_to_clipboard(data)
            if data_type == "password" and getattr(self.platform, "backend_name", None) != "in-memory":
                SecureClipboardItem._zero_compact_ascii_string(data)

            if not copied:
                item.secure_wipe()
                self._publish_clipboard_error(
                    "copy_failed",
                    data_type=data_type,
                    source_entry_id=source_entry_id,
                    message="Не удалось скопировать данные: системный буфер обмена не принял данные.",
                )
                return False

            self.current_content = item
            timeout = self._get_timeout_seconds()
            self._start_timer_locked(timeout)

            payload = {
                "data_type": data_type,
                "source_entry_id": source_entry_id,
                "timeout": timeout,
            }
            self._publish("ClipboardCopied", payload)
            self._notify_observers_locked()
            return True

    def copy_text(self, data: str, source_entry_id: Optional[str] = None) -> bool:
        """Копирует text."""
        return self.copy_to_clipboard(data, data_type="text", source_entry_id=source_entry_id)

    def copy_username(self, username: str, source_entry_id: Optional[str] = None) -> bool:
        """Копирует username."""
        return self.copy_to_clipboard(username, data_type="username", source_entry_id=source_entry_id)

    def copy_password(self, password: str, source_entry_id: Optional[str] = None) -> bool:
        """Копирует password."""
        return self.copy_to_clipboard(password, data_type="password", source_entry_id=source_entry_id)

    def copy_notes(self, notes: str, source_entry_id: Optional[str] = None) -> bool:
        """Копирует notes."""
        return self.copy_to_clipboard(notes, data_type="notes", source_entry_id=source_entry_id)

    def copy_totp(self, code: str, source_entry_id: Optional[str] = None) -> bool:
        """Копирует totp."""
        return self.copy_to_clipboard(code, data_type="totp", source_entry_id=source_entry_id)

    def copy_encrypted_blob(self, blob_text: str, source_entry_id: Optional[str] = None) -> bool:
        """Копирует encrypted blob."""
        return self.copy_to_clipboard(blob_text, data_type="encrypted_blob", source_entry_id=source_entry_id)

    def copy_entry_field(self, entry_manager, entry_id: str, field_name: str) -> bool:
        """Получить расшифрованную запись хранилища и скопировать разрешённое поле."""
        entry = self._get_entry_for_clipboard(entry_manager, entry_id, field_name)
        value = entry.get(field_name, "")
        if not value:
            raise ValueError(f"No clipboard data for entry field: {field_name}")

        try:
            if field_name == "password":
                return self.copy_password(value, source_entry_id=entry_id)
            if field_name == "username":
                return self.copy_username(value, source_entry_id=entry_id)
            if field_name == "notes":
                return self.copy_notes(value, source_entry_id=entry_id)
            if field_name == "totp_secret":
                return self.copy_totp(value, source_entry_id=entry_id)
            if field_name == "sharing_metadata":
                return self.copy_encrypted_blob(str(value), source_entry_id=entry_id)
            return self.copy_text(value, source_entry_id=entry_id)
        finally:
            if field_name == "password":
                SecureClipboardItem._zero_compact_ascii_string(value)
                entry[field_name] = ""
                value = ""

    def copy_entry_summary(self, entry_manager, entry_id: str) -> bool:
        """Скопировать безопасную сводку из нескольких полей последней расшифрованной записи."""
        entry = self._get_entry_for_clipboard(entry_manager, entry_id, "summary")
        fields = [
            ("Title", entry.get("title", "")),
            ("Username", entry.get("username", "")),
            ("Password", entry.get("password", "")),
            ("URL", entry.get("url", "")),
        ]
        content = "\n".join(f"{name}: {value}" for name, value in fields if value)
        if not content:
            raise ValueError("No clipboard data for entry summary")
        return self.copy_text(content, source_entry_id=entry_id)

    def clear_clipboard(self, reason: str = "manual") -> bool:
        """Очищает clipboard."""
        with self._lock:
            return self._clear_clipboard_locked(reason, publish_event=True)

    def shutdown(self) -> bool:
        """Очистить буфер обмена перед выходом из приложения."""
        self._unregister_exit_handler()
        return self.clear_clipboard("close")

    def get_clipboard_status(self) -> ClipboardStatus:
        """Возвращает данные для clipboard status."""
        with self._lock:
            return self._build_status_locked()

    def reveal_current_content(self, authenticator: Callable[[], bool]) -> Optional[str]:
        """Показать текущие данные буфера обмена только после внешней аутентификации."""
        with self._lock:
            if not self.current_content:
                return None
            if not authenticator():
                raise PermissionError("Для просмотра содержимого буфера обмена требуется подтверждение доступа.")
            return self.current_content.reveal()

    def unblock_copies(self):
        """Описывает публичное действие unblock copies."""
        with self._lock:
            self._copy_blocked = False
            self._copy_block_reason = None
            self._publish("ClipboardCopyBlockChanged", {"blocked": False})
            self._notify_observers_locked()

    def is_copy_blocked(self) -> bool:
        """Описывает публичное действие is copy blocked."""
        with self._lock:
            return self._copy_blocked

    def handle_panic_mode(self, reason: str = "panic_mode"):
        """Описывает публичное действие handle panic mode."""
        with self._lock:
            self._copy_blocked = True
            self._copy_block_reason = reason
            self._clear_clipboard_locked(reason, publish_event=True)
            self._publish(
                "ClipboardCopyBlockChanged",
                {
                    "blocked": True,
                    "reason": reason,
                },
            )
            self._notify_observers_locked()

    def set_auto_clear_timeout(self, timeout_seconds: Optional[int]) -> Optional[int]:
        """Сохраняет или обновляет значение auto clear timeout."""
        normalized = self._normalize_timeout(timeout_seconds)
        stored_value = NEVER_AUTO_CLEAR if normalized is None else normalized
        if hasattr(self.config, "set"):
            self.config.set("clipboard_timeout", stored_value)
        else:
            self.config["clipboard_timeout"] = stored_value
        return normalized

    def handle_external_change(self, observed_content: Optional[str]):
        """Описывает публичное действие handle external change."""
        with self._lock:
            if not self.current_content:
                return
            expected = self.current_content.reveal()
            if observed_content == expected:
                return

            self._record_suspicious_activity_locked("external_change", "clear")
            self._clear_clipboard_locked("external_change", publish_event=True)

    def handle_suspicious_access(self, reason: str = "possible_clipboard_snooping"):
        """Описывает публичное действие handle suspicious access."""
        with self._lock:
            if not self.current_content:
                return
            self._record_suspicious_activity_locked(reason, "accelerate_clear")
            self._accelerate_clear_locked(SUSPICIOUS_CLEAR_DELAY_SECONDS, reason)

    def accelerate_clear(self, seconds: int = SUSPICIOUS_CLEAR_DELAY_SECONDS, reason: str = "security"):
        """Описывает публичное действие accelerate clear."""
        with self._lock:
            self._accelerate_clear_locked(seconds, reason)

    def _validate_copy_request(self, data: str, data_type: str):
        if getattr(self.state, "is_locked", False):
            raise PermissionError("Перед операциями с буфером обмена нужно разблокировать хранилище.")
        if self._copy_blocked:
            reason = self._copy_block_reason or "security policy"
            raise PermissionError(f"Копирование в буфер обмена заблокировано: {reason}.")
        if not isinstance(data, str):
            raise TypeError("Данные буфера обмена должны быть текстом.")
        if not data:
            raise ValueError("Данные буфера обмена не должны быть пустыми.")
        if len(data) > MAX_CLIPBOARD_CHARS:
            raise ValueError("Данные буфера обмена превышают допустимый размер.")
        if "\x00" in data:
            raise ValueError("Данные буфера обмена содержат недопустимый NUL-байт.")
        if data_type not in SUPPORTED_DATA_TYPES:
            raise ValueError(f"Неподдерживаемый тип данных буфера обмена: {data_type}")

    def _get_entry_for_clipboard(self, entry_manager, entry_id: str, field_name: str) -> dict:
        if not entry_manager or not hasattr(entry_manager, "get_entry"):
            raise ValueError("Для операций буфера обмена с хранилищем требуется EntryManager.")
        if not entry_id:
            raise ValueError("Для операций буфера обмена с хранилищем требуется ID записи.")

        entry = entry_manager.get_entry(entry_id)
        self._validate_entry_clipboard_policy(entry, field_name)
        return entry

    def _validate_entry_clipboard_policy(self, entry: dict, field_name: str):
        if entry.get("never_copy_to_clipboard") in (True, "true", "True", "1", 1):
            raise PermissionError("Для этой записи запрещено копирование данных в буфер обмена.")

        policy = entry.get("clipboard_policy") or {}
        if policy.get("never_copy") in (True, "true", "True", "1", 1):
            raise PermissionError("Для этой записи запрещено копирование данных в буфер обмена.")

        blocked_fields = set(policy.get("blocked_fields") or policy.get("never_copy_fields") or [])
        if field_name in blocked_fields or (field_name == "summary" and blocked_fields):
            raise PermissionError(f"Копирование поля записи отключено: {field_name}.")

    def _get_timeout_seconds(self) -> Optional[int]:
        if self._config_get("clipboard_auto_clear", True) in (False, "false", "False", "0", 0):
            return None
        raw_value = self._config_get("clipboard_timeout", DEFAULT_TIMEOUT_SECONDS)
        return self._normalize_timeout(raw_value)

    @staticmethod
    def _normalize_timeout(raw_value) -> Optional[int]:
        if raw_value in (None, NEVER_AUTO_CLEAR, "Never", "NEVER", 0, "0", False):
            return None
        try:
            timeout = int(raw_value)
        except (TypeError, ValueError):
            timeout = DEFAULT_TIMEOUT_SECONDS
        return max(MIN_TIMEOUT_SECONDS, min(MAX_TIMEOUT_SECONDS, timeout))

    def _start_timer_locked(self, timeout: Optional[int]):
        self._cancel_timer_locked()
        if timeout is None:
            self._expires_at = None
            return

        self._expires_at = time.monotonic() + timeout
        self._timer = threading.Timer(timeout, self._on_timeout)
        self._timer.daemon = True
        self._timer.start()

    def _accelerate_clear_locked(self, seconds: int, reason: str):
        if not self.current_content:
            return

        delay = max(1, min(SUSPICIOUS_CLEAR_DELAY_SECONDS, int(seconds)))
        current_remaining = None
        if self._expires_at is not None:
            current_remaining = max(0.0, self._expires_at - time.monotonic())
            delay = min(delay, max(1, int(current_remaining)))

        self._start_timer_locked(delay)
        self._publish(
            "ClipboardClearAccelerated",
            {
                "reason": reason,
                "remaining_seconds": delay,
                "source_entry_id": self.current_content.source_entry_id,
                "data_type": self.current_content.data_type,
                "previous_remaining_seconds": current_remaining,
            },
        )
        self._publish(
            "ClipboardWarning",
            {
                "reason": reason,
                "message": "Буфер обмена скоро будет очищен из-за подозрительной активности.",
                "remaining_seconds": delay,
            },
        )
        self._notify_observers_locked()

    def _on_timeout(self):
        with self._lock:
            self._clear_clipboard_locked("timeout", publish_event=True)

    def _clear_on_exit(self):
        try:
            self.clear_clipboard("process_exit")
        except Exception as exc:
            logger.debug("Clipboard process-exit clear failed: %s", exc)

    def _unregister_exit_handler(self):
        if not self._exit_handler_registered or not hasattr(atexit, "unregister"):
            return
        try:
            atexit.unregister(self._exit_handler)
        except Exception as exc:
            logger.debug("Clipboard exit handler unregister failed: %s", exc)
        finally:
            self._exit_handler_registered = False

    def _clear_clipboard_locked(self, reason: str, publish_event: bool) -> bool:
        self._cancel_timer_locked()
        self._expires_at = None

        had_content = self.current_content is not None
        source_entry_id = self.current_content.source_entry_id if self.current_content else None
        data_type = self.current_content.data_type if self.current_content else None

        cleared = self.platform.clear_clipboard()
        if self.current_content:
            self.current_content.secure_wipe()
            self.current_content = None

        if publish_event and (had_content or reason in {"manual", "lock", "close"}):
            self._publish(
                "ClipboardCleared",
                {
                    "reason": reason,
                    "source_entry_id": source_entry_id,
                    "data_type": data_type,
                    "cleared": cleared,
                },
            )

        if had_content or reason != "replaced":
            self._notify_observers_locked(clear_reason=reason)
        if not cleared:
            self._publish_clipboard_error(
                "clear_failed",
                data_type=data_type,
                source_entry_id=source_entry_id,
                message="Не удалось автоматически очистить буфер обмена. Очистите его вручную.",
                manual_clear_required=True,
            )
        return cleared

    def _cancel_timer_locked(self):
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None

    def _build_status_locked(self, clear_reason: Optional[str] = None) -> ClipboardStatus:
        if not self.current_content:
            return ClipboardStatus(
                active=False,
                clear_reason=clear_reason,
                copy_blocked=self._copy_blocked,
                suspicious_count=self._suspicious_count,
            )

        remaining = 0.0
        if self._expires_at is not None:
            remaining = max(0.0, self._expires_at - time.monotonic())

        return ClipboardStatus(
            active=True,
            data_type=self.current_content.data_type,
            source_entry_id=self.current_content.source_entry_id,
            remaining_seconds=remaining,
            preview=self.current_content.preview(),
            clear_reason=clear_reason,
            copy_blocked=self._copy_blocked,
            suspicious_count=self._suspicious_count,
        )

    def _notify_observers_locked(self, clear_reason: Optional[str] = None):
        status = self._build_status_locked(clear_reason)
        for observer in list(self._observers):
            try:
                observer(status)
            except Exception as exc:
                logger.error("Clipboard observer failed: %s", exc)

    def _publish(self, event_name: str, payload: dict):
        if self.events:
            self.events.publish(event_name, payload)

    def _publish_clipboard_error(
        self,
        reason: str,
        data_type: Optional[str] = None,
        source_entry_id: Optional[str] = None,
        message: str = "",
        manual_clear_required: bool = False,
    ):
        payload = {
            "reason": reason,
            "data_type": data_type,
            "source_entry_id": source_entry_id,
            "backend_name": getattr(self.platform, "backend_name", None),
            "message": message,
            "manual_clear_required": manual_clear_required,
        }
        self._publish("ClipboardError", payload)

    def _config_get(self, key: str, default=None):
        if hasattr(self.config, "get"):
            return self.config.get(key, default)
        return default

    def _record_suspicious_activity_locked(self, reason: str, action: str):
        self._suspicious_count += 1
        source_entry_id = self.current_content.source_entry_id if self.current_content else None
        data_type = self.current_content.data_type if self.current_content else None

        payload = {
            "reason": reason,
            "action": action,
            "source_entry_id": source_entry_id,
            "data_type": data_type,
            "count": self._suspicious_count,
        }
        self._publish("ClipboardSuspiciousActivity", payload)
        self._publish(
            "ClipboardWarning",
            {
                "reason": reason,
                "message": "Suspicious clipboard activity detected.",
                "action": action,
            },
        )

        if self._config_get("clipboard_block_on_suspicious", False) in (True, "true", "True", "1", 1):
            self._copy_blocked = True
            self._copy_block_reason = reason
            self._publish(
                "ClipboardCopyBlockChanged",
                {
                    "blocked": True,
                    "reason": reason,
                },
            )

    def _subscribe_to_security_events(self):
        if not hasattr(self.events, "subscribe"):
            return
        try:
            for event_name in LOCK_CLEAR_EVENTS:
                self.events.subscribe(event_name, lambda event: self.clear_clipboard("lock"))
            self.events.subscribe("PanicModeActivated", lambda event: self.handle_panic_mode())
        except Exception as exc:
            logger.debug("Clipboard security event subscription failed: %s", exc)

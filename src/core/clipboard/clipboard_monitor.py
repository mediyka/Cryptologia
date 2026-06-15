import logging
import threading
from typing import Optional

from .clipboard_service import ClipboardService
from .platform_adapter import ClipboardAccessInfo

logger = logging.getLogger("ClipboardMonitor")


class ClipboardMonitor:


    """Описывает публичный класс ClipboardMonitor."""
    def __init__(self, clipboard_service: ClipboardService, interval_seconds: float = 1.0):
        self.clipboard_service = clipboard_service
        self.interval_seconds = max(0.25, float(interval_seconds))
        self._timer: Optional[threading.Timer] = None
        self._running = False
        self._last_seen: Optional[ClipboardAccessInfo] = None
        self._lock = threading.RLock()

    def start(self) -> bool:
        """Описывает публичное действие start."""
        with self._lock:
            if self._running:
                return True
            self._running = True
            self._last_seen = self._read_access_info()
            self._schedule_locked()
            self.clipboard_service._publish(
                "ClipboardMonitorStarted",
                {"interval_seconds": self.interval_seconds},
            )
            return True

    def stop(self):
        """Описывает публичное действие stop."""
        with self._lock:
            self._running = False
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
        self.clipboard_service._publish("ClipboardMonitorStopped", {})

    def poll_once(self):
        """Описывает публичное действие poll once."""
        current = self._read_access_info()
        if current is _READ_FAILED:
            return

        if self._looks_like_external_access(current):
            self.clipboard_service.handle_suspicious_access("external_clipboard_access")
            return

        if self._content_changed(current):
            self._last_seen = current
            self.clipboard_service.handle_external_change(current.content)

    def _read_access_info(self):
        try:
            return self.clipboard_service.platform.get_access_info()
        except Exception as exc:
            logger.warning("Clipboard monitoring failed: %s", exc)
            self.clipboard_service._publish(
                "ClipboardMonitorError",
                {
                    "reason": "poll_failed",
                    "message": "Мониторинг буфера обмена ограничен: не удалось получить доступ к буферу.",
                },
            )
            return _READ_FAILED

    def _looks_like_external_access(self, current: ClipboardAccessInfo) -> bool:
        if not self.clipboard_service.get_clipboard_status().active:
            return False
        if current.is_busy or current.access_error:
            return True
        return False

    def _content_changed(self, current: ClipboardAccessInfo) -> bool:
        if self._last_seen is None or self._last_seen is _READ_FAILED:
            return True
        if current.sequence_number is not None and self._last_seen.sequence_number is not None:
            if current.sequence_number != self._last_seen.sequence_number:
                return True
        return current.content != self._last_seen.content

    def _schedule_locked(self):
        if not self._running:
            return
        self._timer = threading.Timer(self.interval_seconds, self._poll_loop)
        self._timer.daemon = True
        self._timer.start()

    def _poll_loop(self):
        with self._lock:
            if not self._running:
                return
        self.poll_once()
        with self._lock:
            self._schedule_locked()


class _ReadFailed:
    pass


_READ_FAILED = _ReadFailed()

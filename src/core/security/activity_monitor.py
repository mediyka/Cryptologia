import threading
import time
from typing import Callable, Optional

from core.events import event_bus

SENSITIVITY_INTERVALS = {
    "low": 5.0,
    "medium": 1.0,
    "high": 0.5,
}


class ActivityMonitor:
    """Точка входа фреймворка Sprint 7 для отслеживания активности и автоблокировки."""

    def __init__(
        self,
        lock_callback: Callable[[str], None],
        config: Optional[dict] = None,
        bus=event_bus,
        is_locked_callback: Optional[Callable[[], bool]] = None,
    ):
        self.lock_callback = lock_callback
        self.config = config or {}
        self.bus = bus
        self.last_activity = time.monotonic()
        self.last_published_activity = self.last_activity
        self.last_focus_change = None
        self.last_system_lock_signal = None
        self.monitoring = False
        self._thread = None
        self._lock = threading.RLock()
        self._lock_requested = False
        self._is_locked_callback = is_locked_callback or (lambda: False)

    def start_monitoring(self):
        """Запускает monitoring."""
        with self._lock:
            if self.monitoring:
                return
            self.monitoring = True
            self._lock_requested = False
            self._thread = threading.Thread(target=self._monitor_loop, name="ActivityMonitor", daemon=True)
            self._thread.start()
            self.bus.publish("ActivityMonitorStarted", {"timeout_seconds": self.timeout_seconds})

    def stop_monitoring(self):
        """Останавливает monitoring."""
        with self._lock:
            self.monitoring = False
        if self._thread:
            self._thread.join(timeout=2.0)
            self._thread = None
        self.bus.publish("ActivityMonitorStopped", {})

    def record_activity(self, source: str = "application"):
        """Описывает публичное действие record activity."""
        now = time.monotonic()
        with self._lock:
            should_publish = now - self.last_published_activity >= self._publish_interval()
            self.last_activity = now
            self._lock_requested = False
            if should_publish:
                self.last_published_activity = now
        if should_publish:
            self.bus.publish("UserActivityRecorded", {"source": source, "idle_seconds": 0})

    def record_mouse_activity(self):
        """Описывает публичное действие record mouse activity."""
        self.record_activity("mouse")

    def record_keyboard_activity(self):
        """Описывает публичное действие record keyboard activity."""
        self.record_activity("keyboard")

    def record_focus_change(self, focused: bool):
        """Описывает публичное действие record focus change."""
        with self._lock:
            self.last_focus_change = time.monotonic()
        self.bus.publish("WindowFocusChanged", {"focused": bool(focused)})
        if focused:
            self.record_activity("focus")

    def record_system_lock_signal(self, source: str = "system"):
        """Описывает публичное действие record system lock signal."""
        with self._lock:
            self.last_system_lock_signal = time.monotonic()
            self._lock_requested = True
        self.bus.publish("SystemLockDetected", {"source": source})
        self.lock_callback("system_lock")

    def update_config(self, config: Optional[dict]):
        """Обновляет config."""
        with self._lock:
            self.config = config or {}
        self.bus.publish("ActivityMonitorConfigUpdated", {"timeout_seconds": self.timeout_seconds})

    @property
    def timeout_seconds(self) -> int:
        """Описывает публичное действие timeout seconds."""
        raw = self._config_get("activity_lock_timeout_seconds", None)
        device_profile = str(self._config_get("activity_device_profile", "") or "").lower()
        if device_profile in {"desktop", "laptop"}:
            raw = self._config_get(f"activity_lock_timeout_seconds_{device_profile}", raw)
        if raw is None:
            # Обратная совместимость: старая настройка хранится в минутах.
            raw = int(self._config_get("auto_lock_timeout", 5)) * 60
        try:
            value = int(raw)
        except (TypeError, ValueError):
            value = 300
        return max(60, min(8 * 60 * 60, value))

    @property
    def sensitivity(self) -> str:
        """Описывает публичное действие sensitivity."""
        value = str(self._config_get("activity_sensitivity", "medium") or "medium").lower()
        return value if value in SENSITIVITY_INTERVALS else "medium"

    def get_idle_time(self) -> float:
        """Возвращает данные для idle time."""
        with self._lock:
            return time.monotonic() - self.last_activity

    def should_lock(self) -> bool:
        """Описывает публичное действие should lock."""
        return not self._is_locked_callback() and self.get_idle_time() >= self.timeout_seconds

    def _monitor_loop(self):
        while True:
            with self._lock:
                if not self.monitoring:
                    return
                already_requested = self._lock_requested
            if not already_requested and self.should_lock():
                idle_time = self.get_idle_time()
                with self._lock:
                    self._lock_requested = True
                self.bus.publish("ActivityAutoLockTriggered", {"idle_seconds": idle_time})
                self.lock_callback("inactivity")
            time.sleep(self._check_interval())

    def _check_interval(self) -> float:
        configured = self._config_get("activity_check_interval_seconds", None)
        if configured is not None:
            try:
                return max(0.5, min(60.0, float(configured)))
            except (TypeError, ValueError):
                pass
        return SENSITIVITY_INTERVALS[self.sensitivity]

    def _publish_interval(self) -> float:
        return {"low": 2.0, "medium": 1.0, "high": 0.25}[self.sensitivity]

    def _config_get(self, key: str, default=None):
        if hasattr(self.config, "get"):
            return self.config.get(key, default)
        return default

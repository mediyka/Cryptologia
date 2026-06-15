import logging
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Callable, Optional

from core.events import event_bus

logger = logging.getLogger("PanicMode")


class PanicMode:
    """Координатор аварийного режима для интеграций GUI и системного трея."""

    def __init__(self, config: Optional[dict] = None, bus=event_bus):
        self.config = config or {}
        self.bus = bus
        self.activated = False
        self._handlers: list[Callable[[str], None]] = []
        self._lock = threading.RLock()
        self._window_positions = deque(maxlen=8)
        self._gesture_started_at: Optional[float] = None
        self._gesture_last_x: Optional[int] = None
        self._gesture_last_direction = 0
        self._gesture_direction_changes = 0
        self.register_handler(self._wipe_secure_memory)

    def register_handler(self, handler: Callable[[str], None]):
        """Описывает публичное действие register handler."""
        with self._lock:
            self._handlers.append(handler)

    def activate(self, method: str = "manual") -> bool:
        """Описывает публичное действие activate."""
        if not self.is_enabled:
            return False
        with self._lock:
            if self.activated:
                return False
            self.activated = True
            handlers = list(self._handlers)

        payload = self._activation_payload(method)
        self.bus.publish("PanicModeActivated", payload)
        for handler in handlers:
            try:
                handler(method)
            except Exception as exc:
                logger.error("Panic handler failed: %s", exc)
                self.bus.publish("PanicModeHandlerFailed", {"method": method, "error": str(exc)})
        self.execute_stealth_actions(method)
        return True

    def reset(self):
        """Описывает публичное действие reset."""
        with self._lock:
            self.activated = False
        self.bus.publish("PanicModeDeactivated", {})

    def recover(self, method: str = "manual") -> bool:
        """Описывает публичное действие recover."""
        with self._lock:
            if not self.activated:
                return False
        self.bus.publish("PanicModeRecoveryStarted", {"method": method})
        self.reset()
        return True

    @property
    def is_enabled(self) -> bool:
        """Описывает публичное действие is enabled."""
        return self._config_bool("panic_mode_enabled", True)

    @property
    def close_application(self) -> bool:
        """Описывает публичное действие close application."""
        return self._config_bool("panic_close_application", False)

    @property
    def stealth_mode(self) -> bool:
        """Описывает публичное действие stealth mode."""
        return self._config_bool("panic_stealth_mode", False)

    def hotkey_sequence(self) -> str:
        """Описывает публичное действие hotkey sequence."""
        hotkey = "Ctrl+Alt+P"
        tokens = [token.strip().lower() for token in hotkey.replace("+", " ").split() if token.strip()]
        mapping = {
            "ctrl": "Control",
            "control": "Control",
            "shift": "Shift",
            "alt": "Alt",
            "esc": "Escape",
            "escape": "Escape",
        }
        mapped = [mapping.get(token, token.lower() if len(token) == 1 else token.capitalize()) for token in tokens]
        return f"<{'-'.join(mapped)}>" if mapped else "<Control-Alt-p>"

    def record_window_position(self, x: int, y: int, now: Optional[float] = None) -> bool:
        """Описывает публичное действие record window position."""
        if not self._config_bool("panic_mouse_gesture_enabled", True):
            return False
        now = time.monotonic() if now is None else now
        x = int(x)
        y = int(y)
        if self._window_positions:
            _, last_x, last_y = self._window_positions[-1]
            if abs(x - last_x) < 8 and abs(y - last_y) < 8:
                return False
        self._window_positions.append((now, x, y))
        if self._detect_shake():
            position_count = len(self._window_positions)
            self._window_positions.clear()
            self._reset_pointer_gesture()
            self.bus.publish("PanicMouseGestureDetected", {"positions": position_count})
            return True
        return False

    def record_pointer_position(self, x: int, y: int, now: Optional[float] = None) -> bool:
        """Описывает публичное действие record pointer position."""
        if not self._config_bool("panic_mouse_gesture_enabled", True):
            return False
        now = time.monotonic() if now is None else now
        if self._detect_pointer_shake(int(x), now):
            self._reset_pointer_gesture()
            self.bus.publish("PanicMouseGestureDetected", {"positions": 0, "source": "pointer"})
            return True
        return False

    def execute_stealth_actions(self, method: str = "manual") -> list[dict]:
        """Описывает публичное действие execute stealth actions."""
        if not self.stealth_mode:
            return []
        actions = []
        if self._config_bool("panic_show_fake_error", False):
            actions.append(
                {
                    "type": "fake_error",
                    "message": self._config_get(
                        "panic_fake_error_message",
                        "The application has encountered an unexpected error.",
                    ),
                }
            )
        if self._config_bool("panic_launch_decoy", False):
            command = str(self._config_get("panic_decoy_command", "") or "").strip()
            if command:
                actions.append({"type": "launch_decoy", "command": command})
        redirect_url = str(self._config_get("panic_redirect_url", "") or "").strip()
        if redirect_url:
            actions.append({"type": "redirect_url", "url": redirect_url})

        for action in actions:
            payload = {"method": method, **action}
            self.bus.publish("PanicStealthActionRequested", payload)
        return actions

    def _wipe_secure_memory(self, method: str):
        from core.security.memory_guard import get_secure_memory

        wiped = get_secure_memory().wipe_all()
        self.bus.publish("SecureMemoryWiped", {"reason": "panic_mode", "count": wiped, "method": method})

    def _activation_payload(self, method: str) -> dict:
        return {
            "method": method,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stealth_mode": self.stealth_mode,
            "close_application": self.close_application,
        }

    def _detect_shake(self) -> bool:
        if len(self._window_positions) < 7:
            return False
        positions = list(self._window_positions)
        if positions[-1][0] - positions[0][0] > 1.6:
            return False

        if self._axis_shake_detected(positions, axis=1):
            return True

        return self._axis_shake_detected(positions, axis=2)

    def _axis_shake_detected(self, positions: list[tuple[float, int, int]], axis: int) -> bool:
        values = [position[axis] for position in positions]
        if max(values) - min(values) < 70:
            return False

        changes = 0
        strong_steps = 0
        previous_direction = 0
        for previous, current in zip(values, values[1:]):
            delta = current - previous
            if abs(delta) < 22:
                continue
            strong_steps += 1
            direction = 1 if delta > 0 else -1
            if previous_direction and direction != previous_direction:
                changes += 1
            previous_direction = direction
        return strong_steps >= 5 and changes >= 3

    def _detect_pointer_shake(self, x: int, now: float) -> bool:
        if self._gesture_started_at is None or self._gesture_last_x is None:
            self._gesture_started_at = now
            self._gesture_last_x = x
            return False

        if now - self._gesture_started_at > 2.0:
            self._reset_pointer_gesture()
            self._gesture_started_at = now
            self._gesture_last_x = x
            return False

        delta = x - self._gesture_last_x
        if abs(delta) < 12:
            return False

        direction = 1 if delta > 0 else -1
        if self._gesture_last_direction and direction != self._gesture_last_direction:
            self._gesture_direction_changes += 1
        self._gesture_last_direction = direction
        self._gesture_last_x = x
        return self._gesture_direction_changes >= 2

    def _reset_pointer_gesture(self):
        self._gesture_started_at = None
        self._gesture_last_x = None
        self._gesture_last_direction = 0
        self._gesture_direction_changes = 0

    def _config_get(self, key: str, default=None):
        if hasattr(self.config, "get"):
            return self.config.get(key, default)
        return default

    def _config_bool(self, key: str, default: bool = False) -> bool:
        value = self._config_get(key, default)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in {"1", "true", "yes", "on"}
        return bool(value)

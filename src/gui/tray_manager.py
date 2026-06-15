import logging
import threading
from dataclasses import dataclass
from typing import Callable, Optional

from core.events import event_bus

logger = logging.getLogger("TrayManager")


@dataclass
class TrayState:
    """Описывает публичный класс TrayState."""
    locked: bool = True
    clipboard_active: bool = False
    clipboard_text: str = "Буфер: пусто"
    backend: str = "fallback"
    running: bool = False


class TrayManager:
    """
    Координатор системного трея с опциональным backend на pystray.

    Если pystray недоступен, менеджер всё равно предоставляет тот же набор
    команд и позволяет Tk-окну работать скрыто в фоне.
    """

    def __init__(
        self,
        app,
        config,
        *,
        lock_callback: Callable[[], None],
        unlock_callback: Callable[[], None],
        show_callback: Callable[[], None],
        quick_search_callback: Callable[[], None],
        clear_clipboard_callback: Callable[[], None],
        panic_callback: Callable[[], None],
        settings_callback: Callable[[], None],
        exit_callback: Callable[[], None],
        bus=event_bus,
    ):
        self.app = app
        self.config = config
        self.lock_callback = lock_callback
        self.unlock_callback = unlock_callback
        self.show_callback = show_callback
        self.quick_search_callback = quick_search_callback
        self.clear_clipboard_callback = clear_clipboard_callback
        self.panic_callback = panic_callback
        self.settings_callback = settings_callback
        self.exit_callback = exit_callback
        self.bus = bus
        self.state = TrayState()
        self._icon = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> bool:
        """Описывает публичное действие start."""
        if not self._config_bool("tray_enabled", True):
            return False
        if self.state.running:
            return True
        self.state.running = True
        started = self._start_pystray()
        if not started:
            self.state.backend = "fallback"
        self.bus.publish("TrayStarted", {"backend": self.state.backend})
        return True

    def stop(self):
        """Описывает публичное действие stop."""
        if not self.state.running:
            return
        self.state.running = False
        icon = self._icon
        self._icon = None
        if icon is not None:
            try:
                icon.stop()
            except Exception as exc:
                logger.debug("Tray backend stop failed: %s", exc)
        self.bus.publish("TrayStopped", {"backend": self.state.backend})

    def hide_window(self):
        """Скрывает window."""
        try:
            self.app.withdraw()
            self.bus.publish("WindowHiddenToTray", {"backend": self.state.backend})
        except Exception as exc:
            logger.error("Failed to hide window to tray: %s", exc)

    def show_window(self):
        """Показывает window."""
        try:
            self.app.deiconify()
            self.app.lift()
            try:
                self.app.focus_force()
            except Exception:
                pass
            self.bus.publish("WindowRestoredFromTray", {"backend": self.state.backend})
        except Exception as exc:
            logger.error("Failed to restore window from tray: %s", exc)

    def update_security_state(self, locked: bool):
        """Обновляет security state."""
        self.state.locked = bool(locked)
        self._refresh_icon()

    def update_clipboard_status(self, status):
        """Обновляет clipboard status."""
        active = bool(getattr(status, "active", False))
        self.state.clipboard_active = active
        if active:
            data_type = getattr(status, "data_type", "text") or "text"
            remaining = getattr(status, "remaining_seconds", 0)
            self.state.clipboard_text = f"Очистить буфер: {data_type} ({int(remaining)} сек)"
        else:
            self.state.clipboard_text = "Буфер: пусто"
        self._refresh_icon()

    def notify(self, title: str, message: str):
        """Описывает публичное действие notify."""
        if self._icon is not None and hasattr(self._icon, "notify"):
            try:
                self._icon.notify(message, title)
                return
            except Exception as exc:
                logger.debug("Tray notification failed: %s", exc)
        self.bus.publish("TrayNotification", {"title": title, "message": message})

    def command_lock_or_unlock(self):
        """Описывает публичное действие command lock or unlock."""
        if self.state.locked:
            self._dispatch(self.unlock_callback)
        else:
            self._dispatch(self.lock_callback)

    def command_show(self):
        """Описывает публичное действие command show."""
        self._dispatch(self.show_callback)

    def command_quick_search(self):
        """Описывает публичное действие command quick search."""
        self._dispatch(self.quick_search_callback)

    def command_clear_clipboard(self):
        """Описывает публичное действие command clear clipboard."""
        self._dispatch(self.clear_clipboard_callback)

    def command_panic(self):
        """Описывает публичное действие command panic."""
        self._dispatch(self.panic_callback)

    def command_settings(self):
        """Описывает публичное действие command settings."""
        self._dispatch(self.settings_callback)

    def command_exit(self):
        """Описывает публичное действие command exit."""
        self._dispatch(self.exit_callback)

    def _dispatch(self, callback: Callable[[], None]):
        if hasattr(self.app, "after"):
            try:
                self.app.after(0, callback)
                return
            except Exception as exc:
                logger.debug("Tray Tk dispatch failed: %s", exc)
        callback()

    def _start_pystray(self) -> bool:
        try:
            import pystray
            from PIL import Image, ImageDraw
        except Exception:
            return False

        try:
            image = self._build_icon_image(Image, ImageDraw)
            self._icon = pystray.Icon(
                "cryptosafe-manager",
                image,
                "CryptoSafe Manager",
                self._build_pystray_menu(pystray),
            )
            self.state.backend = "pystray"
            self._thread = threading.Thread(target=self._icon.run, name="CryptoSafeTray", daemon=True)
            self._thread.start()
            return True
        except Exception as exc:
            logger.warning("pystray backend unavailable: %s", exc)
            self._icon = None
            return False

    def _build_pystray_menu(self, pystray):
        return pystray.Menu(
            pystray.MenuItem(lambda item: "Разблокировать" if self.state.locked else "Заблокировать", self.command_lock_or_unlock),
            pystray.MenuItem("Показать окно", self.command_show),
            pystray.MenuItem("Быстрый поиск", self.command_quick_search),
            pystray.MenuItem(lambda item: self.state.clipboard_text, self.command_clear_clipboard),
            pystray.MenuItem("Режим паники", self.command_panic),
            pystray.MenuItem("Настройки", self.command_settings),
            pystray.MenuItem("Выход", self.command_exit),
        )

    def _build_icon_image(self, Image, ImageDraw):
        color = "#b00020" if self.state.locked else "#128a42"
        image = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        draw = ImageDraw.Draw(image)
        draw.rounded_rectangle((10, 24, 54, 56), radius=8, fill=color)
        draw.arc((18, 6, 46, 38), start=180, end=360, fill=color, width=7)
        if self.state.clipboard_active:
            draw.ellipse((44, 44, 58, 58), fill="#f4c430")
        return image

    def _refresh_icon(self):
        if self._icon is None:
            return
        try:
            from PIL import Image, ImageDraw

            self._icon.icon = self._build_icon_image(Image, ImageDraw)
            if hasattr(self._icon, "update_menu"):
                self._icon.update_menu()
        except Exception as exc:
            logger.debug("Tray refresh failed: %s", exc)

    def _config_bool(self, key: str, default: bool) -> bool:
        if hasattr(self.config, "get_bool"):
            return self.config.get_bool(key, default)
        if hasattr(self.config, "get"):
            return bool(self.config.get(key, default))
        return default

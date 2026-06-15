import logging
import os
import platform
import shutil
import subprocess
from abc import ABC, abstractmethod
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("ClipboardAdapter")


@dataclass(frozen=True)
class ClipboardAccessInfo:
    """Описывает публичный класс ClipboardAccessInfo."""
    content: Optional[str]
    backend_name: str
    sequence_number: Optional[int] = None
    is_busy: bool = False
    owner_handle: Optional[int] = None
    access_error: Optional[str] = None


class ClipboardAdapter(ABC):


    """Описывает публичный класс ClipboardAdapter."""
    backend_name = "abstract"

    @abstractmethod
    def copy_to_clipboard(self, data: str) -> bool:
        """Скопировать текстовые данные в системный буфер обмена."""

    @abstractmethod
    def clear_clipboard(self) -> bool:
        """Очистить системный буфер обмена."""

    @abstractmethod
    def get_clipboard_content(self) -> Optional[str]:
        """Вернуть текущий текст из буфера обмена, если он доступен."""

    def get_access_info(self) -> ClipboardAccessInfo:
        """Возвращает данные для access info."""
        try:
            return ClipboardAccessInfo(
                content=self.get_clipboard_content(),
                backend_name=self.backend_name,
            )
        except Exception as exc:
            return ClipboardAccessInfo(
                content=None,
                backend_name=self.backend_name,
                is_busy=True,
                access_error=str(exc),
            )


class WindowsClipboardAdapter(ClipboardAdapter):


    """Описывает публичный класс WindowsClipboardAdapter."""
    backend_name = "windows-win32clipboard"

    def __init__(self):
        import win32clipboard

        self.win32clipboard = win32clipboard

    @contextmanager
    def _open_clipboard(self):
        self.win32clipboard.OpenClipboard()
        try:
            yield
        finally:
            self.win32clipboard.CloseClipboard()

    def copy_to_clipboard(self, data: str) -> bool:
        """Копирует to clipboard."""
        try:
            with self._open_clipboard():
                self.win32clipboard.EmptyClipboard()
                self.win32clipboard.SetClipboardText(data, self.win32clipboard.CF_UNICODETEXT)
            return True
        except Exception as exc:
            logger.warning("Windows clipboard copy failed: %s", exc)
            return False

    def clear_clipboard(self) -> bool:
        """Очищает clipboard."""
        try:
            with self._open_clipboard():
                self.win32clipboard.EmptyClipboard()
            return True
        except Exception as exc:
            logger.warning("Windows clipboard clear failed: %s", exc)
            return False

    def get_clipboard_content(self) -> Optional[str]:
        """Возвращает данные для clipboard content."""
        try:
            with self._open_clipboard():
                if not self.win32clipboard.IsClipboardFormatAvailable(self.win32clipboard.CF_UNICODETEXT):
                    return None
                return self.win32clipboard.GetClipboardData(self.win32clipboard.CF_UNICODETEXT)
        except Exception as exc:
            logger.debug("Windows clipboard read failed: %s", exc)
            return None

    def get_access_info(self) -> ClipboardAccessInfo:
        """Возвращает данные для access info."""
        sequence_number = self._get_sequence_number()
        owner_handle = self._get_open_clipboard_window()
        try:
            with self._open_clipboard():
                if not self.win32clipboard.IsClipboardFormatAvailable(self.win32clipboard.CF_UNICODETEXT):
                    content = None
                else:
                    content = self.win32clipboard.GetClipboardData(self.win32clipboard.CF_UNICODETEXT)
            return ClipboardAccessInfo(
                content=content,
                backend_name=self.backend_name,
                sequence_number=sequence_number,
                is_busy=False,
                owner_handle=owner_handle,
            )
        except Exception as exc:
            return ClipboardAccessInfo(
                content=None,
                backend_name=self.backend_name,
                sequence_number=sequence_number,
                is_busy=True,
                owner_handle=owner_handle,
                access_error=str(exc),
            )

    def _get_sequence_number(self) -> Optional[int]:
        try:
            import ctypes

            user32 = ctypes.windll.user32
            return int(user32.GetClipboardSequenceNumber())
        except Exception:
            return None

    def _get_open_clipboard_window(self) -> Optional[int]:
        try:
            import ctypes

            user32 = ctypes.windll.user32
            handle = int(user32.GetOpenClipboardWindow())
            return handle or None
        except Exception:
            return None


class MacOSClipboardAdapter(ClipboardAdapter):


    """Описывает публичный класс MacOSClipboardAdapter."""
    backend_name = "macos-nspasteboard"

    def __init__(self):
        from AppKit import NSPasteboard, NSPasteboardTypeString

        self.NSPasteboard = NSPasteboard
        self.NSPasteboardTypeString = NSPasteboardTypeString
        self.pasteboard = NSPasteboard.generalPasteboard()

    def copy_to_clipboard(self, data: str) -> bool:
        """Копирует to clipboard."""
        try:
            self.pasteboard.declareTypes_owner_([self.NSPasteboardTypeString], None)
            return bool(self.pasteboard.setString_forType_(data, self.NSPasteboardTypeString))
        except Exception as exc:
            logger.warning("macOS clipboard copy failed: %s", exc)
            return False

    def clear_clipboard(self) -> bool:
        """Очищает clipboard."""
        try:
            self.pasteboard.clearContents()
            return True
        except Exception as exc:
            logger.warning("macOS clipboard clear failed: %s", exc)
            return False

    def get_clipboard_content(self) -> Optional[str]:
        """Возвращает данные для clipboard content."""
        try:
            value = self.pasteboard.stringForType_(self.NSPasteboardTypeString)
            return str(value) if value is not None else None
        except Exception as exc:
            logger.debug("macOS clipboard read failed: %s", exc)
            return None


class LinuxClipboardAdapter(ClipboardAdapter):

    """Описывает публичный класс LinuxClipboardAdapter."""
    backend_name = "linux-command"

    def __init__(self, selection: str = "clipboard"):
        self.selection = self._normalize_selection(selection)
        self.backend = self._detect_backend()
        self._copy_cmd = self._find_copy_command()
        self._paste_cmd = self._find_paste_command()
        if not self._copy_cmd or not self._paste_cmd:
            raise RuntimeError("No Linux clipboard backend found")
        self.backend_name = f"linux-{self.backend}-{self.selection}"

    def copy_to_clipboard(self, data: str) -> bool:
        """Копирует to clipboard."""
        try:
            subprocess.run(
                self._copy_cmd,
                input=data,
                text=True,
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True
        except Exception as exc:
            logger.warning("Linux clipboard copy failed: %s", exc)
            return False

    def clear_clipboard(self) -> bool:
        """Очищает clipboard."""
        return self.copy_to_clipboard("")

    def get_clipboard_content(self) -> Optional[str]:
        """Возвращает данные для clipboard content."""
        try:
            result = subprocess.run(
                self._paste_cmd,
                text=True,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
            return result.stdout
        except Exception as exc:
            logger.debug("Linux clipboard read failed: %s", exc)
            return None

    @staticmethod
    def _command_exists(command: str) -> bool:
        return shutil.which(command) is not None

    @staticmethod
    def _normalize_selection(selection: str) -> str:
        selection = (selection or "clipboard").lower()
        if selection not in {"clipboard", "primary"}:
            raise ValueError("Linux clipboard selection must be 'clipboard' or 'primary'")
        return selection

    def _detect_backend(self) -> Optional[str]:
        if os.environ.get("WAYLAND_DISPLAY") and self._command_exists("wl-copy") and self._command_exists("wl-paste"):
            return "wl-clipboard"
        if self._command_exists("xclip"):
            return "xclip"
        if self._command_exists("xsel"):
            return "xsel"
        if self._command_exists("wl-copy") and self._command_exists("wl-paste"):
            return "wl-clipboard"
        return None

    def _find_copy_command(self):
        if self.backend == "wl-clipboard":
            command = ["wl-copy"]
            if self.selection == "primary":
                command.append("--primary")
            return command
        if self.backend == "xclip":
            return ["xclip", "-selection", self.selection]
        if self.backend == "xsel":
            return ["xsel", self._xsel_selection_arg(), "--input"]
        return None

    def _find_paste_command(self):
        if self.backend == "wl-clipboard":
            command = ["wl-paste", "--no-newline"]
            if self.selection == "primary":
                command.append("--primary")
            return command
        if self.backend == "xclip":
            return ["xclip", "-selection", self.selection, "-o"]
        if self.backend == "xsel":
            return ["xsel", self._xsel_selection_arg(), "--output"]
        return None

    def _xsel_selection_arg(self) -> str:
        return "--clipboard" if self.selection == "clipboard" else "--primary"


class PyperclipClipboardAdapter(ClipboardAdapter):

    """Описывает публичный класс PyperclipClipboardAdapter."""
    backend_name = "pyperclip"

    def __init__(self):
        import pyperclip

        self.pyperclip = pyperclip

    def copy_to_clipboard(self, data: str) -> bool:
        """Копирует to clipboard."""
        try:
            self.pyperclip.copy(data)
            return True
        except Exception as exc:
            logger.warning("pyperclip copy failed: %s", exc)
            return False

    def clear_clipboard(self) -> bool:
        """Очищает clipboard."""
        return self.copy_to_clipboard("")

    def get_clipboard_content(self) -> Optional[str]:
        """Возвращает данные для clipboard content."""
        try:
            return self.pyperclip.paste()
        except Exception as exc:
            logger.debug("pyperclip paste failed: %s", exc)
            return None


class InMemoryClipboardAdapter(ClipboardAdapter):

    """Описывает публичный класс InMemoryClipboardAdapter."""
    backend_name = "in-memory"

    def __init__(self):
        self.content = ""

    def copy_to_clipboard(self, data: str) -> bool:
        """Копирует to clipboard."""
        self.content = data
        return True

    def clear_clipboard(self) -> bool:
        """Очищает clipboard."""
        self.content = ""
        return True

    def get_clipboard_content(self) -> Optional[str]:
        """Возвращает данные для clipboard content."""
        return self.content


def get_default_clipboard_adapter() -> ClipboardAdapter:
    """Возвращает данные для default clipboard adapter."""
    system = platform.system()
    adapter_classes = []

    if system == "Windows":
        adapter_classes.append(WindowsClipboardAdapter)
    elif system == "Darwin":
        adapter_classes.append(MacOSClipboardAdapter)
    elif system == "Linux":
        adapter_classes.append(LinuxClipboardAdapter)

    adapter_classes.append(PyperclipClipboardAdapter)

    for adapter_class in adapter_classes:
        try:
            return adapter_class()
        except Exception as exc:
            logger.info("Clipboard adapter %s unavailable: %s", adapter_class.__name__, exc)

    logger.warning("Falling back to in-memory clipboard adapter")
    return InMemoryClipboardAdapter()

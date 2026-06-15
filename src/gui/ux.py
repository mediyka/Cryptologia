from dataclasses import dataclass
from typing import Iterable, Iterator, Sequence, TypeVar

import tkinter as tk
from tkinter import ttk

T = TypeVar("T")


COMMON_SHORTCUTS = {
    "add_entry": "<Control-n>",
    "edit_entry": "<Control-e>",
    "delete_entry": "<Delete>",
    "copy_username": "<Control-u>",
    "copy_password": "<Control-c>",
    "toggle_password": "<Control-Shift-P>",
    "search": "<Control-f>",
    "lock": "<Control-l>",
    "settings": "<Control-comma>",
}


SECURITY_STATE_COLORS = {
    "locked": "#ef4444",
    "unlocked": "#22c55e",
    "warning": "#f59e0b",
    "neutral": "#94a3b8",
}

THEMES = {
    "light": {
        "background": "#eef2f7",
        "surface": "#ffffff",
        "surface_alt": "#f8fafc",
        "sidebar": "#111827",
        "sidebar_text": "#e5e7eb",
        "hero": "#0f172a",
        "hero_text": "#f8fafc",
        "accent": "#2563eb",
        "accent_hover": "#1d4ed8",
        "danger": "#dc2626",
        "danger_hover": "#b91c1c",
        "text": "#111827",
        "muted": "#64748b",
        "field": "#ffffff",
        "border": "#d5dbe7",
        "selection": "#2563eb",
        "selection_text": "#ffffff",
        "success": "#16a34a",
        "warning": "#d97706",
    },
    "dark": {
        "background": "#0b1020",
        "surface": "#121a2b",
        "surface_alt": "#172033",
        "sidebar": "#090e1a",
        "sidebar_text": "#e5e7eb",
        "hero": "#111827",
        "hero_text": "#f8fafc",
        "accent": "#38bdf8",
        "accent_hover": "#0ea5e9",
        "danger": "#fb7185",
        "danger_hover": "#f43f5e",
        "text": "#e5e7eb",
        "muted": "#94a3b8",
        "field": "#0f172a",
        "border": "#334155",
        "selection": "#2563eb",
        "selection_text": "#ffffff",
        "success": "#22c55e",
        "warning": "#fbbf24",
    },
}



@dataclass(frozen=True)
class UserMessage:
    """Описывает публичный класс UserMessage."""
    title: str
    body: str
    suggestion: str = ""

    def format(self) -> str:
        """Описывает публичное действие format."""
        return f"{self.body}\n\n{self.suggestion}" if self.suggestion else self.body


class ToolTip:
    """Небольшая Tk-подсказка с метаданными для средств доступности."""

    def __init__(self, widget, text: str, delay_ms: int = 500):
        self.widget = widget
        self.text = text
        self.delay_ms = delay_ms
        self._after_id = None
        self._tip = None
        self._set_accessible_metadata(widget, text)
        widget.bind("<Enter>", self._schedule, add="+")
        widget.bind("<Leave>", self.hide, add="+")
        widget.bind("<FocusIn>", self._schedule, add="+")
        widget.bind("<FocusOut>", self.hide, add="+")

    def _schedule(self, event=None):
        self.hide()
        self._after_id = self.widget.after(self.delay_ms, self.show)

    def show(self):
        """Описывает публичное действие show."""
        if self._tip or not self.text:
            return
        x = self.widget.winfo_rootx() + 12
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 8
        self._tip = tk.Toplevel(self.widget)
        self._tip.wm_overrideredirect(True)
        self._tip.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            self._tip,
            text=self.text,
            justify=tk.LEFT,
            relief=tk.SOLID,
            borderwidth=1,
            padx=6,
            pady=3,
        )
        label.pack()

    def hide(self, event=None):
        """Описывает публичное действие hide."""
        if self._after_id:
            self.widget.after_cancel(self._after_id)
            self._after_id = None
        if self._tip:
            self._tip.destroy()
            self._tip = None

    @staticmethod
    def _set_accessible_metadata(widget, text: str):
        try:
            widget.configure(takefocus=True)
        except tk.TclError:
            pass
        setattr(widget, "accessible_name", text)


def security_state_color(state: str) -> str:
    """Описывает публичную операцию security state color."""
    return SECURITY_STATE_COLORS.get(state, SECURITY_STATE_COLORS["neutral"])


def normalize_theme(theme: str) -> str:
    """Описывает публичную операцию normalize theme."""
    value = str(theme or "light").strip().lower()
    if value in {"тёмная", "темная", "dark"}:
        return "dark"
    if value in {"светлая", "light"}:
        return "light"
    return "light"


def apply_theme(root, theme: str):
    """Применяет theme."""
    theme_name = normalize_theme(theme)
    palette = THEMES[theme_name]
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    root.configure(background=palette["background"])
    style.configure(".", background=palette["background"], foreground=palette["text"])
    style.configure("TFrame", background=palette["background"])
    style.configure("TLabelframe", background=palette["background"], foreground=palette["text"])
    style.configure("TLabelframe.Label", background=palette["background"], foreground=palette["text"])
    style.configure("TLabel", background=palette["background"], foreground=palette["text"])
    style.configure("TButton", background=palette["surface"], foreground=palette["text"])
    style.map(
        "TButton",
        background=[("active", palette["border"]), ("pressed", palette["border"])],
        foreground=[("disabled", palette["muted"])],
    )
    style.configure("TCheckbutton", background=palette["background"], foreground=palette["text"])
    style.configure("TRadiobutton", background=palette["background"], foreground=palette["text"])
    style.configure(
        "TEntry",
        background=palette["field"],
        fieldbackground=palette["field"],
        foreground=palette["text"],
        insertcolor=palette["text"],
    )
    style.configure(
        "TSpinbox",
        background=palette["field"],
        fieldbackground=palette["field"],
        foreground=palette["text"],
        arrowcolor=palette["text"],
    )
    style.map(
        "TSpinbox",
        fieldbackground=[("readonly", palette["field"]), ("disabled", palette["field"])],
        foreground=[("readonly", palette["text"]), ("disabled", palette["muted"])],
    )
    style.configure(
        "TCombobox",
        background=palette["field"],
        fieldbackground=palette["field"],
        foreground=palette["text"],
        arrowcolor=palette["text"],
        selectbackground=palette["selection"],
        selectforeground=palette["selection_text"],
    )
    style.map(
        "TCombobox",
        background=[("readonly", palette["field"]), ("disabled", palette["field"])],
        fieldbackground=[("readonly", palette["field"]), ("disabled", palette["field"])],
        foreground=[("readonly", palette["text"]), ("disabled", palette["muted"])],
        selectbackground=[("readonly", palette["field"])],
        selectforeground=[("readonly", palette["text"])],
        arrowcolor=[("readonly", palette["text"]), ("disabled", palette["muted"])],
    )
    root.option_add("*TCombobox*Listbox.background", palette["field"])
    root.option_add("*TCombobox*Listbox.foreground", palette["text"])
    root.option_add("*TCombobox*Listbox.selectBackground", palette["selection"])
    root.option_add("*TCombobox*Listbox.selectForeground", palette["selection_text"])
    style.configure("TNotebook", background=palette["background"])
    style.configure("TNotebook.Tab", background=palette["surface"], foreground=palette["text"])
    style.map(
        "TNotebook.Tab",
        background=[("selected", palette["background"]), ("active", palette["border"])],
        foreground=[("selected", palette["text"])],
    )
    style.configure("Treeview", background=palette["surface"], fieldbackground=palette["surface"], foreground=palette["text"])
    style.configure("Treeview.Heading", background=palette["background"], foreground=palette["text"])
    style.map(
        "Treeview",
        background=[("selected", palette["selection"])],
        foreground=[("selected", palette["selection_text"])],
    )
    style.configure("App.TFrame", background=palette["background"])
    style.configure("Hero.TFrame", background=palette["hero"])
    style.configure("Sidebar.TFrame", background=palette["sidebar"])
    style.configure("Card.TFrame", background=palette["surface"], relief="flat")
    style.configure("CardAlt.TFrame", background=palette["surface_alt"], relief="flat")
    style.configure("Toolbar.TFrame", background=palette["surface"])
    style.configure("StatusBar.TFrame", background=palette["surface_alt"])
    style.configure("HeroTitle.TLabel", background=palette["hero"], foreground=palette["hero_text"], font=("Segoe UI", 20, "bold"))
    style.configure("HeroSubtitle.TLabel", background=palette["hero"], foreground=palette["muted"], font=("Segoe UI", 10))
    style.configure("SidebarTitle.TLabel", background=palette["sidebar"], foreground=palette["sidebar_text"], font=("Segoe UI", 12, "bold"))
    style.configure("SidebarMuted.TLabel", background=palette["sidebar"], foreground="#9ca3af", font=("Segoe UI", 9))
    style.configure("KPIValue.TLabel", background=palette["sidebar"], foreground=palette["sidebar_text"], font=("Segoe UI", 18, "bold"))
    style.configure("KPILabel.TLabel", background=palette["sidebar"], foreground="#9ca3af", font=("Segoe UI", 9))
    style.configure("CardTitle.TLabel", background=palette["surface"], foreground=palette["text"], font=("Segoe UI", 12, "bold"))
    style.configure("Muted.TLabel", background=palette["surface"], foreground=palette["muted"], font=("Segoe UI", 9))
    style.configure("StatusMuted.TLabel", background=palette["surface_alt"], foreground=palette["muted"], font=("Segoe UI", 9))
    style.configure("Primary.TButton", background=palette["accent"], foreground="#ffffff", padding=(12, 7), font=("Segoe UI", 9, "bold"))
    style.map("Primary.TButton", background=[("active", palette["accent_hover"]), ("pressed", palette["accent_hover"])], foreground=[("disabled", palette["muted"])])
    style.configure("Danger.TButton", background=palette["danger"], foreground="#ffffff", padding=(12, 7), font=("Segoe UI", 9, "bold"))
    style.map("Danger.TButton", background=[("active", palette["danger_hover"]), ("pressed", palette["danger_hover"])], foreground=[("disabled", palette["muted"])])
    style.configure("Ghost.TButton", background=palette["surface_alt"], foreground=palette["text"], padding=(10, 7))
    style.map("Ghost.TButton", background=[("active", palette["border"]), ("pressed", palette["border"])])
    style.configure("SecurityLocked.TLabel", background=palette["background"], foreground=SECURITY_STATE_COLORS["locked"], font=("Segoe UI", 9, "bold"))
    style.configure("SecurityUnlocked.TLabel", background=palette["background"], foreground=SECURITY_STATE_COLORS["unlocked"], font=("Segoe UI", 9, "bold"))
    style.configure("SecurityWarning.TLabel", background=palette["background"], foreground=SECURITY_STATE_COLORS["warning"], font=("Segoe UI", 9, "bold"))
    _apply_theme_to_children(root, palette)


def _apply_theme_to_children(widget, palette: dict):
    for child in widget.winfo_children():
        if isinstance(child, tk.Menu):
            continue
        options = {}
        for option, value in (("background", palette["background"]), ("foreground", palette["text"])):
            try:
                child.cget(option)
                options[option] = value
            except tk.TclError:
                pass
        if isinstance(child, tk.Canvas):
            options["background"] = palette["background"]
        if isinstance(child, (tk.Entry, tk.Text, tk.Listbox, tk.Spinbox)):
            options["background"] = palette["field"]
            options["foreground"] = palette["text"]
            options["insertbackground"] = palette["text"]
        if options:
            try:
                child.configure(**options)
            except tk.TclError:
                pass
        _apply_theme_to_children(child, palette)


def batched(items: Sequence[T], batch_size: int) -> Iterator[Sequence[T]]:
    """Описывает публичную операцию batched."""
    size = max(1, int(batch_size or 1))
    for index in range(0, len(items), size):
        yield items[index : index + size]


ERROR_TRANSLATIONS = {
    "Clipboard could not be cleared automatically. Clear it manually.": "Не удалось автоматически очистить буфер обмена. Очистите его вручную.",
    "Clipboard copy failed; platform backend did not accept the data.": "Не удалось скопировать данные: системный буфер обмена не принял данные.",
    "Vault must be unlocked before clipboard operations.": "Перед операциями с буфером обмена нужно разблокировать хранилище.",
    "Clipboard data must be text.": "Данные буфера обмена должны быть текстом.",
    "Clipboard data must not be empty.": "Данные буфера обмена не должны быть пустыми.",
    "Operation interrupted by panic mode.": "Операция прервана режимом паники.",
    "Plaintext export requires allow_plaintext=True.": "Экспорт в открытом виде требует явного подтверждения.",
    "Encrypted export requires encryption_password or recipient_public_key.": "Для зашифрованного экспорта нужен пароль экспорта или публичный ключ получателя.",
    "encryption_strength must be 128 or 256": "Стойкость шифрования должна быть 128 или 256 бит.",
    "ECC public-key export requires AES-256-GCM.": "Экспорт по ECC-ключу требует AES-256-GCM.",
    "ECC public-key export requires a P-256 recipient key.": "Для ECC-экспорта нужен ключ получателя P-256.",
    "Unsupported or unknown import format.": "Неподдерживаемый или неизвестный формат импорта.",
    "Encrypted JSON import requires encryption_password.": "Для импорта зашифрованного JSON нужен пароль.",
    "Payload integrity hash mismatch.": "Контрольная сумма данных не совпадает.",
    "Native export payload does not contain entries.": "Файл экспорта не содержит записей.",
    "Unsupported key derivation.": "Неподдерживаемый способ получения ключа.",
    "Invalid PBKDF2 iteration count.": "Некорректное количество итераций PBKDF2.",
    "PBKDF2 iteration count is below policy.": "Количество итераций PBKDF2 ниже политики безопасности.",
    "Public-key encrypted import requires private_key_pem.": "Для импорта, зашифрованного публичным ключом, нужен приватный ключ.",
    "ECC export requires an elliptic curve private key.": "Для ECC-экспорта нужен приватный ключ эллиптической кривой.",
    "RSA export requires an RSA private key.": "Для RSA-экспорта нужен RSA-приватный ключ.",
    "Export package signature verification failed.": "Не удалось проверить подпись пакета экспорта.",
    "JSON import must contain an entries/items list.": "JSON для импорта должен содержать список entries или items.",
    "Bitwarden JSON must contain items.": "JSON Bitwarden должен содержать список items.",
    "Bitwarden encrypted JSON import requires encryption_password.": "Для импорта зашифрованного JSON Bitwarden нужен пароль.",
    "Bitwarden encrypted JSON must be an object.": "Зашифрованный JSON Bitwarden должен быть объектом.",
    "Bitwarden encrypted JSON must be password-protected.": "Зашифрованный JSON Bitwarden должен быть защищен паролем.",
    "Bitwarden encrypted JSON password or integrity check failed.": "Пароль Bitwarden неверный или проверка целостности не пройдена.",
    "Bitwarden encrypted JSON padding validation failed.": "Проверка padding в зашифрованном JSON Bitwarden не пройдена.",
    "CSV import requires a header row.": "CSV-файл должен содержать строку заголовков.",
    "entry must be an object": "Запись должна быть объектом.",
    "title is required": "Название обязательно.",
    "password is required": "Пароль обязателен.",
    "Duplicate entries detected.": "Обнаружены дубликаты записей.",
    "Import checkpoint is corrupted.": "Контрольная точка импорта повреждена.",
    "Import checkpoint belongs to a different source file.": "Контрольная точка импорта относится к другому файлу.",
    "Database connection is required for replace import.": "Для импорта с заменой требуется подключение к базе данных.",
    "Import processing timed out.": "Время обработки импорта истекло.",
    "JSON root must be an object or list.": "Корень JSON должен быть объектом или списком.",
    "mode must be one of: dry-run, merge, replace": "Режим должен быть одним из: dry-run, merge, replace.",
    "duplicate_policy must be one of: skip, update, rename, error": "Политика дубликатов должна быть одной из: skip, update, rename, error.",
    "timeout_seconds must be positive": "Таймаут должен быть положительным.",
    "QR payload decompression failed.": "Не удалось распаковать QR-данные.",
    "QR payload checksum mismatch.": "Контрольная сумма QR-данных не совпадает.",
    "QR payload JSON is invalid.": "QR-данные содержат некорректный JSON.",
    "QR payload must be an object.": "QR-данные должны быть объектом.",
    "Unsupported QR payload version.": "Неподдерживаемая версия QR-данных.",
    "Unsupported QR payload type.": "Неподдерживаемый тип QR-данных.",
    "QR payload has expired.": "Срок действия QR-данных истек.",
    "QR payload replay detected.": "Обнаружена повторная отправка QR-данных.",
    "QR image scanning requires Pillow and pyzbar.": "Для сканирования QR-изображений нужны Pillow и pyzbar.",
    "Camera scanning requires OpenCV and an available camera.": "Для сканирования камерой нужен OpenCV и доступная камера.",
    "Unsupported share encryption method.": "Неподдерживаемый метод шифрования обмена.",
    "Share method must be 'password' or 'public_key'.": "Метод обмена должен быть password или public_key.",
    "Share expiration must be between 1 and 30 days.": "Срок действия обмена должен быть от 1 до 30 дней.",
    "Password-based sharing requires password.": "Для обмена по паролю нужен пароль.",
    "Public-key sharing requires recipient_public_key.": "Для обмена по публичному ключу нужен ключ получателя.",
    "ECIES sharing requires an ECC P-256 recipient key.": "Для ECIES-обмена нужен ECC P-256 ключ получателя.",
    "ECC share requires an elliptic curve private key.": "Для ECC-обмена нужен приватный ключ эллиптической кривой.",
    "RSA share requires an RSA private key.": "Для RSA-обмена нужен RSA-приватный ключ.",
    "Shared package signature verification failed.": "Не удалось проверить подпись пакета обмена.",
    "QR payload TTL must be positive.": "Срок действия QR-данных должен быть положительным.",
    "Secure allocation size must be non-negative": "Размер защищенного выделения памяти не может быть отрицательным.",
    "Key must be bytes-like.": "Ключ должен быть байтовым значением.",
    "RSA key_size must be at least 2048 bits": "Размер RSA-ключа должен быть не менее 2048 бит.",
    "Export requires master password confirmation.": "Экспорт требует подтверждения мастер-пароля.",
    "Decryption failed: authentication tag invalid. Data may be tampered.": "Не удалось расшифровать данные: проверка подлинности не пройдена. Возможно, данные были изменены.",
}


def translate_error_text(error) -> str:
    """Описывает публичную операцию translate error text."""
    text = str(error).strip()
    if not text:
        return "Неизвестная ошибка."
    if text in ERROR_TRANSLATIONS:
        return ERROR_TRANSLATIONS[text]

    translated = text
    replacements = {
        "Clipboard error": "Ошибка буфера обмена",
        "unknown": "неизвестно",
        "Unsupported clipboard data type": "Неподдерживаемый тип данных буфера обмена",
        "Unsupported export format": "Неподдерживаемый формат экспорта",
        "Unsupported export frequency": "Неподдерживаемая периодичность экспорта",
        "Invalid JSON": "Некорректный JSON",
        "must be base64 text": "должно быть текстом base64",
        "is not valid base64": "не является корректным base64",
        "is malformed": "имеет некорректный формат",
        "is too long": "слишком длинное",
        "must be a scalar text field": "должно быть простым текстовым полем",
        "requires": "требует",
        "required": "обязательно",
        "failed": "не выполнено",
        "invalid": "некорректно",
    }
    for source, target in replacements.items():
        translated = translated.replace(source, target)
    return translated


def friendly_error_message(error: Exception, context: str = "operation") -> UserMessage:
    """Описывает публичную операцию friendly error message."""
    text = str(error).strip()
    lowered = text.lower()
    if "database" in lowered or "sqlite" in lowered or "locked" in lowered:
        return UserMessage(
            "Данные хранилища временно недоступны",
            f"CryptoSafe не смог выполнить операцию: база занята или недоступна.",
            "Закройте другие окна CryptoSafe и попробуйте снова. Если ошибка повторяется, перезапустите приложение.",
        )
    if "permission" in lowered or "access" in lowered or "denied" in lowered:
        return UserMessage(
            "Недостаточно прав",
            "CryptoSafe не хватает прав для выполнения операции.",
            "Выберите папку с правами на запись или запустите приложение от учетной записи с нужными правами.",
        )
    if "password" in lowered or "authentication" in lowered or "decrypt" in lowered:
        return UserMessage(
            "Требуется подтверждение доступа",
            "CryptoSafe не смог проверить доступ к защищенным данным.",
            "Проверьте мастер-пароль и попробуйте снова.",
        )
    return UserMessage(
        "Действие не выполнено",
        translate_error_text(error),
        "Попробуйте снова. Технические подробности записаны в журнал приложения.",
    )

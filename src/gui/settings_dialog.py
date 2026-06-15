import tkinter as tk
from tkinter import ttk, messagebox

from core.config import CLIPBOARD_PRESETS, SECURITY_PROFILES
from gui.ux import translate_error_text

CLIPBOARD_PROFILE_LABELS = {
    "Standard": "Стандартный",
    "Secure": "Безопасный",
    "Public Computer": "Публичный компьютер",
}
SECURITY_PROFILE_LABELS = {
    "Standard": "Стандартный",
    "Enhanced": "Усиленный",
    "Paranoid": "Параноидальный",
}
SECURITY_LEVEL_LABELS = {
    "basic": "Базовый",
    "advanced": "Расширенный",
    "paranoid": "Параноидальный",
}
SENSITIVITY_LABELS = {
    "low": "Низкая",
    "medium": "Средняя",
    "high": "Высокая",
}
THEME_LABELS = {
    "light": "Светлая",
    "dark": "Тёмная",
}
PANIC_HOTKEY = "Ctrl+Alt+P"


class SettingsDialog(tk.Toplevel):
    """Окно настроек безопасности, буфера обмена и внешнего вида."""
    def __init__(self, parent):
        super().__init__(parent)
        self.parent = parent
        self.config_manager = parent.app_config
        self._initial_security_profile = self.config_manager.get("security_profile", "Standard")
        self.title("Настройки")
        self.geometry("560x520")
        self.minsize(500, 420)

        self._build_variables()
        self.create_widgets()

        self.transient(parent)
        self.grab_set()

    def _build_variables(self):
        settings = self.config_manager.get_clipboard_settings()
        self.profile_var = tk.StringVar(value=self._label(CLIPBOARD_PROFILE_LABELS, settings["profile"]))
        self.timeout_var = tk.IntVar(value=max(5, min(300, int(settings["timeout"]))))
        self.never_clear_var = tk.BooleanVar(value=not settings["auto_clear"])
        self.monitor_var = tk.BooleanVar(value=settings["monitor_enabled"])
        self.block_var = tk.BooleanVar(value=settings["block_on_suspicious"])
        self.security_level_var = tk.StringVar(value=self._label(SECURITY_LEVEL_LABELS, settings["security_level"]))
        self.notify_copy_var = tk.BooleanVar(value=settings["notify_on_copy"])
        self.notify_clear_var = tk.BooleanVar(value=settings["notify_on_clear"])
        self.notify_warning_var = tk.BooleanVar(value=settings["notify_on_warning"])
        self.whitelist_var = tk.StringVar(value=", ".join(settings["allowed_applications"]))
        self.security_profile_var = tk.StringVar(
            value=self._label(SECURITY_PROFILE_LABELS, self.config_manager.get("security_profile", "Standard"))
        )
        self.auto_lock_var = tk.IntVar(
            value=max(1, min(480, self.config_manager.get_int("activity_lock_timeout_seconds", 300) // 60))
        )
        self.activity_sensitivity_var = tk.StringVar(
            value=self._label(SENSITIVITY_LABELS, self.config_manager.get("activity_sensitivity", "medium"))
        )
        self.tray_enabled_var = tk.BooleanVar(value=self.config_manager.get_bool("tray_enabled", True))
        self.minimize_to_tray_var = tk.BooleanVar(value=self.config_manager.get_bool("minimize_to_tray", True))
        self.start_minimized_var = tk.BooleanVar(value=self.config_manager.get_bool("start_minimized_to_tray", False))
        self.panic_enabled_var = tk.BooleanVar(value=self.config_manager.get_bool("panic_mode_enabled", True))
        self.panic_mouse_gesture_var = tk.BooleanVar(
            value=self.config_manager.get_bool("panic_mouse_gesture_enabled", False)
        )
        self.panic_close_app_var = tk.BooleanVar(value=self.config_manager.get_bool("panic_close_application", False))
        self.panic_stealth_var = tk.BooleanVar(value=self.config_manager.get_bool("panic_stealth_mode", False))
        self.panic_fake_error_var = tk.BooleanVar(value=self.config_manager.get_bool("panic_show_fake_error", False))
        self.panic_hotkey_var = tk.StringVar(value=PANIC_HOTKEY)
        self.theme_var = tk.StringVar(value=self._label(THEME_LABELS, self.config_manager.get("theme", "light")))

    def create_widgets(self):
        """Создает widgets."""
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        security_tab, security_content = self._create_scrollable_tab(notebook)
        notebook.add(security_tab, text="Безопасность")
        self._create_clipboard_settings(security_content)

        appearance_tab = ttk.Frame(notebook, padding=10)
        notebook.add(appearance_tab, text="Внешний вид")
        ttk.Label(appearance_tab, text="Тема:").pack(anchor=tk.W)
        ttk.Combobox(
            appearance_tab,
            textvariable=self.theme_var,
            values=[THEME_LABELS[key] for key in ("light", "dark")],
            state="readonly",
        ).pack(anchor=tk.W, fill=tk.X, pady=5)

        footer = ttk.Frame(self)
        footer.pack(fill=tk.X, padx=10, pady=(0, 10))
        ttk.Button(footer, text="Сохранить", command=self.save).pack(side=tk.RIGHT, padx=4)
        ttk.Button(footer, text="Закрыть", command=self.destroy).pack(side=tk.RIGHT, padx=4)

    def _create_scrollable_tab(self, notebook):
        container = ttk.Frame(notebook)
        canvas = tk.Canvas(container, highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient=tk.VERTICAL, command=canvas.yview)
        content = ttk.Frame(canvas, padding=10)
        window_id = canvas.create_window((0, 0), window=content, anchor=tk.NW)

        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        def update_scroll_region(_event=None):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def update_content_width(event):
            canvas.itemconfigure(window_id, width=event.width)

        def on_mousewheel(event):
            delta = -1 if event.delta > 0 else 1
            canvas.yview_scroll(delta * 3, "units")

        content.bind("<Configure>", update_scroll_region)
        canvas.bind("<Configure>", update_content_width)
        canvas.bind("<Enter>", lambda _event: canvas.bind_all("<MouseWheel>", on_mousewheel))
        canvas.bind("<Leave>", lambda _event: canvas.unbind_all("<MouseWheel>"))
        return container, content

    def _create_clipboard_settings(self, parent):
        ttk.Label(parent, text="Профиль буфера обмена:").pack(anchor=tk.W)
        profile_combo = ttk.Combobox(
            parent,
            textvariable=self.profile_var,
            values=[self._label(CLIPBOARD_PROFILE_LABELS, key) for key in CLIPBOARD_PRESETS],
            state="readonly",
        )
        profile_combo.pack(anchor=tk.W, fill=tk.X, pady=(2, 8))
        profile_combo.bind("<<ComboboxSelected>>", lambda event: self._apply_profile_to_form())

        ttk.Label(parent, text="Таймаут автоочистки (сек):").pack(anchor=tk.W)
        timeout_spin = ttk.Spinbox(parent, from_=5, to=300, textvariable=self.timeout_var)
        timeout_spin.pack(anchor=tk.W, pady=(2, 4))
        ttk.Checkbutton(parent, text="Никогда не очищать автоматически", variable=self.never_clear_var).pack(anchor=tk.W)

        ttk.Label(parent, text="Уровень защиты:").pack(anchor=tk.W, pady=(10, 0))
        ttk.Combobox(
            parent,
            textvariable=self.security_level_var,
            values=[SECURITY_LEVEL_LABELS[key] for key in ("basic", "advanced", "paranoid")],
            state="readonly",
        ).pack(anchor=tk.W, fill=tk.X, pady=(2, 8))

        ttk.Checkbutton(parent, text="Включить мониторинг буфера обмена", variable=self.monitor_var).pack(anchor=tk.W)
        ttk.Checkbutton(parent, text="Блокировать копирование при подозрительной активности", variable=self.block_var).pack(anchor=tk.W)

        notification_box = ttk.LabelFrame(parent, text="Уведомления", padding=8)
        notification_box.pack(fill=tk.X, pady=10)
        ttk.Checkbutton(notification_box, text="При копировании", variable=self.notify_copy_var).pack(anchor=tk.W)
        ttk.Checkbutton(notification_box, text="При очистке", variable=self.notify_clear_var).pack(anchor=tk.W)
        ttk.Checkbutton(notification_box, text="При предупреждениях", variable=self.notify_warning_var).pack(anchor=tk.W)

        ttk.Label(parent, text="Разрешённые приложения (через запятую):").pack(anchor=tk.W)
        ttk.Entry(parent, textvariable=self.whitelist_var).pack(fill=tk.X, pady=(2, 8))

        ttk.Label(parent, text="Авто-блокировка приложения (мин):").pack(anchor=tk.W)
        ttk.Spinbox(parent, from_=1, to=480, textvariable=self.auto_lock_var).pack(anchor=tk.W, pady=(2, 8))

        ttk.Label(parent, text="Профиль безопасности:").pack(anchor=tk.W)
        ttk.Combobox(
            parent,
            textvariable=self.security_profile_var,
            values=[self._label(SECURITY_PROFILE_LABELS, key) for key in SECURITY_PROFILES],
            state="readonly",
        ).pack(anchor=tk.W, fill=tk.X, pady=(2, 8))

        ttk.Label(parent, text="Чувствительность к активности:").pack(anchor=tk.W)
        ttk.Combobox(
            parent,
            textvariable=self.activity_sensitivity_var,
            values=[SENSITIVITY_LABELS[key] for key in ("low", "medium", "high")],
            state="readonly",
        ).pack(anchor=tk.W, fill=tk.X, pady=(2, 0))

        tray_box = ttk.LabelFrame(parent, text="Системный трей", padding=8)
        tray_box.pack(fill=tk.X, pady=10)
        ttk.Checkbutton(tray_box, text="Включить интеграцию с треем", variable=self.tray_enabled_var).pack(anchor=tk.W)
        ttk.Checkbutton(tray_box, text="Сворачивать в трей", variable=self.minimize_to_tray_var).pack(anchor=tk.W)
        ttk.Checkbutton(tray_box, text="Запускать свернутым в трей", variable=self.start_minimized_var).pack(anchor=tk.W)

        panic_box = ttk.LabelFrame(parent, text="Режим паники", padding=8)
        panic_box.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(panic_box, text=f"Горячая клавиша: {PANIC_HOTKEY}").pack(anchor=tk.W, pady=(0, 8))
        ttk.Checkbutton(panic_box, text="Включить режим паники", variable=self.panic_enabled_var).pack(anchor=tk.W)
        ttk.Checkbutton(panic_box, text="Включить жест встряхивания окна", variable=self.panic_mouse_gesture_var).pack(anchor=tk.W)
        ttk.Checkbutton(panic_box, text="Закрывать приложение после паники", variable=self.panic_close_app_var).pack(anchor=tk.W)
        ttk.Checkbutton(panic_box, text="Включить скрытные действия", variable=self.panic_stealth_var).pack(anchor=tk.W)
        ttk.Checkbutton(panic_box, text="Показывать окно ложной ошибки", variable=self.panic_fake_error_var).pack(anchor=tk.W)

    def _apply_profile_to_form(self):
        preset = CLIPBOARD_PRESETS.get(self._value(CLIPBOARD_PROFILE_LABELS, self.profile_var.get()))
        if not preset:
            return
        self.timeout_var.set(preset["clipboard_timeout"])
        self.never_clear_var.set(not preset["clipboard_auto_clear"])
        self.monitor_var.set(preset["clipboard_monitor_enabled"])
        self.block_var.set(preset["clipboard_block_on_suspicious"])
        self.security_level_var.set(self._label(SECURITY_LEVEL_LABELS, preset["clipboard_security_level"]))
        self.notify_copy_var.set(preset["clipboard_notify_on_copy"])
        self.notify_clear_var.set(preset["clipboard_notify_on_clear"])
        self.notify_warning_var.set(preset["clipboard_notify_on_warning"])

    def save(self):
        """Сохраняет текущие данные или настройки."""
        timeout = max(5, min(300, int(self.timeout_var.get())))
        allowed_apps = [
            value.strip()
            for value in self.whitelist_var.get().split(",")
            if value.strip()
        ]
        auto_lock_minutes = max(1, min(480, int(self.auto_lock_var.get())))
        selected_profile = self._value(SECURITY_PROFILE_LABELS, self.security_profile_var.get())
        pending = {}

        if selected_profile != self._initial_security_profile:
            explanation = self.config_manager.explain_security_profile_change(selected_profile)
            if not messagebox.askyesno("Смена профиля безопасности", explanation + "\n\nПрименить этот профиль?", parent=self):
                return
            pending.update(SECURITY_PROFILES[selected_profile])
            pending["security_profile"] = selected_profile

        pending.update(
            {
                "clipboard_profile": self._value(CLIPBOARD_PROFILE_LABELS, self.profile_var.get()),
                "clipboard_timeout": timeout,
                "clipboard_auto_clear": not self.never_clear_var.get(),
                "clipboard_monitor_enabled": self.monitor_var.get(),
                "clipboard_block_on_suspicious": self.block_var.get(),
                "clipboard_security_level": self._value(SECURITY_LEVEL_LABELS, self.security_level_var.get()),
                "clipboard_notify_on_copy": self.notify_copy_var.get(),
                "clipboard_notify_on_clear": self.notify_clear_var.get(),
                "clipboard_notify_on_warning": self.notify_warning_var.get(),
                "clipboard_allowed_applications": allowed_apps,
                "auto_lock_timeout": auto_lock_minutes,
                "activity_lock_timeout_seconds": auto_lock_minutes * 60,
                "activity_lock_timeout_seconds_desktop": auto_lock_minutes * 60,
                "activity_lock_timeout_seconds_laptop": auto_lock_minutes * 60,
                "activity_sensitivity": self._value(SENSITIVITY_LABELS, self.activity_sensitivity_var.get()),
                "tray_enabled": self.tray_enabled_var.get(),
                "minimize_to_tray": self.minimize_to_tray_var.get(),
                "start_minimized_to_tray": self.start_minimized_var.get(),
                "panic_mode_enabled": self.panic_enabled_var.get(),
                "panic_hotkey": PANIC_HOTKEY,
                "panic_mouse_gesture_enabled": self.panic_mouse_gesture_var.get(),
                "panic_close_application": self.panic_close_app_var.get(),
                "panic_stealth_mode": self.panic_stealth_var.get(),
                "panic_show_fake_error": self.panic_fake_error_var.get(),
                "theme": self._value(THEME_LABELS, self.theme_var.get()),
            }
        )

        try:
            warnings = self.config_manager.set_many(pending, source="settings_dialog")
        except Exception as exc:
            messagebox.showerror(
                "Проверка настроек",
                f"Настройки не сохранены.\n\n{translate_error_text(exc)}\n\nИсправьте параметры и попробуйте снова.",
                parent=self,
            )
            return

        if hasattr(self.parent, "clipboard_service"):
            self.parent.clipboard_service.set_auto_clear_timeout(None if self.never_clear_var.get() else timeout)
        if hasattr(self.parent, "apply_clipboard_monitor_setting"):
            self.parent.apply_clipboard_monitor_setting()
        if hasattr(self.parent, "apply_activity_monitor_setting"):
            self.parent.apply_activity_monitor_setting()
        if hasattr(self.parent, "apply_tray_setting"):
            self.parent.apply_tray_setting()
        if hasattr(self.parent, "apply_panic_setting"):
            self.parent.apply_panic_setting()
        if hasattr(self.parent, "apply_platform_security_setting"):
            self.parent.apply_platform_security_setting()
        if hasattr(self.parent, "apply_theme_setting"):
            self.parent.apply_theme_setting()

        if warnings:
            messagebox.showwarning("Настройки сохранены с предупреждениями", "\n".join(warnings), parent=self)
        else:
            messagebox.showinfo("Настройки", "Настройки сохранены.", parent=self)
        self.destroy()

    @staticmethod
    def _label(labels: dict, value: str) -> str:
        return labels.get(value, value)

    @staticmethod
    def _value(labels: dict, label: str) -> str:
        reverse = {display: value for value, display in labels.items()}
        return reverse.get(label, label)

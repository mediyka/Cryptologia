import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import os
import logging
import subprocess
import sys
import threading
import time
import webbrowser
from datetime import datetime, timezone

from .widgets.secure_table import SecureTable
from .widgets.audit_log_viewer import AuditLogViewer
from .widgets.search_widget import SearchWidget
from .settings_dialog import SettingsDialog
from .setup_wizard import SetupWizard
from .dialogs.login_dialog import LoginDialog
from .dialogs.change_password_dialog import ChangePasswordDialog
from .dialogs.entry_dialog import EntryDialog
from .dialogs.export_dialog import ExportDialog
from .dialogs.import_dialog import ImportDialog
from .dialogs.sharing_dialog import SharingDialog
from .tray_manager import TrayManager
from .ux import COMMON_SHORTCUTS, ToolTip, apply_theme, friendly_error_message, security_state_color, translate_error_text

from core.config import ConfigManager
from core.state_manager import state_manager
from core.events import event_bus
from core.audit import AuditManager
from database.db import DatabaseHelper
from core.key_manager import KeyManager
from core.vault.entry_manager import EntryManager
from core.vault.encryption_service import AES256GCMService
from core.vault.password_generator import PasswordStrength
from core.clipboard import ClipboardMonitor, ClipboardService
from core.security import ActivityMonitor, PanicMode, PlatformSecurityManager

logger = logging.getLogger("MainWindow")


class MainWindow(tk.Tk):
    """Главное окно с таблицей записей и действиями хранилища."""
    def __init__(self, config: ConfigManager, defer_startup: bool = False):
        super().__init__()
        self.title("CryptoSafeManager · Secure Vault")
        self.geometry("1320x780")
        self.minsize(1120, 680)

        self.app_config = config
        self.db = None
        self.audit = None
        self.key_manager = None
        self.encryption_service = None
        self.entry_manager = None
        self.clipboard_service = ClipboardService(config=self.app_config, state=state_manager)
        self.clipboard_monitor = None
        self.activity_monitor = ActivityMonitor(
            self._schedule_auto_lock,
            config=self.app_config.get_security_settings(),
            is_locked_callback=lambda: state_manager.is_locked,
        )
        self.panic_mode = PanicMode(config=self.app_config.get_security_settings())
        self.panic_mode.register_handler(self._schedule_panic_response)
        self.platform_security = PlatformSecurityManager(config=self.app_config.get_security_settings())
        self.platform_security.detect_capabilities()
        self.tray_manager = TrayManager(
            self,
            self.app_config,
            lock_callback=lambda: self.lock_application("tray"),
            unlock_callback=self.show_window_from_tray,
            show_callback=self.show_window_from_tray,
            quick_search_callback=self.quick_search_from_tray,
            clear_clipboard_callback=lambda: self.clipboard_service.clear_clipboard("tray"),
            panic_callback=lambda: self.activate_panic_mode("tray"),
            settings_callback=self.show_settings,
            exit_callback=self.exit_application,
        )
        self._clipboard_warning_shown = False
        self._lock_in_progress = False
        self._hidden_to_tray = False
        self._loading_entries = False
        self._last_entries_snapshot = []
        self._window_shake_after_id = None
        self._window_shake_stop = threading.Event()
        self._window_shake_thread = None
        self._last_window_position = None
        self._panic_hotkey_bindings = []
        self._closing = False
        self._pending_after_ids = set()
        apply_theme(self, self.app_config.get("theme", "dark"))

        self.create_app_header()
        self.create_body_shell()
        self.create_toolbar()
        self.create_search_area()
        self.create_main_area()
        self.create_menu()
        self.create_status_bar()
        self.refresh_dashboard_metrics()
        self.setup_clipboard_ui()
        self.setup_tray()
        self.after(250, self.start_window_shake_watcher)

        if not defer_startup:
            self.after(100, self.startup_sequence)

        self.auto_lock_check_interval = 60000
        self.after(self.auto_lock_check_interval, self.check_inactivity)

        self.bind("<Unmap>", self.on_minimize_event)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def startup_sequence(self):
        """Описывает публичное действие startup sequence."""
        db_path = self.app_config.db_path
        if not os.path.exists(db_path):
            self.run_setup_wizard()
        else:
            self.login_and_load()

    def run_setup_wizard(self):
        """Описывает публичное действие run setup wizard."""
        wizard = SetupWizard(self, self.app_config)
        self.wait_window(wizard)

        if wizard.completed:
            if self.initialize_new_vault(wizard.db_path, wizard.password):
                self.on_login_success()
                messagebox.showinfo("Успех", "Хранилище успешно создано!", parent=self)
            else:
                messagebox.showerror("Ошибка", "Не удалось создать хранилище.", parent=self)
                self.quit()
        else:
            self.quit()

    def initialize_new_vault(self, db_path, password):
        """Описывает публичное действие initialize new vault."""
        try:
            self.db = DatabaseHelper(db_path)
            self.app_config.db_path = db_path
            self.app_config.set("db_path", db_path)
            self.app_config.attach_database(self.db)

            self.key_manager = KeyManager(self.db, self.app_config.get_security_settings())
            if not self.key_manager.setup_new_vault(password):
                return False
            self.app_config.attach_key_manager(self.key_manager)

            self.encryption_service = AES256GCMService()
            self.encryption_service.set_key_manager(self.key_manager)
            self.entry_manager = EntryManager(self.db, self.key_manager)
            return True
        except Exception as e:
            logger.error(f"Init error: {e}")
            return False

    def login_and_load(self):
        """Описывает публичное действие login and load."""
        try:
            self.db = DatabaseHelper(self.app_config.db_path)
            self.app_config.attach_database(self.db)
            self.key_manager = KeyManager(self.db, self.app_config.get_security_settings())
            self.update_security_status(True)
            self.update_status("Хранилище заблокировано")
            self._show_lock_overlay()

            login = LoginDialog(self, self.key_manager, secure_desktop=self.platform_security.should_use_secure_desktop())
            if login.success:
                self._hide_lock_overlay()
                self.app_config.attach_key_manager(self.key_manager)
                self.encryption_service = AES256GCMService()
                self.encryption_service.set_key_manager(self.key_manager)
                self.entry_manager = EntryManager(self.db, self.key_manager)
                state_manager.login("default_user")
                self.on_login_success()
            else:
                self.quit()
        except Exception as e:
            logger.error(f"Load error: {e}")
            messagebox.showerror("Ошибка", f"Не удалось открыть БД:\n{e}")
            self.quit()

    def on_login_success(self):
        """Описывает публичное действие on login success."""
        state_manager.login("default_user")
        self.clipboard_service.unblock_copies()
        if self.audit and hasattr(self.audit, "shutdown"):
            self.audit.shutdown()
        self.audit = AuditManager(self.db, key_manager=self.key_manager)
        self.update_security_status(False)
        self.update_status("Хранилище разблокировано")
        self.tray_manager.update_security_state(False)
        event_bus.publish("UserLoggedIn", data={"user": "default_user"})
        self.start_clipboard_monitor()
        self.start_activity_monitor()
        self.load_entries()

    def load_entries(self, search_query: str = "", filters=None):
        """Загружает entries."""
        try:
            if search_query:
                data = self.entry_manager.search_entries(search_query)
            else:
                data = self.entry_manager.get_all_entries(include_decrypted_password=False)

            if filters:
                data = self._apply_demo_filters(data, filters)

            self._last_entries_snapshot = list(data)
            self._load_entries_into_table(data)
            self._update_search_categories(data)
            self.refresh_dashboard_metrics()
            self.update_status(f"Загружено записей: {len(data)}")
        except Exception as e:
            logger.exception("Load entries error")
            self.show_friendly_error(e, "load entries")
            return

    def on_minimize_event(self, event):
        """Описывает публичное действие on minimize event."""
        self.record_focus_change(False)
        if event.widget is self and self.app_config.get_bool("minimize_to_tray", True):
            self.hide_to_tray()
        elif event.widget is self and self.key_manager and not state_manager.is_locked:
            self._schedule_auto_lock("minimize")

    def check_inactivity(self):
        """Описывает публичное действие check inactivity."""
        if self.key_manager and not state_manager.is_locked:
            if self.activity_monitor.should_lock():
                self._schedule_auto_lock("fallback_timer")
            else:
                self.key_manager.touch()

        self.after(self.auto_lock_check_interval, self.check_inactivity)

    def lock_application(self, reason: str = "manual"):
        """Описывает публичное действие lock application."""
        if self._lock_in_progress or state_manager.is_locked:
            return
        self._lock_in_progress = True
        logger.info("Locking application...")
        self.stop_activity_monitor()
        self.clipboard_service.clear_clipboard(reason)
        if self.key_manager:
            self.key_manager.lock()
        state_manager.logout()
        self.tray_manager.update_security_state(True)
        event_bus.publish("VaultLocked", data={"reason": reason})
        self.update_security_status(True)

        self.update_status("Хранилище заблокировано")
        self.table.load_data([])
        self._last_entries_snapshot = []
        self.refresh_dashboard_metrics()
        self._show_lock_overlay()

        login = LoginDialog(self, self.key_manager, secure_desktop=self.platform_security.should_use_secure_desktop())
        if login.success:
            self._hide_lock_overlay()
            state_manager.login("default_user")
            event_bus.publish("VaultUnlocked", data={"reason": "reauthentication"})
            self.on_login_success()
        else:
            self.on_close()
        self._lock_in_progress = False

    def on_close(self):
        """Описывает публичное действие on close."""
        if self.app_config.get_bool("minimize_to_tray", True) and self.tray_manager.state.running:
            self.hide_to_tray()
            return
        self.exit_application()

    def exit_application(self):
        """Описывает публичное действие exit application."""
        if self._closing:
            return
        self._closing = True
        logger.info("Closing application...")
        self._prepare_input_state_for_exit()
        self.stop_activity_monitor()
        if self.tray_manager:
            self.tray_manager.stop()
        if self.clipboard_monitor:
            self.clipboard_monitor.stop()
        self.stop_window_shake_watcher()
        self.clipboard_service.shutdown()
        if self.audit and hasattr(self.audit, "shutdown"):
            self.audit.shutdown()
        if self.key_manager:
            self.key_manager.lock()
        self.destroy()

    def _prepare_input_state_for_exit(self):
        for after_id in list(getattr(self, "_pending_after_ids", set())):
            try:
                self.after_cancel(after_id)
            except Exception:
                pass
        self._pending_after_ids.clear()
        for sequence in getattr(self, "_panic_hotkey_bindings", []):
            try:
                self.unbind_all(sequence)
            except Exception:
                pass
        try:
            self.unbind_all("<MouseWheel>")
        except Exception:
            pass
        try:
            grabbed = self.grab_current()
            if grabbed is not None:
                grabbed.grab_release()
        except Exception:
            pass
        self._release_windows_modifier_keys()

    def _safe_after(self, delay_ms: int, callback, *args):
        if self._closing:
            return None

        after_id = None

        def guarded_callback():
            self._pending_after_ids.discard(after_id)
            if self._closing or not self.winfo_exists():
                return
            callback(*args)

        try:
            after_id = self.after(delay_ms, guarded_callback)
            self._pending_after_ids.add(after_id)
            return after_id
        except tk.TclError:
            return None

    def _release_windows_modifier_keys(self):
        if sys.platform != "win32":
            return
        try:
            import ctypes

            keyeventf_keyup = 0x0002
            for virtual_key in (0x10, 0xA0, 0xA1, 0x11, 0xA2, 0xA3, 0x12, 0xA4, 0xA5):
                ctypes.windll.user32.keybd_event(virtual_key, 0, keyeventf_keyup, 0)
        except Exception:
            pass

    def create_app_header(self):
        """Создает современную верхнюю панель проекта."""
        self.header = ttk.Frame(self, style="Hero.TFrame", padding=(22, 16, 22, 14))
        self.header.pack(side=tk.TOP, fill=tk.X)

        title_block = ttk.Frame(self.header, style="Hero.TFrame")
        title_block.pack(side=tk.LEFT, fill=tk.X, expand=True)

        ttk.Label(title_block, text="CryptoSafeManager", style="HeroTitle.TLabel").pack(anchor=tk.W)
        ttk.Label(
            title_block,
            text="Локальный менеджер паролей · AES-256-GCM · Argon2id · SQLite · Secure Clipboard · Audit Chain",
            style="HeroSubtitle.TLabel",
        ).pack(anchor=tk.W, pady=(3, 0))

        status_block = ttk.Frame(self.header, style="Hero.TFrame")
        status_block.pack(side=tk.RIGHT)
        self.header_lock_var = tk.StringVar(value="🔒 Locked")
        self.header_db_var = tk.StringVar(value="DB: not loaded")
        ttk.Label(status_block, textvariable=self.header_lock_var, style="HeroSubtitle.TLabel").pack(anchor=tk.E)
        ttk.Label(status_block, textvariable=self.header_db_var, style="HeroSubtitle.TLabel").pack(anchor=tk.E, pady=(4, 0))

    def create_body_shell(self):
        """Создает главный двухколоночный layout: dashboard + рабочая область."""
        self.body_shell = ttk.Frame(self, style="App.TFrame", padding=(12, 12, 12, 8))
        self.body_shell.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

        self.sidebar = ttk.Frame(self.body_shell, style="Sidebar.TFrame", padding=(16, 16, 16, 16), width=260)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 12))
        self.sidebar.pack_propagate(False)

        self.content_frame = ttk.Frame(self.body_shell, style="App.TFrame")
        self.content_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self._build_sidebar()

    def _build_sidebar(self):
        """Создает левый dashboard по состоянию vault."""
        ttk.Label(self.sidebar, text="Security Dashboard", style="SidebarTitle.TLabel").pack(anchor=tk.W)
        ttk.Label(
            self.sidebar,
            text="Контроль состояния хранилища, буфера обмена",
            style="SidebarMuted.TLabel",
            wraplength=220,
            justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(4, 16))

        self.sidebar_entries_var = tk.StringVar(value="0")
        self.sidebar_entries_label_var = tk.StringVar(value="записей в vault")
        self.sidebar_state_var = tk.StringVar(value="🔒 Vault locked")
        self.sidebar_clipboard_var = tk.StringVar(value="Буфер: пусто")
        self.sidebar_action_var = tk.StringVar(value="Ожидание входа")

        self._sidebar_metric("", self.sidebar_entries_var, self.sidebar_entries_label_var)
        self._sidebar_text_card("Vault", self.sidebar_state_var)
        self._sidebar_text_card("Clipboard", self.sidebar_clipboard_var)


        ttk.Separator(self.sidebar, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=14)
        ttk.Button(self.sidebar, text="🔐 Заблокировать", style="Ghost.TButton", command=lambda: self.lock_application("sidebar")).pack(fill=tk.X, pady=(0, 8))
        ttk.Button(self.sidebar, text="⚙ Настройки", style="Ghost.TButton", command=self.show_settings).pack(fill=tk.X, pady=(0, 8))
        ttk.Button(self.sidebar, text="🧯 Режим паники", style="Danger.TButton", command=lambda: self.activate_panic_mode("sidebar")).pack(fill=tk.X)



    def _sidebar_metric(self, title: str, value_var, label_var):
        box = ttk.Frame(self.sidebar, style="Sidebar.TFrame")
        box.pack(fill=tk.X, pady=(0, 12))
        ttk.Label(box, text=title, style="SidebarMuted.TLabel").pack(anchor=tk.W)
        ttk.Label(box, textvariable=value_var, style="KPIValue.TLabel").pack(anchor=tk.W)
        ttk.Label(box, textvariable=label_var, style="KPILabel.TLabel").pack(anchor=tk.W)

    def _sidebar_text_card(self, title: str, value_var):
        box = ttk.Frame(self.sidebar, style="Sidebar.TFrame")
        box.pack(fill=tk.X, pady=(0, 12))
        ttk.Label(box, text=title, style="SidebarMuted.TLabel").pack(anchor=tk.W)
        ttk.Label(box, textvariable=value_var, style="SidebarTitle.TLabel", wraplength=220, justify=tk.LEFT).pack(anchor=tk.W, pady=(2, 0))

    def refresh_dashboard_metrics(self):
        """Обновляет видимые метрики dashboard без влияния на core-логику."""
        if hasattr(self, "sidebar_entries_var"):
            count = len(getattr(self, "_last_entries_snapshot", []) or [])
            self.sidebar_entries_var.set(str(count))
            self.sidebar_entries_label_var.set("запись" if count == 1 else "записей в vault")
        if hasattr(self, "header_db_var"):
            db_path = getattr(self.app_config, "db_path", "") or "not selected"
            self.header_db_var.set(f"DB: {os.path.basename(db_path) or db_path}")

    def create_toolbar(self):
        """Создает современную action-панель."""
        parent = getattr(self, "content_frame", self)
        toolbar_card = ttk.Frame(parent, style="Card.TFrame", padding=(12, 12, 12, 12))
        toolbar_card.pack(side=tk.TOP, fill=tk.X, pady=(0, 10))

        left = ttk.Frame(toolbar_card, style="Card.TFrame")
        left.pack(side=tk.LEFT)
        right = ttk.Frame(toolbar_card, style="Card.TFrame")
        right.pack(side=tk.RIGHT)

        ttk.Button(left, text="＋ Новая запись", style="Primary.TButton", command=self.add_entry).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(left, text="✎ Редактировать", style="Ghost.TButton", command=self.edit_selected).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(left, text="🗑 Удалить", style="Ghost.TButton", command=self.delete_selected).pack(side=tk.LEFT, padx=(0, 8))
        self.password_toggle_btn = ttk.Button(left, text="👁 Показать пароль", style="Ghost.TButton", command=self.toggle_password_visibility)
        self.password_toggle_btn.pack(side=tk.LEFT, padx=(0, 8))

        ttk.Button(right, text="Импорт", style="Ghost.TButton", command=self.show_import_dialog).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(right, text="Экспорт", style="Ghost.TButton", command=self.show_export_dialog).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(right, text="Поделиться", style="Ghost.TButton", command=self.share_selected).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(right, text="📋 Логин", style="Ghost.TButton", command=self.copy_username).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(right, text="🔑 Пароль", style="Primary.TButton", command=self.copy_password).pack(side=tk.LEFT)

        self._apply_toolbar_accessibility(toolbar_card)

    def _apply_toolbar_accessibility(self, toolbar):
        tooltips = {
            "＋ Новая запись": "Добавить запись (Ctrl+N)",
            "✎ Редактировать": "Редактировать выбранную запись (Ctrl+E)",
            "🗑 Удалить": "Удалить выбранные записи (Delete)",
            "👁 Показать пароль": "Показать или скрыть выбранные пароли (Ctrl+Shift+P)",
            "Импорт": "Импортировать данные в хранилище",
            "Экспорт": "Экспортировать данные хранилища",
            "Поделиться": "Безопасно поделиться выбранной записью",
            "📋 Логин": "Копировать логин выбранной записи (Ctrl+U)",
            "🔑 Пароль": "Копировать пароль выбранной записи (Ctrl+C)",
        }
        for child in toolbar.winfo_children():
            for button in child.winfo_children() if hasattr(child, "winfo_children") else []:
                if isinstance(button, ttk.Button):
                    ToolTip(button, tooltips.get(button.cget("text"), button.cget("text")))

    def create_search_area(self):
        """Создает search area."""
        parent = getattr(self, "content_frame", self)
        self.search_card = ttk.Frame(parent, style="Card.TFrame", padding=(12, 10, 12, 10))
        self.search_card.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(self.search_card, text="Поиск и фильтры", style="CardTitle.TLabel").pack(anchor=tk.W, pady=(0, 8))
        self.search_widget = SearchWidget(self.search_card, on_search=self.on_search)
        self.search_widget.pack(fill=tk.X)

    def on_search(self, query):
        """Описывает публичное действие on search."""
        if isinstance(query, dict):
            self.load_entries(search_query=query.get("query", ""), filters=query)
        else:
            self.load_entries(search_query=query)

    def create_main_area(self):
        """Создает центральную рабочую область с таблицей vault."""
        parent = getattr(self, "content_frame", self)
        self.table_card = ttk.Frame(parent, style="Card.TFrame", padding=(12, 12, 12, 12))
        self.table_card.pack(fill=tk.BOTH, expand=True)

        table_header = ttk.Frame(self.table_card, style="Card.TFrame")
        table_header.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(table_header, text="Vault entries", style="CardTitle.TLabel").pack(side=tk.LEFT)
        ttk.Label(table_header, text="Пароли скрыты по умолчанию · копирование через secure clipboard", style="Muted.TLabel").pack(side=tk.RIGHT)

        table_wrap = ttk.Frame(self.table_card, style="Card.TFrame")
        table_wrap.pack(fill=tk.BOTH, expand=True)
        self.table = SecureTable(table_wrap, height=18)
        self.table.pack(fill=tk.BOTH, expand=True)

        self.bind_all("<Button-1>", lambda e: self.record_user_activity("mouse"))
        self.bind_all("<Motion>", lambda e: self.record_user_activity("mouse"))
        self.bind_all("<Key>", lambda e: self.record_user_activity("keyboard"))
        self.bind_all("<FocusIn>", lambda e: self.record_focus_change(True))
        self.bind_all("<FocusOut>", lambda e: self.record_focus_change(False))
        self.bind_all("<Control-Shift-P>", lambda e: self.toggle_password_visibility())
        self._bind_panic_hotkey()
        self._bind_common_shortcuts()
        self.bind("<Configure>", self._on_window_configure)

        self.table.set_context_callback(self._on_table_action)
        self.table.set_password_reveal_callback(self._load_password_for_table)

    def _bind_common_shortcuts(self):
        bindings = {
            "add_entry": lambda event: self.add_entry(),
            "edit_entry": lambda event: self.edit_selected(),
            "delete_entry": lambda event: self.delete_selected(),
            "copy_username": lambda event: self.copy_username(),
            "copy_password": lambda event: self.copy_password(),
            "search": lambda event: self.focus_search(),
            "lock": lambda event: self.lock_application("shortcut"),
            "settings": lambda event: self.show_settings(),
        }
        for action, callback in bindings.items():
            self.bind_all(COMMON_SHORTCUTS[action], callback)

    def focus_search(self):
        """Описывает публичное действие focus search."""
        if hasattr(self.search_widget, "focus_search"):
            self.search_widget.focus_search()

    def setup_clipboard_ui(self):
        """Описывает публичное действие setup clipboard ui."""
        self.clipboard_service.add_observer(lambda status: self._safe_after(0, self._on_clipboard_status, status))
        event_bus.subscribe("ClipboardCopied", lambda event: self._safe_after(0, self._on_clipboard_copied, event.data))
        event_bus.subscribe("ClipboardCleared", lambda event: self._safe_after(0, self._on_clipboard_cleared, event.data))
        event_bus.subscribe("ClipboardWarning", lambda event: self._safe_after(0, self._on_clipboard_warning, event.data))
        event_bus.subscribe("ClipboardCopyBlockChanged", lambda event: self._safe_after(0, self._on_clipboard_block_changed, event.data))
        event_bus.subscribe("ClipboardError", lambda event: self._safe_after(0, self._on_clipboard_error, event.data))
        self._safe_after(1000, self.refresh_clipboard_status)

    def setup_tray(self):
        """Описывает публичное действие setup tray."""
        if not self.app_config.get_bool("tray_enabled", True):
            return
        self.tray_manager.start()
        self.tray_manager.update_security_state(state_manager.is_locked)
        if self.app_config.get_bool("start_minimized_to_tray", False):
            self.after(250, self.hide_to_tray)

    def apply_tray_setting(self):
        """Применяет tray setting."""
        if self.app_config.get_bool("tray_enabled", True):
            self.tray_manager.start()
            self.tray_manager.update_security_state(state_manager.is_locked)
        else:
            self.tray_manager.stop()

    def apply_panic_setting(self):
        """Применяет panic setting."""
        self.panic_mode.config = self.app_config.get_security_settings()
        self._bind_panic_hotkey()
        if self.app_config.get_bool("panic_mouse_gesture_enabled", True):
            self.start_window_shake_watcher()
        else:
            self.stop_window_shake_watcher()

    def _bind_panic_hotkey(self):
        for sequence in self._panic_hotkey_bindings:
            self.unbind_all(sequence)
        self._panic_hotkey_bindings = [self.panic_mode.hotkey_sequence()]
        for sequence in self._panic_hotkey_bindings:
            self.bind_all(sequence, self._on_panic_hotkey)

    def _on_panic_hotkey(self, event=None):
        self.activate_panic_mode("hotkey")
        return "break"

    def apply_platform_security_setting(self):
        """Применяет platform security setting."""
        self.platform_security.config = self.app_config.get_security_settings()
        self.platform_security.detect_capabilities()

    def apply_theme_setting(self):
        """Применяет theme setting."""
        apply_theme(self, self.app_config.get("theme", "light"))

    def hide_to_tray(self):
        """Скрывает to tray."""
        if self._hidden_to_tray or not self.tray_manager.state.running:
            return
        self._hidden_to_tray = True
        self.tray_manager.hide_window()
        self.tray_manager.notify("CryptoSafe Manager", "Приложение работает в фоновом режиме.")

    def show_window_from_tray(self):
        """Показывает window from tray."""
        if self.panic_mode.activated:
            self.recover_from_panic("tray")
            return
        self._hidden_to_tray = False
        self.tray_manager.show_window()

    def quick_search_from_tray(self):
        """Описывает публичное действие quick search from tray."""
        self.show_window_from_tray()
        query = simpledialog.askstring("Быстрый поиск", "Поиск в хранилище:", parent=self)
        if query is not None:
            self.load_entries(search_query=query)

    def activate_panic_mode(self, method: str = "manual"):
        """Описывает публичное действие activate panic mode."""
        if not self.panic_mode.activate(method) and not self.panic_mode.activated:
            self.update_status("Режим паники отключен в настройках")

    def recover_from_panic(self, method: str = "manual"):
        """Описывает публичное действие recover from panic."""
        self.panic_mode.recover(method)
        self._hidden_to_tray = False
        self.tray_manager.show_window()
        if self.key_manager and state_manager.is_locked:
            self._reauthenticate_after_panic()

    def _schedule_panic_response(self, method: str):
        try:
            self.after(0, lambda: self._perform_panic_response(method))
        except Exception:
            self._perform_panic_response(method)

    def _perform_panic_response(self, method: str):
        self.clipboard_service.handle_panic_mode("panic_mode")
        self.stop_activity_monitor()
        if self.key_manager:
            self.key_manager.lock()
        state_manager.logout()
        self._destroy_child_windows()
        self.table.load_data([])
        self._last_entries_snapshot = []
        self.update_security_status(True)
        self.update_status("Хранилище заблокировано режимом паники")
        self._show_lock_overlay()
        self.tray_manager.update_security_state(True)
        event_bus.publish("VaultLocked", data={"reason": "panic_mode"})
        if self.panic_mode.close_application:
            show_fake_error = self._should_show_panic_fake_error()
            self._execute_panic_stealth_actions(method, show_fake_error=False)
            delay = 500 if method == "window_shake" else 100
            self._safe_after(delay, self._finish_panic_close, show_fake_error)
        elif self.tray_manager.state.running:
            self._execute_panic_stealth_actions(method)
            self._hidden_to_tray = True
            self.withdraw()
        else:
            self._execute_panic_stealth_actions(method)

    def _reauthenticate_after_panic(self):
        self._show_lock_overlay()
        login = LoginDialog(self, self.key_manager, secure_desktop=self.platform_security.should_use_secure_desktop())
        if login.success:
            self._hide_lock_overlay()
            self.clipboard_service.unblock_copies()
            state_manager.login("default_user")
            event_bus.publish("VaultUnlocked", data={"reason": "panic_recovery"})
            self.on_login_success()
            return

        if self.tray_manager.state.running:
            self._hidden_to_tray = True
            self.withdraw()
        else:
            self.exit_application()

    def _destroy_child_windows(self):
        for child in list(self.winfo_children()):
            if isinstance(child, tk.Toplevel):
                try:
                    child.destroy()
                except Exception:
                    pass
        self._hide_lock_overlay()

    def _should_show_panic_fake_error(self) -> bool:
        return self.app_config.get_bool("panic_show_fake_error", False)

    def _finish_panic_close(self, show_fake_error: bool = False):
        if show_fake_error:
            self._show_panic_fake_error()
        self.exit_application()

    def _show_panic_fake_error(self):
        if self._closing or not self.winfo_exists():
            return
        message = self.app_config.get(
            "panic_fake_error_message",
            "The application has encountered an unexpected error.",
        )
        try:
            messagebox.showerror("Ошибка приложения", message, parent=self)
        except tk.TclError:
            pass

    def _execute_panic_stealth_actions(self, method: str, show_fake_error: bool = True):
        if show_fake_error and self.app_config.get_bool("panic_show_fake_error", False):
            self._safe_after(50, self._show_panic_fake_error)
        if not self.panic_mode.stealth_mode:
            return
        command = str(self.app_config.get("panic_decoy_command", "") or "").strip()
        if self.app_config.get_bool("panic_launch_decoy", False) and command:
            try:
                subprocess.Popen(command, shell=True)
            except Exception as exc:
                logger.warning("Failed to launch panic decoy: %s", exc)
        redirect_url = str(self.app_config.get("panic_redirect_url", "") or "").strip()
        if redirect_url:
            try:
                webbrowser.open(redirect_url)
            except Exception as exc:
                logger.warning("Failed to open panic redirect URL: %s", exc)

    def _on_window_configure(self, event):
        if event.widget is not self or state_manager.is_locked:
            return
        if self.panic_mode.record_window_position(self.winfo_x(), self.winfo_y()):
            self.activate_panic_mode("mouse_gesture")

    def start_window_shake_watcher(self):
        """Запускает window shake watcher."""
        if self._window_shake_after_id is not None:
            return
        if not self.app_config.get_bool("panic_mouse_gesture_enabled", True):
            return
        self._last_window_position = None
        self._start_native_window_shake_watcher()
        self._watch_window_shake()

    def stop_window_shake_watcher(self):
        """Останавливает window shake watcher."""
        if self._window_shake_after_id is not None:
            try:
                self.after_cancel(self._window_shake_after_id)
            except Exception:
                pass
        self._window_shake_after_id = None
        self._window_shake_stop.set()
        self._window_shake_thread = None
        self._last_window_position = None

    def _watch_window_shake(self):
        self._window_shake_after_id = None
        if not self.app_config.get_bool("panic_mouse_gesture_enabled", True):
            return
        if state_manager.is_locked or self.panic_mode.activated:
            self._last_window_position = None
            self._window_shake_after_id = self.after(30, self._watch_window_shake)
            return

        position = (self.winfo_rootx(), self.winfo_rooty())
        if position != self._last_window_position:
            self._last_window_position = position
            if self.panic_mode.record_window_position(position[0], position[1]):
                self.activate_panic_mode("window_shake")
                return

        self._window_shake_after_id = self.after(30, self._watch_window_shake)

    def _start_native_window_shake_watcher(self):
        if sys.platform != "win32" or self._window_shake_thread is not None:
            return
        hwnd = self._get_native_window_handle()
        if not hwnd:
            self.after(300, self._start_native_window_shake_watcher)
            return
        self._window_shake_stop.clear()
        self._window_shake_thread = threading.Thread(
            target=self._watch_native_window_shake,
            args=(hwnd,),
            name="CryptoSafeNativeWindowShake",
            daemon=True,
        )
        self._window_shake_thread.start()

    def _get_native_window_handle(self) -> int:
        candidates = []
        try:
            candidates.append(self.frame())
        except Exception:
            pass
        try:
            candidates.append(self.winfo_id())
        except Exception:
            pass

        for candidate in candidates:
            try:
                hwnd = int(str(candidate), 0)
            except (TypeError, ValueError):
                continue
            if hwnd:
                try:
                    import ctypes

                    root_hwnd = ctypes.windll.user32.GetAncestor(hwnd, 2)
                    return root_hwnd or hwnd
                except Exception:
                    return hwnd
        return 0

    def _watch_native_window_shake(self, hwnd: int):
        try:
            import ctypes
            from ctypes import wintypes

            class RECT(ctypes.Structure):
                _fields_ = [
                    ("left", wintypes.LONG),
                    ("top", wintypes.LONG),
                    ("right", wintypes.LONG),
                    ("bottom", wintypes.LONG),
                ]

            user32 = ctypes.windll.user32
            rect = RECT()
            last_position = None
            while not self._window_shake_stop.wait(0.03):
                if state_manager.is_locked or self.panic_mode.activated:
                    last_position = None
                    continue
                if not user32.GetWindowRect(hwnd, ctypes.byref(rect)):
                    break
                position = (int(rect.left), int(rect.top))
                if position == last_position:
                    continue
                last_position = position
                if self.panic_mode.record_window_position(position[0], position[1]):
                    try:
                        self.after(0, lambda: self.activate_panic_mode("window_shake"))
                    except Exception:
                        pass
                    break
                time.sleep(0.01)
        finally:
            self._window_shake_thread = None

    def start_clipboard_monitor(self):
        """Запускает clipboard monitor."""
        if self.clipboard_monitor or not self.app_config.get("clipboard_monitor_enabled", True):
            return
        self.clipboard_monitor = ClipboardMonitor(self.clipboard_service)
        self.clipboard_monitor.start()

    def apply_clipboard_monitor_setting(self):
        """Применяет clipboard monitor setting."""
        enabled = self.app_config.get_bool("clipboard_monitor_enabled", True)
        if enabled:
            self.start_clipboard_monitor()
        elif self.clipboard_monitor:
            self.clipboard_monitor.stop()
            self.clipboard_monitor = None

    def start_activity_monitor(self):
        """Запускает activity monitor."""
        self.activity_monitor.update_config(self.app_config.get_security_settings())
        self.activity_monitor.start_monitoring()

    def stop_activity_monitor(self):
        """Останавливает activity monitor."""
        self.activity_monitor.stop_monitoring()

    def apply_activity_monitor_setting(self):
        """Применяет activity monitor setting."""
        self.activity_monitor.update_config(self.app_config.get_security_settings())
        if not state_manager.is_locked:
            self.start_activity_monitor()

    def record_user_activity(self, source: str = "application"):
        """Описывает публичное действие record user activity."""
        state_manager.update_activity()
        if source == "keyboard":
            self.activity_monitor.record_keyboard_activity()
        elif source == "mouse":
            self.activity_monitor.record_mouse_activity()
        else:
            self.activity_monitor.record_activity(source)

    def record_focus_change(self, focused: bool):
        """Описывает публичное действие record focus change."""
        self.activity_monitor.record_focus_change(focused)

    def _schedule_auto_lock(self, reason: str = "inactivity"):
        try:
            self.after(0, lambda: self.lock_application(reason))
        except Exception as exc:
            logger.error("Failed to schedule auto-lock: %s", exc)

    def _show_lock_overlay(self):
        if getattr(self, "_lock_overlay", None):
            return
        overlay = tk.Frame(self, background="#d6d8dc", borderwidth=1, relief=tk.SOLID)
        overlay.place(relx=0, rely=0, relwidth=1, relheight=1)
        overlay.lift()

        card = tk.Frame(overlay, background="#eef0f2", borderwidth=1, relief=tk.SOLID)
        card.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        ttk.Label(card, text="Хранилище заблокировано", font=("Segoe UI", 14, "bold")).pack(
            padx=36,
            pady=(24, 6),
        )
        ttk.Label(card, text="Для продолжения требуется мастер-пароль.").pack(padx=36, pady=(0, 24))
        self._lock_overlay = overlay

    def _hide_lock_overlay(self):
        overlay = getattr(self, "_lock_overlay", None)
        if overlay:
            try:
                overlay.destroy()
            except Exception:
                pass
        self._lock_overlay = None

    def _apply_demo_filters(self, entries, filters):
        """Применить дополнительные GUI-фильтры к уже найденным записям."""
        category = (filters.get("category") or "").strip()
        tag = (filters.get("tag") or "").strip().lower()
        start_date = self._parse_iso_datetime(filters.get("start_date"))
        end_date = self._parse_iso_datetime(filters.get("end_date"))
        min_strength = filters.get("min_strength")

        results = []
        for entry in entries:
            if category and entry.get("category", "") != category:
                continue

            if tag:
                entry_tags = [str(item).lower() for item in entry.get("tags", [])]
                if tag not in entry_tags:
                    continue

            if start_date or end_date:
                entry_dt = self._parse_iso_datetime(entry.get("updated_at"))
                if entry_dt is None:
                    continue
                if start_date and entry_dt < start_date:
                    continue
                if end_date and entry_dt > end_date:
                    continue

            if min_strength is not None:
                score = PasswordStrength.calculate(entry.get("password", ""))
                if score < min_strength:
                    continue

            results.append(entry)

        return results

    def _update_search_categories(self, entries):
        categories = sorted({
            entry.get("category", "").strip()
            for entry in entries
            if entry.get("category", "").strip()
        })
        self.search_widget.set_categories(categories)

    @staticmethod
    def _parse_iso_datetime(value):
        """Парсинг даты для демо-фильтрации."""
        if not value:
            return None

        text = str(value).strip()
        if not text:
            return None

        if len(text) == 10:
            text = f"{text}T00:00:00+00:00"
        elif len(text) == 16 and "T" in text:
            text = f"{text}:00+00:00"
        elif len(text) == 19 and "T" in text:
            text = f"{text}+00:00"

        normalized = text.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(normalized)
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def create_menu(self):
        """Создает menu."""
        menubar = tk.Menu(self)

        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(label="Импорт...", command=self.show_import_dialog)
        file_menu.add_command(label="Экспорт...", command=self.show_export_dialog)
        file_menu.add_separator()
        file_menu.add_command(label="Заблокировать", command=self.lock_application)
        file_menu.add_command(label="Режим паники", command=lambda: self.activate_panic_mode("menu"))
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.exit_application)
        menubar.add_cascade(label="Файл", menu=file_menu)

        edit_menu = tk.Menu(menubar, tearoff=0)
        edit_menu.add_command(label="Добавить запись", command=self.add_entry)
        edit_menu.add_command(label="Редактировать", command=self.edit_selected)
        edit_menu.add_command(label="Удалить", command=self.delete_selected)
        edit_menu.add_separator()
        edit_menu.add_command(label="Сменить мастер-пароль", command=self.show_change_password)
        menubar.add_cascade(label="Правка", menu=edit_menu)

        view_menu = tk.Menu(menubar, tearoff=0)
        view_menu.add_command(label="Логи аудита", command=self.show_audit_window)
        view_menu.add_command(label="Настройки", command=self.show_settings)
        menubar.add_cascade(label="Вид", menu=view_menu)

        help_menu = tk.Menu(menubar, tearoff=0)
        help_menu.add_command(label="О программе", command=self.show_about)
        menubar.add_cascade(label="Справка", menu=help_menu)

        self.config(menu=menubar)

    def create_status_bar(self):
        """Создает status bar."""
        style = ttk.Style(self)
        style.configure("SecurityLocked.TLabel", foreground=security_state_color("locked"))
        style.configure("SecurityUnlocked.TLabel", foreground=security_state_color("unlocked"))
        style.configure("SecurityWarning.TLabel", foreground=security_state_color("warning"))
        self.status_bar = ttk.Frame(self, style="StatusBar.TFrame", padding=(12, 6, 12, 6))
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_label = ttk.Label(self.status_bar, text="Готово", style="StatusMuted.TLabel")
        self.status_label.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.clipboard_label = ttk.Label(self.status_bar, text="Буфер: --", style="StatusMuted.TLabel")
        self.clipboard_label.pack(side=tk.RIGHT, fill=tk.X, padx=(12, 0))
        self.clipboard_label.bind("<Button-1>", lambda event: self.show_clipboard_preview())
        self.progress = ttk.Progressbar(self.status_bar, mode="indeterminate", length=96)

    def update_security_status(self, locked: bool):
        """Обновляет security status."""
        if hasattr(self, "header_lock_var"):
            self.header_lock_var.set("🔒 Locked" if locked else "🟢 Unlocked")
        if hasattr(self, "sidebar_state_var"):
            self.sidebar_state_var.set("🔒 Vault locked" if locked else "🟢 Vault unlocked")
        if not hasattr(self, "status_label"):
            return
        if locked:
            self.status_label.configure(text="Status: locked", style="SecurityLocked.TLabel")
        else:
            self.status_label.configure(text="Status: unlocked", style="SecurityUnlocked.TLabel")

    def show_progress(self, message: str):
        """Показывает progress."""
        self._loading_entries = True
        self.update_status(message)
        if hasattr(self, "progress") and not self.progress.winfo_ismapped():
            self.progress.pack(side=tk.LEFT, padx=(6, 0))
            self.progress.start(12)

    def hide_progress(self):
        """Скрывает progress."""
        self._loading_entries = False
        if hasattr(self, "progress") and self.progress.winfo_ismapped():
            self.progress.stop()
            self.progress.pack_forget()

    def _load_entries_into_table(self, data):
        if len(data) < 250:
            self.table.load_data(data)
            self.hide_progress()
            return

        self.show_progress(f"Loading {len(data)} entries...")
        self.table.load_data_incremental(
            data,
            batch_size=100,
            schedule=self.after,
            on_done=lambda total: (self.hide_progress(), self.update_status(f"Entries: {total}")),
        )

    def show_friendly_error(self, error: Exception, context: str):
        """Показывает friendly error."""
        message = friendly_error_message(error, context)
        self.update_status(message.title)
        messagebox.showerror(message.title, message.format(), parent=self)

    def add_entry(self):
        """Добавляет entry."""
        EntryDialog(self, on_save=self._on_entry_save)

    def edit_selected(self):
        """Описывает публичное действие edit selected."""
        selected = self.table.get_selected_entries()
        if not selected:
            messagebox.showinfo("Информация", "Выберите запись для редактирования")
            return

        self._open_entry_editor(selected[0])

    def delete_selected(self):
        """Удаляет selected."""
        selected = self.table.get_selected_entries()
        if not selected:
            messagebox.showinfo("Информация", "Выберите записи для удаления")
            return

        count = len(selected)
        if messagebox.askyesno("Подтверждение", f"Удалить {count} записей в корзину?"):
            for entry in selected:
                try:
                    self.entry_manager.delete_entry(entry["id"], soft_delete=True)
                except Exception as e:
                    logger.error(f"Delete error for {entry.get('id')}: {e}")

            self.load_entries()
            messagebox.showinfo("Успех", f"Удалено {count} записей")

    def copy_password(self):
        """Копирует password."""
        selected = self.table.get_selected_entries()
        if not selected:
            messagebox.showinfo("Информация", "Выберите запись")
            return

        self.copy_entry_field(selected[0], "password")

    def copy_username(self):
        """Копирует username."""
        selected = self.table.get_selected_entries()
        if not selected:
            messagebox.showinfo("Информация", "Выберите запись")
            return

        self.copy_entry_field(selected[0], "username")

    def copy_entry_field(self, entry: dict, field_name: str):
        """Копирует entry field."""
        entry_id = entry.get("id")
        if not entry_id:
            self.show_clipboard_toast(f"Нет данных для копирования: {field_name}", warning=True)
            return

        try:
            self.clipboard_service.copy_entry_field(self.entry_manager, entry_id, field_name)
        except Exception as e:
            logger.error(f"Clipboard copy error: {e}")
            messagebox.showerror("Буфер обмена", f"Не удалось скопировать данные:\n{translate_error_text(e)}", parent=self)

    def _load_password_for_table(self, entry_id: str) -> str:
        if not self.entry_manager or not entry_id:
            return ""
        try:
            entry = self.entry_manager.get_entry(entry_id)
            return entry.get("password", "") if entry else ""
        except Exception as e:
            logger.error(f"Password reveal error for {entry_id}: {e}")
            messagebox.showerror("Пароль", f"Не удалось показать пароль:\n{translate_error_text(e)}", parent=self)
            return ""

    def _open_entry_editor(self, entry: dict):
        entry_id = entry.get("id")
        if not entry_id:
            messagebox.showerror("Редактирование", "Не удалось определить выбранную запись.", parent=self)
            return

        try:
            full_entry = self.entry_manager.get_entry(entry_id)
        except Exception as e:
            logger.error(f"Entry load for edit failed for {entry_id}: {e}")
            messagebox.showerror("Редактирование", f"Не удалось загрузить запись:\n{translate_error_text(e)}", parent=self)
            return

        if not full_entry:
            messagebox.showerror("Редактирование", "Запись не найдена.", parent=self)
            return

        EntryDialog(self, entry_data=full_entry, on_save=lambda data: self._on_entry_save(data, entry_id))

    def copy_entry_all(self, entry: dict):
        """Копирует entry all."""
        entry_id = entry.get("id")
        if not entry_id:
            self.show_clipboard_toast("Нет данных для копирования", warning=True)
            return

        try:
            self.clipboard_service.copy_entry_summary(self.entry_manager, entry_id)
        except Exception as e:
            logger.error(f"Clipboard copy all error: {e}")
            messagebox.showerror("Буфер обмена", f"Не удалось скопировать запись:\n{translate_error_text(e)}", parent=self)

    def _on_entry_save(self, data: dict, entry_id: str = None):
        try:
            if entry_id:
                self.entry_manager.update_entry(entry_id, data)
                messagebox.showinfo("Успех", "Запись обновлена")
            else:
                self.entry_manager.create_entry(data)
                messagebox.showinfo("Успех", "Запись создана")

            self.load_entries()
        except Exception as e:
            logger.error(f"Save error: {e}")
            messagebox.showerror("Ошибка", f"Не удалось сохранить запись:\n{translate_error_text(e)}")

    def _on_table_action(self, action: str, entry: dict):
        if action == "open":
            self._open_entry_editor(entry)
        elif action == "edit":
            self._open_entry_editor(entry)
        elif action == "copy_password":
            self.copy_entry_field(entry, "password")
        elif action == "copy_username":
            self.copy_entry_field(entry, "username")
        elif action == "copy_all":
            self.copy_entry_all(entry)
        elif action == "share":
            self.show_sharing_dialog(entry.get("id"))
        elif action == "delete":
            if messagebox.askyesno("Подтверждение", f"Удалить '{entry.get('title')}'?"):
                self.entry_manager.delete_entry(entry["id"], soft_delete=True)
                self.load_entries()
        elif action == "permanent_delete":
            if messagebox.askyesno("Подтверждение", f"Удалить '{entry.get('title')}' НАВСЕГДА?"):
                self.entry_manager.delete_entry(entry["id"], soft_delete=False)
                self.load_entries()

    def show_change_password(self):
        """Показывает change password."""
        ChangePasswordDialog(self, self.key_manager, self.entry_manager, self.encryption_service)

    def show_export_dialog(self):
        """Показывает export dialog."""
        if not self.entry_manager:
            messagebox.showinfo("Экспорт", "Сначала разблокируйте хранилище.", parent=self)
            return
        ExportDialog(self, self.entry_manager, selected_entry_ids=self.table.get_selected_ids())

    def show_import_dialog(self):
        """Показывает import dialog."""
        if not self.entry_manager:
            messagebox.showinfo("Импорт", "Сначала разблокируйте хранилище.", parent=self)
            return
        ImportDialog(self, self.entry_manager, on_import_complete=self.load_entries)

    def share_selected(self):
        """Описывает публичное действие share selected."""
        selected = self.table.get_selected_entries()
        if not selected:
            messagebox.showinfo("Обмен", "Выберите запись, которой нужно поделиться.", parent=self)
            return
        self.show_sharing_dialog(selected[0].get("id"))

    def show_sharing_dialog(self, entry_id: str):
        """Показывает sharing dialog."""
        if not entry_id:
            messagebox.showinfo("Обмен", "Не удалось определить выбранную запись.", parent=self)
            return
        SharingDialog(self, self.entry_manager, entry_id)

    def show_settings(self):
        """Показывает settings."""
        SettingsDialog(self)

    def show_audit_window(self):
        """Показывает audit window."""
        win = tk.Toplevel(self)
        win.title("Журнал аудита")
        win.geometry("1100x720")
        viewer = AuditLogViewer(
            win,
            db=self.db,
            audit_manager=self.audit,
            key_manager=self.key_manager,
            on_entry_select=self.highlight_entry_from_audit,
        )
        viewer.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

    def highlight_entry_from_audit(self, entry_id: str):
        """Описывает публичное действие highlight entry from audit."""
        if not entry_id:
            return
        if entry_id not in self.table.get_children():
            self.load_entries()
        if entry_id in self.table.get_children():
            self.table.selection_set(entry_id)
            self.table.focus(entry_id)
            self.table.see(entry_id)
            self.update_status(f"Аудит: выделена запись {entry_id}")
        else:
            messagebox.showinfo("Журнал аудита", f"Запись {entry_id} не найдена в текущем хранилище.", parent=self)

    def show_about(self):
        """Показывает about."""
        messagebox.showinfo(
            "О программе",
            "CryptoSafe Manager\n"
            "Состояние проекта: Sprint 8\n\n"
            "• AES-256-GCM шифрование записей\n"
            "• Управление хранилищем и мастер-паролем\n"
            "• Безопасный буфер обмена с автоочисткой\n"
            "• Импорт, экспорт и безопасный обмен\n"
            "• Журнал аудита и проверка целостности\n"
            "• Автоблокировка, системный трей и режим паники\n"
            "• Финальная сборка, тестовый отчет и документация",
        )

    def toggle_password_visibility(self):
        """GUI-3: Переключить видимость у выбранных записей."""
        self.table.toggle_password_visibility()

    def update_status(self, message: str):
        """Обновляет status и dashboard."""
        if hasattr(self, "status_label"):
            self.status_label.config(text=message)
        if hasattr(self, "sidebar_action_var"):
            self.sidebar_action_var.set(str(message)[:80])

    def refresh_clipboard_status(self):
        """Описывает публичное действие refresh clipboard status."""
        if self._closing or not self.winfo_exists():
            return
        self._on_clipboard_status(self.clipboard_service.get_clipboard_status())
        self._safe_after(1000, self.refresh_clipboard_status)

    def _on_clipboard_status(self, status):
        if self._closing or not self.winfo_exists():
            return
        self.tray_manager.update_clipboard_status(status)
        if status.active:
            remaining = "never" if status.remaining_seconds <= 0 else f"{int(status.remaining_seconds)}s"
            clipboard_text = f"Буфер: {status.data_type} {status.preview} ({remaining})"
            self.clipboard_label.config(text=clipboard_text)
            if hasattr(self, "sidebar_clipboard_var"):
                self.sidebar_clipboard_var.set(clipboard_text)
            self.table.set_clipboard_entry(status.source_entry_id)
            if 0 < status.remaining_seconds <= 5 and not self._clipboard_warning_shown:
                self._clipboard_warning_shown = True
                self.show_clipboard_toast("Буфер обмена скоро будет очищен", warning=True)
        else:
            self._clipboard_warning_shown = False
            self.clipboard_label.config(text="Буфер: --")
            if hasattr(self, "sidebar_clipboard_var"):
                self.sidebar_clipboard_var.set("Буфер: пусто")
            self.table.set_clipboard_entry(None)

    def _on_clipboard_copied(self, data):
        if self._closing or not self.winfo_exists():
            return
        if not self.app_config.get_bool("clipboard_notify_on_copy", True):
            return
        self.show_clipboard_toast(f"Скопировано: {data.get('data_type', 'text')}")

    def _on_clipboard_cleared(self, data):
        if self._closing or not self.winfo_exists():
            return
        if not self.app_config.get_bool("clipboard_notify_on_clear", True):
            return
        reason = data.get("reason", "unknown") if data else "unknown"
        self.show_clipboard_toast(f"Буфер очищен ({reason})")

    def _on_clipboard_warning(self, data):
        if self._closing or not self.winfo_exists():
            return
        if not self.app_config.get_bool("clipboard_notify_on_warning", True):
            return
        message = data.get("message", "Подозрительная активность буфера обмена") if data else "Подозрительная активность буфера обмена"
        self.show_clipboard_toast(message, warning=True)

    def _on_clipboard_block_changed(self, data):
        if self._closing or not self.winfo_exists():
            return
        if data and data.get("blocked"):
            self.show_clipboard_toast("Копирование заблокировано из-за подозрительной активности", warning=True)
        else:
            self.show_clipboard_toast("Копирование снова разрешено")

    def _on_clipboard_error(self, data):
        if self._closing or not self.winfo_exists():
            return
        reason = data.get("reason", "unknown") if data else "unknown"
        message = data.get("message") if data else ""
        if data and data.get("manual_clear_required"):
            message = message or "Не удалось автоматически очистить буфер обмена. Очистите его вручную."
        self.show_clipboard_toast(translate_error_text(message or f"Ошибка буфера обмена: {reason}"), warning=True)

    def show_clipboard_toast(self, message: str, warning: bool = False):
        """Показывает clipboard toast."""
        if self._closing or not self.winfo_exists():
            return
        self.clipboard_label.config(text=message)
        toast = tk.Toplevel(self)
        toast.title("Буфер обмена")
        toast.transient(self)
        toast.resizable(False, False)
        frame = ttk.Frame(toast, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frame, text=message, foreground="#8a5a00" if warning else "#1f6f43").pack()
        toast.update_idletasks()
        x = self.winfo_rootx() + max(0, self.winfo_width() - toast.winfo_width() - 24)
        y = self.winfo_rooty() + max(0, self.winfo_height() - toast.winfo_height() - 64)
        toast.geometry(f"+{x}+{y}")
        toast.after(2500, toast.destroy)

    def show_clipboard_preview(self):
        """Показывает clipboard preview."""
        status = self.clipboard_service.get_clipboard_status()
        if not status.active:
            messagebox.showinfo("Буфер обмена", "Буфер обмена пуст.", parent=self)
            return

        win = tk.Toplevel(self)
        win.title("Буфер обмена")
        win.transient(self)
        win.resizable(False, False)
        frame = ttk.Frame(win, padding=12)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text=f"Тип: {status.data_type}").pack(anchor=tk.W)
        ttk.Label(frame, text=f"Источник: {status.source_entry_id or '--'}").pack(anchor=tk.W, pady=(4, 0))
        preview_var = tk.StringVar(value=f"Предпросмотр: {status.preview}")
        ttk.Label(frame, textvariable=preview_var).pack(anchor=tk.W, pady=(4, 10))

        def reveal():
            try:
                value = self.clipboard_service.reveal_current_content(self._authenticate_for_clipboard_reveal)
                if value is not None:
                    preview_var.set(f"Полное значение: {value}")
            except Exception as e:
                messagebox.showerror("Буфер обмена", translate_error_text(e), parent=win)

        buttons = ttk.Frame(frame)
        buttons.pack(fill=tk.X)
        ttk.Button(buttons, text="Показать", command=reveal).pack(side=tk.LEFT)
        ttk.Button(buttons, text="Закрыть", command=win.destroy).pack(side=tk.RIGHT)

    def _authenticate_for_clipboard_reveal(self) -> bool:
        if not self.key_manager:
            return False
        password = simpledialog.askstring("Аутентификация", "Введите мастер-пароль:", show="*", parent=self)
        if not password:
            return False
        try:
            return self.key_manager.unlock(password)
        except Exception as e:
            logger.warning(f"Clipboard reveal authentication failed: {e}")
            return False

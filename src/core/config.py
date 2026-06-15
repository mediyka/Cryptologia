import base64
import json
import logging
import os
from typing import Any, Optional, TYPE_CHECKING

from core.events import event_bus

if TYPE_CHECKING:
    from src.core.key_manager import KeyManager
    from src.database.db import DatabaseHelper

logger = logging.getLogger("ConfigManager")

CLIPBOARD_PRESETS = {
    "Standard": {
        "clipboard_timeout": 30,
        "clipboard_auto_clear": True,
        "clipboard_monitor_enabled": True,
        "clipboard_block_on_suspicious": False,
        "clipboard_security_level": "basic",
        "clipboard_notify_on_copy": True,
        "clipboard_notify_on_clear": True,
        "clipboard_notify_on_warning": True,
    },
    "Secure": {
        "clipboard_timeout": 15,
        "clipboard_auto_clear": True,
        "clipboard_monitor_enabled": True,
        "clipboard_block_on_suspicious": True,
        "clipboard_security_level": "advanced",
        "clipboard_notify_on_copy": True,
        "clipboard_notify_on_clear": True,
        "clipboard_notify_on_warning": True,
    },
    "Public Computer": {
        "clipboard_timeout": 5,
        "clipboard_auto_clear": True,
        "clipboard_monitor_enabled": True,
        "clipboard_block_on_suspicious": True,
        "clipboard_security_level": "paranoid",
        "clipboard_notify_on_copy": True,
        "clipboard_notify_on_clear": True,
        "clipboard_notify_on_warning": True,
    },
}

SECURITY_PROFILES = {
    "Standard": {
        "side_channel_protection_enabled": True,
        "cache_timing_protection": True,
        "normalize_crypto_timing": True,
        "random_crypto_delay": False,
        "memory_protection_enabled": True,
        "memory_lock_enabled": True,
        "memory_wipe_passes": 1,
        "memory_guard_pages_enabled": True,
        "memory_canary_enabled": True,
        "activity_lock_timeout_seconds": 300,
        "activity_lock_timeout_seconds_desktop": 300,
        "activity_lock_timeout_seconds_laptop": 300,
        "activity_sensitivity": "medium",
        "panic_mode_enabled": True,
        "panic_hotkey": "Ctrl+Alt+P",
        "panic_close_application": False,
        "panic_stealth_mode": False,
        "panic_show_fake_error": False,
        "panic_fake_error_message": "The application has encountered an unexpected error.",
        "panic_launch_decoy": False,
        "panic_decoy_command": "",
        "panic_redirect_url": "",
        "panic_mouse_gesture_enabled": False,
        "platform_secure_storage_enabled": True,
        "windows_credential_guard_enabled": True,
        "windows_hello_enabled": False,
        "windows_secure_desktop_enabled": True,
        "macos_keychain_enabled": True,
        "macos_touch_id_enabled": False,
        "macos_gatekeeper_check_enabled": True,
        "linux_kernel_keyring_enabled": True,
        "linux_systemd_integration_enabled": True,
        "linux_lsm_policy_enabled": True,
    },
    "Enhanced": {
        "side_channel_protection_enabled": True,
        "cache_timing_protection": True,
        "normalize_crypto_timing": True,
        "random_crypto_delay": False,
        "memory_protection_enabled": True,
        "memory_lock_enabled": True,
        "memory_wipe_passes": 2,
        "memory_guard_pages_enabled": True,
        "memory_canary_enabled": True,
        "activity_lock_timeout_seconds": 180,
        "activity_lock_timeout_seconds_desktop": 180,
        "activity_lock_timeout_seconds_laptop": 120,
        "activity_sensitivity": "high",
        "panic_mode_enabled": True,
        "panic_hotkey": "Ctrl+Alt+P",
        "panic_close_application": False,
        "panic_stealth_mode": False,
        "panic_show_fake_error": False,
        "panic_fake_error_message": "The application has encountered an unexpected error.",
        "panic_launch_decoy": False,
        "panic_decoy_command": "",
        "panic_redirect_url": "",
        "panic_mouse_gesture_enabled": True,
        "platform_secure_storage_enabled": True,
        "windows_credential_guard_enabled": True,
        "windows_hello_enabled": False,
        "windows_secure_desktop_enabled": True,
        "macos_keychain_enabled": True,
        "macos_touch_id_enabled": False,
        "macos_gatekeeper_check_enabled": True,
        "linux_kernel_keyring_enabled": True,
        "linux_systemd_integration_enabled": True,
        "linux_lsm_policy_enabled": True,
    },
    "Paranoid": {
        "side_channel_protection_enabled": True,
        "cache_timing_protection": True,
        "normalize_crypto_timing": True,
        "random_crypto_delay": True,
        "random_delay_min_ms": 1,
        "random_delay_max_ms": 5,
        "memory_protection_enabled": True,
        "memory_lock_enabled": True,
        "memory_wipe_passes": 3,
        "memory_guard_pages_enabled": True,
        "memory_canary_enabled": True,
        "activity_lock_timeout_seconds": 60,
        "activity_lock_timeout_seconds_desktop": 60,
        "activity_lock_timeout_seconds_laptop": 60,
        "activity_sensitivity": "high",
        "panic_mode_enabled": True,
        "panic_hotkey": "Ctrl+Alt+P",
        "panic_close_application": False,
        "panic_stealth_mode": True,
        "panic_show_fake_error": True,
        "panic_fake_error_message": "The application has encountered an unexpected error.",
        "panic_launch_decoy": False,
        "panic_decoy_command": "",
        "panic_redirect_url": "",
        "panic_mouse_gesture_enabled": True,
        "platform_secure_storage_enabled": True,
        "windows_credential_guard_enabled": True,
        "windows_hello_enabled": False,
        "windows_secure_desktop_enabled": True,
        "macos_keychain_enabled": True,
        "macos_touch_id_enabled": False,
        "macos_gatekeeper_check_enabled": True,
        "linux_kernel_keyring_enabled": True,
        "linux_systemd_integration_enabled": True,
        "linux_lsm_policy_enabled": True,
    },
}

ENCRYPTED_SETTING_PREFIXES = ("clipboard_",)
SECURITY_PROFILE_DESCRIPTIONS = {
    "Standard": "Баланс безопасности и удобства.",
    "Enhanced": "Дополнительная защита с умеренным влиянием на удобство.",
    "Paranoid": "Максимальная защита с минимальным удобством.",
}
SECURITY_PROFILE_KEYS = tuple(next(iter(SECURITY_PROFILES.values())).keys())
SECURITY_SETTING_LABELS = {
    "side_channel_protection_enabled": "Защита от атак по сторонним каналам",
    "cache_timing_protection": "Защита от cache-timing атак",
    "normalize_crypto_timing": "Нормализация времени криптоопераций",
    "random_crypto_delay": "Случайная задержка криптоопераций",
    "random_delay_min_ms": "Минимальная случайная задержка",
    "random_delay_max_ms": "Максимальная случайная задержка",
    "memory_protection_enabled": "Защита памяти",
    "memory_lock_enabled": "Блокировка памяти",
    "memory_wipe_passes": "Проходы очистки памяти",
    "memory_guard_pages_enabled": "Защитные страницы памяти",
    "memory_canary_enabled": "Проверочные маркеры памяти",
    "activity_lock_timeout_seconds": "Таймаут автоблокировки",
    "activity_lock_timeout_seconds_desktop": "Таймаут автоблокировки для ПК",
    "activity_lock_timeout_seconds_laptop": "Таймаут автоблокировки для ноутбука",
    "activity_sensitivity": "Чувствительность к активности",
    "panic_mode_enabled": "Режим паники",
    "panic_hotkey": "Горячая клавиша режима паники",
    "panic_close_application": "Закрытие приложения при панике",
    "panic_stealth_mode": "Скрытный режим паники",
    "panic_show_fake_error": "Ложная ошибка при панике",
    "panic_launch_decoy": "Запуск маскирующего приложения",
    "panic_redirect_url": "Переход по маскирующей ссылке",
    "panic_mouse_gesture_enabled": "Жест встряхивания окна",
    "platform_secure_storage_enabled": "Защищенное хранилище платформы",
    "windows_credential_guard_enabled": "Windows Credential Guard",
    "windows_hello_enabled": "Windows Hello",
    "windows_secure_desktop_enabled": "Windows Secure Desktop",
    "macos_keychain_enabled": "macOS Keychain Services",
    "macos_touch_id_enabled": "macOS Touch ID",
    "macos_gatekeeper_check_enabled": "macOS Gatekeeper checks",
    "linux_kernel_keyring_enabled": "Linux kernel keyring",
    "linux_systemd_integration_enabled": "Linux systemd integration",
    "linux_lsm_policy_enabled": "Linux SELinux/AppArmor policy",
}


class ConfigManager:
    """Управляет настройками приложения и профилями безопасности."""
    def __init__(self, profile: str = "default"):
        self.profile = profile
        self.config_dir = os.path.join(os.path.expanduser("~"), ".cryptosafe")
        self.config_file = os.path.join(self.config_dir, f"config_{profile}.json")
        self._db_helper: Optional["DatabaseHelper"] = None
        self._key_manager: Optional["KeyManager"] = None

        self._ensure_config_dir()
        self.settings = self._default_settings()
        self._load_meta_config()

    def _ensure_config_dir(self):
        os.makedirs(self.config_dir, exist_ok=True)

    def _default_settings(self) -> dict:
        settings = {
            "clipboard_timeout": 30,
            "clipboard_auto_clear": True,
            "clipboard_monitor_enabled": True,
            "clipboard_block_on_suspicious": False,
            "clipboard_security_level": "basic",
            "clipboard_notify_on_copy": True,
            "clipboard_notify_on_clear": True,
            "clipboard_notify_on_warning": True,
            "clipboard_allowed_applications": [],
            "clipboard_profile": "Standard",
            "auto_lock_timeout": 5,
            "theme": "dark",
            "security_profile": "Standard",
            "side_channel_max_compare_bytes": 4096,
            "side_channel_max_search_bytes": 16384,
            "random_delay_min_ms": 0,
            "random_delay_max_ms": 0,
            "activity_device_profile": "desktop",
            "tray_enabled": True,
            "minimize_to_tray": True,
            "start_minimized_to_tray": False,
        }
        settings.update(SECURITY_PROFILES["Standard"])
        return settings

    def _load_meta_config(self):
        if os.path.exists(self.config_file):
            with open(self.config_file, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.db_path = data.get("db_path", os.path.join(self.config_dir, "vault.db"))
        else:
            self.db_path = os.path.join(self.config_dir, "vault.db")
            self._save_meta_config()

    def _save_meta_config(self):
        with open(self.config_file, "w", encoding="utf-8") as f:
            json.dump({"db_path": self.db_path}, f, indent=4)

    def attach_database(self, db_helper: "DatabaseHelper"):
        """Описывает публичное действие attach database."""
        self._db_helper = db_helper
        self._load_settings_from_db()

    def attach_key_manager(self, key_manager: "KeyManager"):
        """Описывает публичное действие attach key manager."""
        self._key_manager = key_manager
        self._load_settings_from_db()

    def _load_settings_from_db(self):
        if not self._db_helper:
            return

        rows = self._db_helper.fetchall("SELECT setting_key, setting_value, encrypted FROM settings")
        for key, value, encrypted in rows:
            try:
                if encrypted:
                    if not self._key_manager:
                        continue
                    value = self._decrypt_setting_value(value)
                self.settings[key] = self._deserialize_value(value)
            except Exception as e:
                logger.warning(f"Failed to load setting {key}: {e}")

    def get(self, key: str, default=None):
        """Описывает публичное действие get."""
        return self.settings.get(key, default)

    def get_bool(self, key: str, default: bool = False) -> bool:
        """Возвращает данные для bool."""
        value = self.get(key, default)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in {"1", "true", "yes", "on"}
        return bool(value)

    def get_int(self, key: str, default: int = 0) -> int:
        """Возвращает данные для int."""
        try:
            return int(self.get(key, default))
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _as_bool(value: Any) -> bool:
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in {"1", "true", "yes", "on"}
        return bool(value)

    @staticmethod
    def _coerce_int(value: Any, default: int = 0) -> int:
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    def set(self, key: str, value: Any):
        """Описывает публичное действие set."""
        old_value = self.settings.get(key)
        self.settings[key] = value
        try:
            self.validate_settings(self.settings)
            self._persist_setting(key, value)
            event_bus.publish("SettingChanged", {"key": key})
        except Exception:
            if old_value is None and key in self.settings:
                self.settings.pop(key, None)
            else:
                self.settings[key] = old_value
            raise

    def set_many(self, values: dict, *, source: str = "settings") -> list[str]:
        """Сохраняет или обновляет значение many."""
        old_settings = dict(self.settings)
        candidate = dict(self.settings)
        candidate.update(values)
        warnings = self.validate_settings(candidate)
        transaction_started = False
        try:
            self.settings = candidate
            if self._db_helper and hasattr(self._db_helper, "begin_transaction"):
                self._db_helper.begin_transaction()
                transaction_started = True
            for key, value in values.items():
                self._persist_setting(key, value)
                event_bus.publish("SettingChanged", {"key": key, "source": source})
            if transaction_started:
                self._db_helper.commit_transaction()
            event_bus.publish("SettingsSaved", {"source": source, "keys": sorted(values.keys()), "warnings": warnings})
            return warnings
        except Exception:
            if transaction_started:
                self._db_helper.rollback_transaction()
            self.settings = old_settings
            raise

    def _persist_setting(self, key: str, value: Any):
        if key == "db_path":
            self.db_path = value
            self._save_meta_config()

        if not self._db_helper:
            return

        serialized_value = self._serialize_value(value)
        encrypted = 0
        if self._should_encrypt_setting(key) and self._key_manager:
            serialized_value = self._encrypt_setting_value(serialized_value)
            encrypted = 1

        exists = self._db_helper.fetchone("SELECT 1 FROM settings WHERE setting_key = ?", (key,))
        if exists:
            self._db_helper.execute(
                "UPDATE settings SET setting_value = ?, encrypted = ? WHERE setting_key = ?",
                (serialized_value, encrypted, key),
            )
        else:
            self._db_helper.execute(
                "INSERT INTO settings (setting_key, setting_value, encrypted) VALUES (?, ?, ?)",
                (key, serialized_value, encrypted),
            )

    def get_clipboard_settings(self) -> dict:
        """Возвращает данные для clipboard settings."""
        return {
            "timeout": self.get_int("clipboard_timeout", 30),
            "auto_clear": self.get_bool("clipboard_auto_clear", True),
            "monitor_enabled": self.get_bool("clipboard_monitor_enabled", True),
            "block_on_suspicious": self.get_bool("clipboard_block_on_suspicious", False),
            "security_level": self.get("clipboard_security_level", "basic"),
            "notify_on_copy": self.get_bool("clipboard_notify_on_copy", True),
            "notify_on_clear": self.get_bool("clipboard_notify_on_clear", True),
            "notify_on_warning": self.get_bool("clipboard_notify_on_warning", True),
            "allowed_applications": self.get("clipboard_allowed_applications", []),
            "profile": self.get("clipboard_profile", "Standard"),
        }

    def set_clipboard_settings(self, values: dict):
        """Сохраняет или обновляет значение clipboard settings."""
        key_map = {
            "timeout": "clipboard_timeout",
            "auto_clear": "clipboard_auto_clear",
            "monitor_enabled": "clipboard_monitor_enabled",
            "block_on_suspicious": "clipboard_block_on_suspicious",
            "security_level": "clipboard_security_level",
            "notify_on_copy": "clipboard_notify_on_copy",
            "notify_on_clear": "clipboard_notify_on_clear",
            "notify_on_warning": "clipboard_notify_on_warning",
            "allowed_applications": "clipboard_allowed_applications",
            "profile": "clipboard_profile",
        }
        for key, value in values.items():
            self.set(key_map.get(key, key), value)

    def apply_clipboard_profile(self, profile_name: str):
        """Применяет clipboard profile."""
        if profile_name not in CLIPBOARD_PRESETS:
            raise ValueError(f"Unknown clipboard profile: {profile_name}")
        values = dict(CLIPBOARD_PRESETS[profile_name])
        values["clipboard_profile"] = profile_name
        return self.set_many(values, source="clipboard_profile")

    def get_security_settings(self) -> dict:
        """Возвращает данные для security settings."""
        keys = {
            "security_profile",
            "side_channel_protection_enabled",
            "cache_timing_protection",
            "normalize_crypto_timing",
            "random_crypto_delay",
            "random_delay_min_ms",
            "random_delay_max_ms",
            "side_channel_max_compare_bytes",
            "side_channel_max_search_bytes",
            "memory_protection_enabled",
            "memory_lock_enabled",
            "memory_wipe_passes",
            "memory_guard_pages_enabled",
            "memory_canary_enabled",
            "activity_lock_timeout_seconds",
            "activity_lock_timeout_seconds_desktop",
            "activity_lock_timeout_seconds_laptop",
            "activity_sensitivity",
            "activity_device_profile",
            "panic_mode_enabled",
            "panic_hotkey",
            "panic_close_application",
            "panic_stealth_mode",
            "panic_show_fake_error",
            "panic_fake_error_message",
            "panic_launch_decoy",
            "panic_decoy_command",
            "panic_redirect_url",
            "panic_mouse_gesture_enabled",
            "tray_enabled",
            "minimize_to_tray",
            "start_minimized_to_tray",
            "platform_secure_storage_enabled",
            "windows_credential_guard_enabled",
            "windows_hello_enabled",
            "windows_secure_desktop_enabled",
            "macos_keychain_enabled",
            "macos_touch_id_enabled",
            "macos_gatekeeper_check_enabled",
            "linux_kernel_keyring_enabled",
            "linux_systemd_integration_enabled",
            "linux_lsm_policy_enabled",
        }
        return {key: self.get(key) for key in keys}

    def preview_security_profile(self, profile_name: str) -> dict:
        """Описывает публичное действие preview security profile."""
        if profile_name not in SECURITY_PROFILES:
            raise ValueError(f"Unknown security profile: {profile_name}")
        candidate = dict(self.settings)
        candidate.update(SECURITY_PROFILES[profile_name])
        candidate["security_profile"] = profile_name
        warnings = self.validate_settings(candidate)
        changes = []
        for key in ("security_profile", *SECURITY_PROFILE_KEYS):
            old_value = self.settings.get(key)
            new_value = candidate.get(key)
            if old_value != new_value:
                changes.append(
                    {
                        "key": key,
                        "label": SECURITY_SETTING_LABELS.get(key, key),
                        "old": old_value,
                        "new": new_value,
                    }
                )
        return {
            "profile": profile_name,
            "description": SECURITY_PROFILE_DESCRIPTIONS.get(profile_name, ""),
            "changes": changes,
            "warnings": warnings,
        }

    def explain_security_profile_change(self, profile_name: str) -> str:
        """Описывает публичное действие explain security profile change."""
        preview = self.preview_security_profile(profile_name)
        lines = [f"{preview['profile']}: {preview['description']}"]
        if preview["changes"]:
            lines.append("Changes:")
            for change in preview["changes"]:
                lines.append(f"- {change['label']}: {change['old']} -> {change['new']}")
        else:
            lines.append("No setting changes are needed.")
        if preview["warnings"]:
            lines.append("Warnings:")
            lines.extend(f"- {warning}" for warning in preview["warnings"])
        return "\n".join(lines)

    def apply_security_profile(self, profile_name: str):
        """Применяет security profile."""
        preview = self.preview_security_profile(profile_name)
        values = dict(SECURITY_PROFILES[profile_name])
        values["security_profile"] = profile_name
        warnings = self.set_many(values, source="security_profile")
        event_bus.publish(
            "ConfigChanged",
            {
                "source": "security_profile",
                "profile": profile_name,
                "changes": preview["changes"],
                "warnings": warnings,
            },
        )
        return preview

    def validate_security_settings(self, settings: Optional[dict] = None) -> list[str]:
        """Проверяет security settings."""
        return self.validate_settings(settings or self.settings)

    def validate_settings(self, settings: Optional[dict] = None) -> list[str]:
        """Проверяет settings."""
        settings = settings or self.settings
        warnings = []
        timeout = self._coerce_int(settings.get("activity_lock_timeout_seconds", 300), 300)
        if timeout < 60 or timeout > 8 * 60 * 60:
            raise ValueError("Таймаут автоблокировки должен быть от 60 до 28800 секунд")
        for key in ("activity_lock_timeout_seconds_desktop", "activity_lock_timeout_seconds_laptop"):
            device_timeout = self._coerce_int(settings.get(key, timeout), timeout)
            if device_timeout < 60 or device_timeout > 8 * 60 * 60:
                label = SECURITY_SETTING_LABELS.get(key, key)
                raise ValueError(f"{label} должен быть от 60 до 28800 секунд")
        if settings.get("security_profile", "Standard") not in SECURITY_PROFILES:
            raise ValueError("Профиль безопасности должен быть Standard, Enhanced или Paranoid")
        if settings.get("activity_sensitivity", "medium") not in {"low", "medium", "high"}:
            raise ValueError("Чувствительность к активности должна быть low, medium или high")
        wipe_passes = self._coerce_int(settings.get("memory_wipe_passes", 1), 1)
        if wipe_passes < 1 or wipe_passes > 7:
            raise ValueError("Количество проходов очистки памяти должно быть от 1 до 7")
        if not self._as_bool(settings.get("side_channel_protection_enabled", True)):
            warnings.append("Защита от атак по сторонним каналам отключена.")
        if not self._as_bool(settings.get("cache_timing_protection", True)):
            warnings.append("Защита от cache-timing атак отключена.")
        if not self._as_bool(settings.get("memory_protection_enabled", True)):
            warnings.append("Защита памяти отключена.")
        if not self._as_bool(settings.get("side_channel_protection_enabled", True)) and self._as_bool(settings.get("cache_timing_protection", True)):
            raise ValueError("Защита от cache-timing атак требует включенной защиты от атак по сторонним каналам")
        if not self._as_bool(settings.get("memory_protection_enabled", True)) and (
            self._as_bool(settings.get("memory_lock_enabled", True))
            or self._as_bool(settings.get("memory_guard_pages_enabled", True))
            or self._as_bool(settings.get("memory_canary_enabled", True))
        ):
            raise ValueError("Дополнительные защиты памяти требуют включенной защиты памяти")
        if not self._as_bool(settings.get("tray_enabled", True)) and self._as_bool(settings.get("start_minimized_to_tray", False)):
            raise ValueError("Запуск свернутым в трей требует включенной интеграции с треем")
        if self._as_bool(settings.get("random_crypto_delay", False)):
            min_delay = self._coerce_int(settings.get("random_delay_min_ms", 0), 0)
            max_delay = self._coerce_int(settings.get("random_delay_max_ms", 0), 0)
            if min_delay < 0 or max_delay < min_delay or max_delay > 250:
                raise ValueError("Случайная задержка криптоопераций должна быть от 0 до 250 мс, максимум не меньше минимума")
        if not self._as_bool(settings.get("clipboard_auto_clear", True)):
            warnings.append("Автоочистка буфера обмена отключена.")
        if not self._as_bool(settings.get("panic_mode_enabled", True)):
            warnings.append("Режим паники отключен.")
        if not self._as_bool(settings.get("platform_secure_storage_enabled", True)):
            warnings.append("Защищенное хранилище платформы отключено.")
        warnings.extend(self.get_non_default_warnings(settings))
        return warnings

    def get_non_default_warnings(self, settings: Optional[dict] = None) -> list[str]:
        """Возвращает данные для non default warnings."""
        settings = settings or self.settings
        defaults = self._default_settings()
        warnings = []
        watched_keys = {
            "side_channel_protection_enabled",
            "cache_timing_protection",
            "memory_protection_enabled",
            "memory_wipe_passes",
            "activity_lock_timeout_seconds",
            "panic_mode_enabled",
            "platform_secure_storage_enabled",
            "clipboard_auto_clear",
            "clipboard_timeout",
        }
        for key in sorted(watched_keys):
            if settings.get(key) != defaults.get(key):
                label = SECURITY_SETTING_LABELS.get(key, key)
                warnings.append(f"{label} отличается от безопасного значения по умолчанию.")
        return warnings

    def _should_encrypt_setting(self, key: str) -> bool:
        return key.startswith(ENCRYPTED_SETTING_PREFIXES)

    @staticmethod
    def _serialize_value(value: Any) -> str:
        return json.dumps(value, ensure_ascii=False)

    @staticmethod
    def _deserialize_value(value: Any) -> Any:
        if value is None or not isinstance(value, str):
            return value
        try:
            return json.loads(value)
        except (TypeError, ValueError, json.JSONDecodeError):
            return value

    def _encrypt_setting_value(self, value: str) -> str:
        if not self._key_manager:
            raise RuntimeError("KeyManager is required to encrypt settings")
        from core.vault.encryption_service import AES256GCMService

        service = AES256GCMService()
        service.set_key_manager(self._key_manager)
        encrypted = service.encrypt(value.encode("utf-8"), associated_data=b"settings")
        return base64.b64encode(encrypted).decode("ascii")

    def _decrypt_setting_value(self, value: str) -> str:
        if not self._key_manager:
            raise RuntimeError("KeyManager is required to decrypt settings")
        from core.vault.encryption_service import AES256GCMService

        service = AES256GCMService()
        service.set_key_manager(self._key_manager)
        encrypted = base64.b64decode(value.encode("ascii"))
        return service.decrypt(encrypted, associated_data=b"settings").decode("utf-8")

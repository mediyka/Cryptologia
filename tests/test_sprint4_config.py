import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from core.config import ConfigManager
from core.key_manager import KeyManager
from database.db import DatabaseHelper


def test_clipboard_profile_applies_expected_values(tmp_path):
    with patch("os.path.expanduser", return_value=str(tmp_path)):
        cfg = ConfigManager(profile="test-profile")

        cfg.apply_clipboard_profile("Public Computer")

        settings = cfg.get_clipboard_settings()
    assert settings["profile"] == "Public Computer"
    assert settings["timeout"] == 5
    assert settings["security_level"] == "paranoid"
    assert settings["block_on_suspicious"] is True


def test_clipboard_settings_are_encrypted_when_key_manager_is_attached(tmp_path):
    db = DatabaseHelper(str(tmp_path / "vault.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    with patch("os.path.expanduser", return_value=str(tmp_path)):
        cfg = ConfigManager(profile="encrypted-settings")
        cfg.attach_database(db)
        cfg.attach_key_manager(key_manager)

        cfg.set_clipboard_settings(
            {
                "timeout": 15,
                "security_level": "advanced",
                "allowed_applications": ["CryptoSafe Manager"],
            }
        )

    rows = db.fetchall("SELECT setting_key, setting_value, encrypted FROM settings WHERE setting_key LIKE 'clipboard_%'")
    assert rows
    assert all(row[2] == 1 for row in rows)
    assert all("CryptoSafe Manager" not in str(row[1]) for row in rows)

    with patch("os.path.expanduser", return_value=str(tmp_path)):
        cfg_reloaded = ConfigManager(profile="encrypted-settings-reloaded")
        cfg_reloaded.attach_database(db)
        cfg_reloaded.attach_key_manager(key_manager)

        settings = cfg_reloaded.get_clipboard_settings()
    assert settings["timeout"] == 15
    assert settings["security_level"] == "advanced"
    assert settings["allowed_applications"] == ["CryptoSafe Manager"]

    db.close()

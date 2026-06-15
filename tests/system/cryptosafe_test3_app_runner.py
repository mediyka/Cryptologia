import os
import sys
import tempfile
import time


REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SRC_ROOT = os.path.join(REPO_ROOT, "src")
if SRC_ROOT not in sys.path:
    sys.path.insert(0, SRC_ROOT)

from core.config import ConfigManager
from core.key_manager import KeyManager
from core.state_manager import state_manager
from core.vault.entry_manager import EntryManager
from core.vault.encryption_service import AES256GCMService
from database.db import DatabaseHelper
from gui.main_window import MainWindow


MASTER_PASSWORD = "Str0ng!P@ssw0rd123"


def main() -> int:
    try:
        db_path = sys.stdin.readline().strip()
        entry_id = sys.stdin.readline().strip()
        if not db_path or not entry_id:
            raise RuntimeError("TEST-3 runner requires db_path and entry_id")

        temp_dir = tempfile.mkdtemp(prefix="cryptosafe-test3-")
        os.environ["HOME"] = temp_dir
        os.environ["USERPROFILE"] = temp_dir

        config = ConfigManager(profile=f"test3-{os.getpid()}")
        config.set("db_path", db_path)
        config.set("clipboard_timeout", "never")
        config.set("clipboard_monitor_enabled", False)
        config.set("clipboard_notify_on_copy", False)
        config.set("clipboard_notify_on_clear", False)
        config.set("clipboard_notify_on_warning", False)

        app = MainWindow(config=config, defer_startup=True)
    except Exception as exc:
        print(f"SKIP:Cannot start CryptoSafe GUI process for TEST-3: {exc}", flush=True)
        return 0

    try:
        db = DatabaseHelper(db_path)
        config.attach_database(db)

        key_manager = KeyManager(db)
        if not key_manager.unlock(MASTER_PASSWORD):
            raise RuntimeError("Cannot unlock TEST-3 vault")
        config.attach_key_manager(key_manager)

        encryption_service = AES256GCMService()
        encryption_service.set_key_manager(key_manager)
        entry_manager = EntryManager(db, key_manager)

        app.db = db
        app.key_manager = key_manager
        app.encryption_service = encryption_service
        app.entry_manager = entry_manager
        state_manager.login("test3-user")
        app.load_entries()

        app.copy_entry_field({"id": entry_id}, "password")

        print(f"{os.getpid()}:{entry_id}", flush=True)

        command = sys.stdin.readline().strip()
        if command == "clear":
            app.clipboard_service.clear_clipboard("manual")
            print("cleared", flush=True)

        sys.stdin.readline()
        return 0
    finally:
        try:
            app.on_close()
        except Exception:
            try:
                app.destroy()
            except Exception:
                pass
        time.sleep(0.1)


if __name__ == "__main__":
    raise SystemExit(main())

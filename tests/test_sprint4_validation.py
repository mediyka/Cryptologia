import os
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

import pytest

from core.clipboard import clipboard_service as clipboard_service_module
from core.clipboard.clipboard_service import ClipboardService, SecureClipboardItem
from core.clipboard.platform_adapter import (
    ClipboardAdapter,
    InMemoryClipboardAdapter,
    LinuxClipboardAdapter,
    get_default_clipboard_adapter,
)
from core.events import EventBus
from core.key_manager import KeyManager
from core.vault.entry_manager import EntryManager
from database.db import DatabaseHelper


TEST3_MASTER_PASSWORD = "Str0ng!P@ssw0rd123"


class UnlockedState:
    is_locked = False


class MemoryConfig(dict):
    def set(self, key, value):
        self[key] = value


def make_service(config=None, adapter=None):
    adapter = adapter or InMemoryClipboardAdapter()
    events = EventBus()
    if config is None:
        config = MemoryConfig({"clipboard_timeout": "never"})
    service = ClipboardService(
        platform_adapter=adapter,
        event_system=events,
        config=config,
        state=UnlockedState(),
        register_exit_handler=False,
    )
    return service, adapter, events


def _write_windows_process_dump(pid, dump_path):
    command = [
        "rundll32.exe",
        r"C:\Windows\System32\comsvcs.dll,MiniDump",
        str(pid),
        str(dump_path),
        "full",
    ]
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=30)
    if result.returncode != 0 or not os.path.exists(dump_path):
        pytest.skip(f"Cannot create Windows process dump for TEST-3: {result.stderr or result.stdout}")
    _wait_until_dump_readable(dump_path)


def _write_linux_process_dump(pid, dump_path):
    maps_path = f"/proc/{pid}/maps"
    mem_path = f"/proc/{pid}/mem"
    try:
        with open(maps_path, "r", encoding="utf-8") as maps_file, open(mem_path, "rb", buffering=0) as mem_file, open(
            dump_path, "wb"
        ) as dump_file:
            for line in maps_file:
                parts = line.split()
                if len(parts) < 2 or "r" not in parts[1]:
                    continue

                start_raw, end_raw = parts[0].split("-", 1)
                start = int(start_raw, 16)
                end = int(end_raw, 16)
                cursor = start

                while cursor < end:
                    read_size = min(1024 * 1024, end - cursor)
                    try:
                        mem_file.seek(cursor)
                        data = mem_file.read(read_size)
                    except OSError:
                        break
                    dump_file.write(data)
                    cursor += read_size
    except OSError as exc:
        pytest.skip(f"Cannot create Linux process dump for TEST-3: {exc}")
    _wait_until_dump_readable(dump_path)


def _write_process_dump(pid, dump_path):
    if sys.platform == "win32":
        _write_windows_process_dump(pid, dump_path)
        return
    if sys.platform.startswith("linux"):
        _write_linux_process_dump(pid, dump_path)
        return
    pytest.skip("TEST-3 process dump is implemented for Windows and Linux")


def _dump_file_contains(dump_path, needle):
    overlap_size = max(len(needle) - 1, 0)
    tail = b""
    try:
        with open(dump_path, "rb") as dump_file:
            while True:
                chunk = dump_file.read(1024 * 1024)
                if not chunk:
                    return False
                data = tail + chunk
                if needle in data:
                    return True
                tail = data[-overlap_size:] if overlap_size else b""
    except PermissionError as exc:
        pytest.skip(f"Cannot read process dump for TEST-3: {exc}")


def _wait_until_dump_readable(dump_path, timeout_seconds=10):
    deadline = time.monotonic() + timeout_seconds
    last_error = None
    while time.monotonic() < deadline:
        try:
            with open(dump_path, "rb") as dump_file:
                dump_file.read(1)
            return
        except (FileNotFoundError, PermissionError, OSError) as exc:
            last_error = exc
            time.sleep(0.1)
    pytest.skip(f"Process dump is not readable for TEST-3: {last_error}")


def _prepare_test3_vault(db_path, secret):
    db = DatabaseHelper(str(db_path))

    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault(TEST3_MASTER_PASSWORD)

    entry_manager = EntryManager(db, key_manager)
    entry_id = entry_manager.create_entry(
        {
            "title": "TEST-3 memory dump entry",
            "username": "test3-user",
            "password": secret,
            "url": "https://example.test",
            "notes": "",
            "category": "TEST-3",
            "tags": ["test-3"],
        }
    )
    db.close()
    return entry_id


def test_auto_clear_timing(monkeypatch):
    monkeypatch.setattr(clipboard_service_module, "MIN_TIMEOUT_SECONDS", 1)
    service, adapter, events = make_service(MemoryConfig({"clipboard_timeout": 1}))
    cleared = threading.Event()
    clear_times = []

    events.subscribe(
        "ClipboardCleared",
        lambda event: (clear_times.append(time.monotonic()), cleared.set()),
    )

    start = time.monotonic()
    assert service.copy_password("timed-secret", source_entry_id="entry-test-1")

    assert cleared.wait(2.0)
    elapsed = clear_times[-1] - start

    assert adapter.get_clipboard_content() == ""
    assert service.get_clipboard_status().active is False
    assert 0.9 <= elapsed <= 1.1


def test_native_adapter_priority(monkeypatch):
    class FakeWindowsAdapter(InMemoryClipboardAdapter):
        backend_name = "fake-windows"

    class FakeMacAdapter(InMemoryClipboardAdapter):
        backend_name = "fake-macos"

    class FakeLinuxAdapter(InMemoryClipboardAdapter):
        backend_name = "fake-linux"

    monkeypatch.setattr("core.clipboard.platform_adapter.WindowsClipboardAdapter", FakeWindowsAdapter)
    monkeypatch.setattr("core.clipboard.platform_adapter.MacOSClipboardAdapter", FakeMacAdapter)
    monkeypatch.setattr("core.clipboard.platform_adapter.LinuxClipboardAdapter", FakeLinuxAdapter)

    monkeypatch.setattr("core.clipboard.platform_adapter.platform.system", lambda: "Windows")
    assert get_default_clipboard_adapter().backend_name == "fake-windows"

    monkeypatch.setattr("core.clipboard.platform_adapter.platform.system", lambda: "Darwin")
    assert get_default_clipboard_adapter().backend_name == "fake-macos"

    monkeypatch.setattr("core.clipboard.platform_adapter.platform.system", lambda: "Linux")
    assert get_default_clipboard_adapter().backend_name == "fake-linux"


def test_linux_xclip_xsel(monkeypatch):
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)

    monkeypatch.setattr(
        LinuxClipboardAdapter,
        "_command_exists",
        staticmethod(lambda command: command == "xclip"),
    )
    xclip_adapter = LinuxClipboardAdapter()

    monkeypatch.setattr(
        LinuxClipboardAdapter,
        "_command_exists",
        staticmethod(lambda command: command == "xsel"),
    )
    xsel_adapter = LinuxClipboardAdapter()

    assert xclip_adapter.backend == "xclip"
    assert xclip_adapter._copy_cmd == ["xclip", "-selection", "clipboard"]
    assert xsel_adapter.backend == "xsel"
    assert xsel_adapter._copy_cmd == ["xsel", "--clipboard", "--input"]
    assert xsel_adapter._paste_cmd == ["xsel", "--clipboard", "--output"]


def test_adapter_fallback(monkeypatch):
    class BrokenNativeAdapter(ClipboardAdapter):
        backend_name = "broken-native"

        def __init__(self):
            raise RuntimeError("native unavailable")

        def copy_to_clipboard(self, data: str) -> bool:
            return False

        def clear_clipboard(self) -> bool:
            return False

        def get_clipboard_content(self):
            return None

    class FakePyperclipAdapter(InMemoryClipboardAdapter):
        backend_name = "fake-pyperclip"

    monkeypatch.setattr("core.clipboard.platform_adapter.platform.system", lambda: "Windows")
    monkeypatch.setattr("core.clipboard.platform_adapter.WindowsClipboardAdapter", BrokenNativeAdapter)
    monkeypatch.setattr("core.clipboard.platform_adapter.PyperclipClipboardAdapter", FakePyperclipAdapter)

    assert get_default_clipboard_adapter().backend_name == "fake-pyperclip"

    monkeypatch.setattr("core.clipboard.platform_adapter.PyperclipClipboardAdapter", BrokenNativeAdapter)
    assert get_default_clipboard_adapter().backend_name == "in-memory"


def test_item_obfuscates_data():
    secret = "memory-dump-target-secret"
    item = SecureClipboardItem(secret, "password", "entry-test-3")

    assert secret.encode("utf-8") not in bytes(item._data)
    assert secret.encode("utf-8") not in bytes(item._mask)
    assert item.reveal() == secret


def test_memory_dump_no_plaintext(tmp_path):
    secret = "UNIQUE_SECRET_TEST_PASSWORD_12345_XYZ"
    db_path = tmp_path / "test3-vault.db"
    entry_id = _prepare_test3_vault(db_path, secret)
    runner_path = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "system", "cryptosafe_test3_app_runner.py")
    )
    dump_before = str(tmp_path / "test3-before.dmp")
    dump_after = str(tmp_path / "test3-after.dmp")
    for dump_path in (dump_before, dump_after):
        if os.path.exists(dump_path):
            os.remove(dump_path)

    process = subprocess.Popen(
        [sys.executable, runner_path],
        cwd=os.path.abspath(os.path.join(os.path.dirname(__file__), "..")),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    try:
        process.stdin.write(str(db_path) + "\n")
        process.stdin.write(entry_id + "\n")
        process.stdin.flush()

        app_status_line = process.stdout.readline().strip()
        if not app_status_line:
            pytest.fail(f"TEST-3 CryptoSafe process failed: {process.stderr.read()}")
        if app_status_line.startswith("SKIP:"):
            pytest.skip(app_status_line.removeprefix("SKIP:"))

        app_pid_raw, copied_entry_id = app_status_line.split(":", 1)
        app_pid = int(app_pid_raw)
        target_bytes = secret.encode("utf-8")

        _write_process_dump(app_pid, dump_before)
        plaintext_found = _dump_file_contains(dump_before, target_bytes)

        process.stdin.write("clear\n")
        process.stdin.flush()
        assert process.stdout.readline().strip() == "cleared"

        _write_process_dump(app_pid, dump_after)
        residue_found = _dump_file_contains(dump_after, target_bytes)

        assert plaintext_found is False, "Plaintext password found in process memory during copy"
        assert residue_found is False, "Plaintext password residue found after clipboard clear"
        assert copied_entry_id == entry_id
    finally:
        if process.stdin:
            try:
                process.stdin.write("\n")
                process.stdin.flush()
            except BrokenPipeError:
                pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.terminate()
            process.wait(timeout=5)


def test_wipe_zeroes_buffers():
    secret = "memory-dump-target-secret"
    item = SecureClipboardItem(secret, "password", "entry-test-3")
    data_buffer = item._data
    mask_buffer = item._mask

    item.secure_wipe()

    assert all(byte == 0 for byte in data_buffer)
    assert all(byte == 0 for byte in mask_buffer)
    assert item._data == bytearray()
    assert item._mask == bytearray()


def test_service_obfuscates_password():
    secret = "service-memory-target-secret"
    service, _, _ = make_service()

    assert service.copy_password(secret, source_entry_id="entry-test-3")

    current_item = service.current_content
    assert current_item is not None
    assert secret.encode("utf-8") not in bytes(current_item._data)
    assert secret.encode("utf-8") not in bytes(current_item._mask)
    assert secret not in current_item.preview()

    service.clear_clipboard("manual")
    assert service.current_content is None


def test_concurrent_copy_no_leak():
    service, adapter, _ = make_service()
    secrets = [f"rapid-secret-{index:02d}" for index in range(30)]
    errors = []

    def copy_secret(secret):
        try:
            service.copy_password(secret, source_entry_id=secret)
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=copy_secret, args=(secret,)) for secret in secrets]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    status = service.get_clipboard_status()
    current_system_value = adapter.get_clipboard_content()
    current_secure_value = service.current_content.reveal()

    assert errors == []
    assert status.active is True
    assert current_system_value in secrets
    assert current_secure_value == current_system_value
    assert current_secure_value.encode("utf-8") not in bytes(service.current_content._data)


def test_exit_clears_clipboard():
    service, adapter, events = make_service()
    cleared = []
    events.subscribe("ClipboardCleared", lambda event: cleared.append(event.data))

    assert service.copy_password("crash-recovery-secret", source_entry_id="entry-test-5")
    service._clear_on_exit()

    assert adapter.get_clipboard_content() == ""
    assert service.get_clipboard_status().active is False
    assert cleared[-1]["reason"] == "process_exit"

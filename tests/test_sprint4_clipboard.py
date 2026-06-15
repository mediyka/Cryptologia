import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

import pytest

from core.clipboard.clipboard_monitor import ClipboardMonitor
from core.clipboard.clipboard_service import ClipboardService, SecureClipboardItem
from core.clipboard.platform_adapter import ClipboardAccessInfo, InMemoryClipboardAdapter, LinuxClipboardAdapter
from core.events import EventBus


class UnlockedState:
    is_locked = False


class LockedState:
    is_locked = True


class MemoryConfig(dict):
    def set(self, key, value):
        self[key] = value


class FailingReadClipboardAdapter(InMemoryClipboardAdapter):
    def get_clipboard_content(self):
        raise RuntimeError("read failed")


class BusyClipboardAdapter(InMemoryClipboardAdapter):
    def get_access_info(self):
        return ClipboardAccessInfo(
            content=self.content,
            backend_name=self.backend_name,
            is_busy=True,
            access_error="clipboard is open by another process",
        )


class BrokenAccessInfoAdapter(InMemoryClipboardAdapter):
    def get_access_info(self):
        raise RuntimeError("access info failed")


def make_service(config=None):
    adapter = InMemoryClipboardAdapter()
    events = EventBus()
    if config is None:
        config = MemoryConfig({"clipboard_timeout": "never"})
    service = ClipboardService(
        platform_adapter=adapter,
        event_system=events,
        config=config,
        state=UnlockedState(),
    )
    return service, adapter, events


def test_clipboard_service_publishes_copied_and_cleared_events():
    service, adapter, events = make_service()
    seen = []

    events.subscribe("ClipboardCopied", lambda event: seen.append((event.name, event.data)))
    events.subscribe("ClipboardCleared", lambda event: seen.append((event.name, event.data)))

    assert service.copy_to_clipboard("secret", data_type="password", source_entry_id="entry-1")
    assert adapter.get_clipboard_content() == "secret"

    assert service.clear_clipboard("manual")
    assert adapter.get_clipboard_content() == ""

    assert seen[0][0] == "ClipboardCopied"
    assert seen[0][1]["data_type"] == "password"
    assert seen[0][1]["source_entry_id"] == "entry-1"
    assert seen[1][0] == "ClipboardCleared"
    assert seen[1][1]["reason"] == "manual"


def test_clipboard_service_notifies_observers_with_status_changes():
    service, _, _ = make_service()
    statuses = []

    service.add_observer(statuses.append)

    service.copy_to_clipboard("secret-value", data_type="password", source_entry_id="entry-2")
    service.clear_clipboard("manual")

    assert statuses[0].active is True
    assert statuses[0].data_type == "password"
    assert statuses[0].source_entry_id == "entry-2"
    assert statuses[0].preview.startswith("sec")
    assert statuses[-1].active is False
    assert statuses[-1].clear_reason == "manual"


def test_clipboard_monitor_detects_external_change_and_clears():
    service, adapter, events = make_service()
    suspicious = []
    cleared = []

    events.subscribe("ClipboardSuspiciousActivity", lambda event: suspicious.append(event.data))
    events.subscribe("ClipboardCleared", lambda event: cleared.append(event.data))

    service.copy_to_clipboard("secret", data_type="password", source_entry_id="entry-3")

    monitor = ClipboardMonitor(service, interval_seconds=0.25)
    monitor.start()
    adapter.copy_to_clipboard("external-value")
    monitor.poll_once()
    monitor.stop()

    assert service.get_clipboard_status().active is False
    assert suspicious[0]["reason"] == "external_change"
    assert cleared[-1]["reason"] == "external_change"


def test_clipboard_monitor_detects_external_access_and_accelerates_clear():
    adapter = BusyClipboardAdapter()
    events = EventBus()
    suspicious = []
    accelerated = []
    events.subscribe("ClipboardSuspiciousActivity", lambda event: suspicious.append(event.data))
    events.subscribe("ClipboardClearAccelerated", lambda event: accelerated.append(event.data))
    service = ClipboardService(
        platform_adapter=adapter,
        event_system=events,
        config=MemoryConfig({"clipboard_timeout": 30}),
        state=UnlockedState(),
    )

    assert service.copy_password("secret", source_entry_id="entry-access")
    monitor = ClipboardMonitor(service)
    monitor.start()
    monitor.poll_once()
    monitor.stop()

    assert service.get_clipboard_status().active is True
    assert service.get_clipboard_status().remaining_seconds <= 5
    assert suspicious[-1]["reason"] == "external_clipboard_access"
    assert suspicious[-1]["action"] == "accelerate_clear"
    assert accelerated[-1]["reason"] == "external_clipboard_access"


def test_suspicious_access_accelerates_clear_and_notifies():
    service, _, events = make_service(MemoryConfig({"clipboard_timeout": 30}))
    warnings = []
    accelerated = []

    events.subscribe("ClipboardWarning", lambda event: warnings.append(event.data))
    events.subscribe("ClipboardClearAccelerated", lambda event: accelerated.append(event.data))

    assert service.copy_password("secret", source_entry_id="entry-security")
    service.handle_suspicious_access("possible_clipboard_snooping")

    status = service.get_clipboard_status()
    assert status.active is True
    assert 0 < status.remaining_seconds <= 5
    assert warnings[-1]["reason"] == "possible_clipboard_snooping"
    assert accelerated[0]["remaining_seconds"] <= 5

    service.clear_clipboard("test_cleanup")


def test_suspicious_activity_can_block_future_copies():
    service, _, _ = make_service(
        MemoryConfig({"clipboard_timeout": "never", "clipboard_block_on_suspicious": True})
    )

    assert service.copy_password("secret", source_entry_id="entry-block")
    service.handle_suspicious_access("possible_clipboard_snooping")

    assert service.is_copy_blocked() is True
    with pytest.raises(PermissionError):
        service.copy_password("another-secret", source_entry_id="entry-block")

    service.unblock_copies()
    assert service.is_copy_blocked() is False
    assert service.copy_password("another-secret", source_entry_id="entry-block")


def test_clipboard_monitor_failure_degrades_gracefully():
    adapter = BrokenAccessInfoAdapter()
    events = EventBus()
    errors = []
    events.subscribe("ClipboardMonitorError", lambda event: errors.append(event.data))
    service = ClipboardService(
        platform_adapter=adapter,
        event_system=events,
        config=MemoryConfig({"clipboard_timeout": "never"}),
        state=UnlockedState(),
    )

    monitor = ClipboardMonitor(service)
    assert monitor.start() is True
    monitor.poll_once()
    monitor.stop()

    assert errors
    assert errors[-1]["reason"] == "poll_failed"


def test_clipboard_service_supports_required_data_types():
    service, adapter, _ = make_service()

    assert service.copy_username("user@example.com", source_entry_id="entry-4")
    assert service.get_clipboard_status().data_type == "username"
    assert adapter.get_clipboard_content() == "user@example.com"

    assert service.copy_password("secret-password", source_entry_id="entry-4")
    assert service.get_clipboard_status().data_type == "password"
    assert adapter.get_clipboard_content() == "secret-password"

    assert service.copy_text("safe note", source_entry_id="entry-4")
    assert service.get_clipboard_status().data_type == "text"
    assert adapter.get_clipboard_content() == "safe note"


def test_secure_clipboard_item_obfuscates_and_wipes_memory():
    item = SecureClipboardItem("plain-secret", "password", "entry-sec")

    assert item._memory_lock_attempted is True
    assert b"plain-secret" not in bytes(item._data)
    assert item.reveal() == "plain-secret"

    data_buffer = item._data
    mask_buffer = item._mask
    item.secure_wipe()

    assert all(byte == 0 for byte in data_buffer)
    assert all(byte == 0 for byte in mask_buffer)
    assert item._data == bytearray()
    assert item._mask == bytearray()


def test_clipboard_copy_requires_unlocked_vault():
    adapter = InMemoryClipboardAdapter()
    service = ClipboardService(
        platform_adapter=adapter,
        event_system=EventBus(),
        config=MemoryConfig({"clipboard_timeout": "never"}),
        state=LockedState(),
    )

    with pytest.raises(PermissionError):
        service.copy_password("secret", source_entry_id="entry-locked")


def test_auto_clear_timeout_is_normalized_and_persisted():
    config = MemoryConfig()
    service, _, _ = make_service(config)

    assert service.set_auto_clear_timeout(3) == 5
    assert config["clipboard_timeout"] == 5

    assert service.set_auto_clear_timeout(999) == 300
    assert config["clipboard_timeout"] == 300

    assert service.set_auto_clear_timeout(None) is None
    assert config["clipboard_timeout"] == "never"


def test_auto_clear_can_be_disabled_by_setting():
    service, _, _ = make_service(MemoryConfig({"clipboard_auto_clear": False, "clipboard_timeout": 30}))

    assert service.copy_password("secret", source_entry_id="entry-timeout")
    assert service.get_clipboard_status().remaining_seconds == 0.0


def test_new_copy_clears_previous_content_with_replaced_reason():
    service, adapter, events = make_service()
    cleared = []

    events.subscribe("ClipboardCleared", lambda event: cleared.append(event.data))

    assert service.copy_password("first", source_entry_id="entry-5")
    assert service.copy_username("second", source_entry_id="entry-6")

    assert adapter.get_clipboard_content() == "second"
    assert cleared[0]["reason"] == "replaced"
    assert cleared[0]["source_entry_id"] == "entry-5"


def test_user_logout_event_clears_clipboard():
    service, adapter, events = make_service()

    assert service.copy_password("secret", source_entry_id="entry-7")
    events.publish("UserLoggedOut")

    assert adapter.get_clipboard_content() == ""
    assert service.get_clipboard_status().active is False


def test_linux_adapter_prefers_wayland_when_available(monkeypatch):
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    monkeypatch.setattr(
        LinuxClipboardAdapter,
        "_command_exists",
        staticmethod(lambda command: command in {"wl-copy", "wl-paste", "xclip", "xsel"}),
    )

    adapter = LinuxClipboardAdapter()

    assert adapter.backend == "wl-clipboard"
    assert adapter._copy_cmd == ["wl-copy"]
    assert adapter._paste_cmd == ["wl-paste", "--no-newline"]


def test_linux_adapter_supports_primary_selection_with_wayland(monkeypatch):
    monkeypatch.setenv("WAYLAND_DISPLAY", "wayland-0")
    monkeypatch.setattr(
        LinuxClipboardAdapter,
        "_command_exists",
        staticmethod(lambda command: command in {"wl-copy", "wl-paste"}),
    )

    adapter = LinuxClipboardAdapter(selection="primary")

    assert adapter.backend == "wl-clipboard"
    assert adapter._copy_cmd == ["wl-copy", "--primary"]
    assert adapter._paste_cmd == ["wl-paste", "--no-newline", "--primary"]


def test_linux_adapter_supports_primary_selection_with_xclip(monkeypatch):
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.setattr(
        LinuxClipboardAdapter,
        "_command_exists",
        staticmethod(lambda command: command == "xclip"),
    )

    adapter = LinuxClipboardAdapter(selection="primary")

    assert adapter.backend == "xclip"
    assert adapter._copy_cmd == ["xclip", "-selection", "primary"]
    assert adapter._paste_cmd == ["xclip", "-selection", "primary", "-o"]

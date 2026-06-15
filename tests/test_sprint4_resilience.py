import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

import pytest

from core.audit import AuditManager
from core.clipboard.clipboard_monitor import ClipboardMonitor
from core.clipboard.clipboard_service import ClipboardService
from core.clipboard.platform_adapter import ClipboardAdapter, InMemoryClipboardAdapter, get_default_clipboard_adapter
from core.events import EventBus, event_bus


class UnlockedState:
    is_locked = False


class MemoryConfig(dict):
    def set(self, key, value):
        self[key] = value


class RecordingDB:
    def __init__(self):
        self.executed = []

    def execute(self, query, params=()):
        self.executed.append((query, params))


class BrokenAdapter(ClipboardAdapter):
    backend_name = "broken"

    def __init__(self):
        raise RuntimeError("backend unavailable")

    def copy_to_clipboard(self, data: str) -> bool:
        return False

    def clear_clipboard(self) -> bool:
        return False

    def get_clipboard_content(self):
        return None


class FailingClearAdapter(InMemoryClipboardAdapter):
    backend_name = "failing-clear"

    def clear_clipboard(self) -> bool:
        return False


class FailingCopyAdapter(InMemoryClipboardAdapter):
    backend_name = "failing-copy"

    def copy_to_clipboard(self, data: str) -> bool:
        return False


class BrokenAccessAdapter(InMemoryClipboardAdapter):
    backend_name = "broken-access"

    def get_access_info(self):
        raise RuntimeError("poll failed")


def make_service(adapter=None, events=None):
    return ClipboardService(
        platform_adapter=adapter or InMemoryClipboardAdapter(),
        event_system=events or EventBus(),
        config=MemoryConfig({"clipboard_timeout": "never"}),
        state=UnlockedState(),
        register_exit_handler=False,
    )


def test_err_1_platform_fallback_uses_pyperclip_then_in_memory(monkeypatch):
    class FakePyperclipAdapter(InMemoryClipboardAdapter):
        backend_name = "fake-pyperclip"

    monkeypatch.setattr("core.clipboard.platform_adapter.platform.system", lambda: "Windows")
    monkeypatch.setattr("core.clipboard.platform_adapter.WindowsClipboardAdapter", BrokenAdapter)
    monkeypatch.setattr("core.clipboard.platform_adapter.PyperclipClipboardAdapter", FakePyperclipAdapter)

    assert get_default_clipboard_adapter().backend_name == "fake-pyperclip"

    monkeypatch.setattr("core.clipboard.platform_adapter.PyperclipClipboardAdapter", BrokenAdapter)
    assert get_default_clipboard_adapter().backend_name == "in-memory"


def test_err_2_clear_failure_warns_user_to_clear_manually():
    events = EventBus()
    errors = []
    events.subscribe("ClipboardError", lambda event: errors.append(event.data))
    adapter = FailingClearAdapter()
    service = make_service(adapter=adapter, events=events)

    assert service.copy_password("manual-clear-secret", source_entry_id="entry-err-2")
    assert service.clear_clipboard("manual") is False

    assert adapter.get_clipboard_content() == "manual-clear-secret"
    assert errors[-1]["reason"] == "clear_failed"
    assert errors[-1]["manual_clear_required"] is True
    assert "вручную" in errors[-1]["message"].lower()
    assert errors[-1]["backend_name"] == "failing-clear"


def test_err_2_copy_failure_reports_backend_without_secret():
    events = EventBus()
    errors = []
    events.subscribe("ClipboardError", lambda event: errors.append(event.data))
    service = make_service(adapter=FailingCopyAdapter(), events=events)

    assert service.copy_password("copy-failure-secret", source_entry_id="entry-copy-fail") is False

    payload = json.dumps(errors[-1], ensure_ascii=False)
    assert errors[-1]["reason"] == "copy_failed"
    assert errors[-1]["backend_name"] == "failing-copy"
    assert "copy-failure-secret" not in payload


def test_err_3_monitoring_failure_degrades_with_warning_event():
    events = EventBus()
    errors = []
    events.subscribe("ClipboardMonitorError", lambda event: errors.append(event.data))
    service = make_service(adapter=BrokenAccessAdapter(), events=events)
    monitor = ClipboardMonitor(service)

    assert monitor.start() is True
    monitor.poll_once()
    monitor.stop()

    assert errors[-1]["reason"] == "poll_failed"
    assert "ограничен" in errors[-1]["message"]


def test_err_4_validation_errors_are_audited_without_exposing_secret():
    secret = "bad-value-secret"
    db = RecordingDB()
    AuditManager(db)
    service = make_service(events=event_bus)

    with pytest.raises(ValueError):
        service.copy_password(f"{secret}\x00", source_entry_id="entry-err-4")

    query, params = db.executed[-1]
    details = json.loads(params[2])

    assert "audit_log" in query
    assert params[0] == "ClipboardError"
    assert details["reason"] == "validation_failed"
    assert details["entry_id"] == "entry-err-4"
    assert secret not in params[2]

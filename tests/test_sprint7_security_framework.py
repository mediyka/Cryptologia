import os
import sys
import threading
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from core.config import ConfigManager, SECURITY_PROFILES
from core.crypto.key_derivation import KeyDerivationService
from core.crypto.key_storage import SecureMemoryCache
from core.security import (
    ActivityMonitor,
    PanicMode,
    PlatformSecurityManager,
    SecretBuffer,
    SecureMemory,
    SecurityValidationSuite,
    SensitiveScope,
    SideChannelProtection,
    constant_time_compare,
    get_secure_memory,
    sensitive_scope,
)
from core.import_export.exporter import VaultExporter
from core.import_export.importer import VaultImporter
from gui.tray_manager import TrayManager
from gui.ux import COMMON_SHORTCUTS, batched, friendly_error_message, security_state_color
from gui.widgets.secure_table import SecureTable


def test_arc_1_imports():
    assert SideChannelProtection is not None
    assert SecureMemory is not None
    assert ActivityMonitor is not None
    assert PanicMode is not None


def test_arc_2_defaults(tmp_path, monkeypatch):
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    config = ConfigManager(profile="sprint7")

    settings = config.get_security_settings()
    assert settings["security_profile"] == "Standard"
    assert settings["side_channel_protection_enabled"] is True
    assert settings["cache_timing_protection"] is True
    assert settings["memory_protection_enabled"] is True
    assert settings["panic_mode_enabled"] is True
    assert settings["panic_hotkey"] == "Ctrl+Alt+P"
    assert settings["panic_mouse_gesture_enabled"] is False
    assert settings["panic_close_application"] is False
    assert 60 <= settings["activity_lock_timeout_seconds"] <= 8 * 60 * 60
    assert config.validate_security_settings() == []


def test_arc_2_profiles(tmp_path, monkeypatch):
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    config = ConfigManager(profile="sprint7_profiles")

    for profile in SECURITY_PROFILES:
        config.apply_security_profile(profile)
        settings = config.get_security_settings()
        assert settings["security_profile"] == profile
        assert settings["side_channel_protection_enabled"] is True
        assert 60 <= settings["activity_lock_timeout_seconds"] <= 8 * 60 * 60


def test_cfg_1_profiles():
    assert set(SECURITY_PROFILES) == {"Standard", "Enhanced", "Paranoid"}
    assert SECURITY_PROFILES["Standard"]["activity_lock_timeout_seconds"] == 300
    assert SECURITY_PROFILES["Enhanced"]["memory_wipe_passes"] >= 2
    assert SECURITY_PROFILES["Paranoid"]["random_crypto_delay"] is True


def test_cfg_2_preview_apply(tmp_path, monkeypatch):
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    config = ConfigManager(profile="sprint7_cfg_preview")

    preview = config.preview_security_profile("Paranoid")

    assert preview["profile"] == "Paranoid"
    assert preview["changes"]
    assert any(change["key"] == "memory_wipe_passes" for change in preview["changes"])
    assert "Paranoid" in config.explain_security_profile_change("Paranoid")

    applied = config.apply_security_profile("Paranoid")
    assert applied["profile"] == "Paranoid"
    assert config.get("security_profile") == "Paranoid"
    assert config.get_bool("random_crypto_delay") is True


def test_cfg_2_rollback(tmp_path, monkeypatch):
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    config = ConfigManager(profile="sprint7_cfg_rollback")
    original_timeout = config.get_int("activity_lock_timeout_seconds")

    try:
        config.set_many({"activity_lock_timeout_seconds": 30}, source="unit_test")
    except ValueError:
        pass
    else:
        raise AssertionError("invalid settings batch must fail")

    assert config.get_int("activity_lock_timeout_seconds") == original_timeout


def test_cfg_3_validation(tmp_path, monkeypatch):
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    config = ConfigManager(profile="sprint7_cfg_validation")

    try:
        config.validate_settings(
            {
                **config.settings,
                "side_channel_protection_enabled": False,
                "cache_timing_protection": True,
            }
        )
    except ValueError as exc:
        assert "cache-timing" in str(exc)
    else:
        raise AssertionError("insecure side-channel combination must be rejected")

    warnings = config.validate_settings({**config.settings, "clipboard_auto_clear": False})
    assert any("Автоочистка буфера обмена отключена" in warning for warning in warnings)


def test_sc_1_compare():
    assert constant_time_compare("secret", "secret")
    assert not constant_time_compare("secret", "secreu")
    assert constant_time_compare(b"secret", bytearray(b"secret"))
    assert not constant_time_compare("secret", "secret-extended")


def test_sc_1_password_verify():
    service = KeyDerivationService({"pbkdf2_iterations": 10000})
    stored_hash = service.create_auth_hash("Str0ng!P@ssw0rd123")

    assert service.verify_password("Str0ng!P@ssw0rd123", stored_hash)
    assert not service.verify_password("Wrong!P@ssw0rd123", stored_hash)


def test_sc_2_search():
    protection = SideChannelProtection({"side_channel_max_search_bytes": 256})

    assert protection.contains("github", "Github Account")
    assert protection.all_tokens_contained(["github", "account"], "Github Account")
    assert not protection.contains("bank", "Github Account")


def test_sc_3_jitter():
    protection = SideChannelProtection(
        {
            "random_crypto_delay": True,
            "random_delay_min_ms": 1,
            "random_delay_max_ms": 1,
        }
    )

    started = time.perf_counter()
    protection.apply_crypto_jitter()
    assert time.perf_counter() - started >= 0.001


def test_mem_1_allocation():
    memory = SecureMemory({"memory_lock_enabled": False})
    buffer = memory.allocate_secure(16)

    assert len(buffer) == 16
    assert memory.get_allocation(buffer) is not None
    assert memory.verify_canary(buffer)

    buffer[:] = b"A" * 16
    assert bytes(buffer) == b"A" * 16
    assert memory.free_secure(buffer)
    assert memory.get_allocation(buffer) is None


def test_mem_2_zero():
    memory = SecureMemory({"memory_wipe_passes": 3})
    buffer = bytearray(b"temporary-secret")

    assert memory.secure_zero(buffer)
    assert bytes(buffer) == b"\x00" * len(buffer)


def test_mem_2_secret_buffer():
    memory = SecureMemory({"memory_lock_enabled": False})
    with SecretBuffer(b"context-secret", memory=memory) as secret:
        tracked = secret.buffer
        assert bytes(tracked) == b"context-secret"
        assert memory.get_allocation(tracked) is not None

    assert bytes(tracked) == b"\x00" * len(tracked)
    assert memory.get_allocation(tracked) is None


def test_mem_3_canary():
    memory = SecureMemory({"memory_lock_enabled": False})
    buffer = memory.allocate_secure(8)
    allocation = memory.get_allocation(buffer)

    assert allocation is not None
    assert memory.verify_canary(buffer)
    allocation.buffer[allocation.guard_size] ^= 0xFF
    assert not memory.verify_canary(buffer)
    assert not memory.free_secure(buffer)


def test_mem_4_key_cache():
    cache = SecureMemoryCache({"memory_lock_enabled": False})
    cache.store_key(b"K" * 32)

    internal = cache._key
    assert cache.get_key() == b"K" * 32
    assert cache._memory.get_allocation(internal) is not None

    cache.clear_key()
    assert bytes(internal) == b"\x00" * len(internal)
    assert cache._key is None


def test_mem_4_wipe_all():
    memory = SecureMemory({"memory_lock_enabled": False})
    first = memory.allocate_secure(5)
    second = memory.allocate_secure(6)
    first[:] = b"first"
    second[:] = b"second"

    assert memory.wipe_all() == 2
    assert bytes(first) == b"\x00" * 5
    assert bytes(second) == b"\x00" * 6


def test_mem_4_panic_wipe():
    memory = get_secure_memory()
    buffer = memory.allocate_secure(12)
    buffer[:] = b"panic-secret"

    panic = PanicMode()
    assert panic.activate("unit_test")
    assert bytes(buffer) == b"\x00" * len(buffer)
    assert memory.get_allocation(buffer) is None


def test_mem_4_scope():
    memory = SecureMemory({"memory_lock_enabled": False})
    scratch = bytearray(b"stack-secret")

    with sensitive_scope("unit-test", memory=memory) as scope:
        scope.register(scratch)
        secret = scope.buffer(b"derived-secret")
        assert bytes(secret.buffer) == b"derived-secret"

    assert scratch == bytearray(len(scratch))
    assert bytes(secret.buffer) == b"\x00" * len(secret.buffer)


def test_act_1_activity():
    reasons = []
    monitor = ActivityMonitor(lambda reason: reasons.append(reason), {"activity_lock_timeout_seconds": 60})

    monitor.record_mouse_activity()
    mouse_idle = monitor.get_idle_time()
    monitor.record_keyboard_activity()
    keyboard_idle = monitor.get_idle_time()
    monitor.record_focus_change(True)

    assert mouse_idle >= 0
    assert keyboard_idle <= mouse_idle + 0.1
    assert monitor.last_focus_change is not None
    assert reasons == []


def test_act_2_config():
    monitor = ActivityMonitor(
        lambda reason: None,
        {
            "activity_lock_timeout_seconds": 8 * 60 * 60 + 1,
            "activity_lock_timeout_seconds_laptop": 120,
            "activity_device_profile": "laptop",
            "activity_sensitivity": "high",
        },
    )

    assert monitor.timeout_seconds == 120
    assert monitor.sensitivity == "high"
    monitor.update_config({"activity_lock_timeout_seconds": 1, "activity_sensitivity": "invalid"})
    assert monitor.timeout_seconds == 60
    assert monitor.sensitivity == "medium"


def test_act_3_auto_lock():
    locked = threading.Event()
    reasons = []
    monitor = ActivityMonitor(
        lambda reason: (reasons.append(reason), locked.set()),
        {"activity_lock_timeout_seconds": 60, "activity_check_interval_seconds": 0.5},
    )
    monitor.last_activity = time.monotonic() - 61

    monitor.start_monitoring()
    try:
        assert locked.wait(2.0)
        assert reasons == ["inactivity"]
    finally:
        monitor.stop_monitoring()


def test_act_4_system_lock():
    reasons = []
    monitor = ActivityMonitor(lambda reason: reasons.append(reason), {"activity_lock_timeout_seconds": 300})

    monitor.record_system_lock_signal("screen_lock")

    assert reasons == ["system_lock"]
    assert monitor.last_system_lock_signal is not None


class _DummyConfig:
    def __init__(self, values=None):
        self.values = values or {}

    def get_bool(self, key, default=False):
        return bool(self.values.get(key, default))


class _EventRecorder:
    def __init__(self):
        self.events = []
        self.subscribers = {}

    def subscribe(self, name, callback):
        self.subscribers.setdefault(name, []).append(callback)

    def publish(self, name, data=None):
        self.events.append((name, data or {}))
        event = type("Event", (), {"name": name, "data": data or {}})()
        for callback in self.subscribers.get(name, []):
            callback(event)

    def names(self):
        return [name for name, _ in self.events]


class _DummyApp:
    def __init__(self):
        self.hidden = False
        self.visible = True

    def withdraw(self):
        self.hidden = True
        self.visible = False

    def deiconify(self):
        self.hidden = False
        self.visible = True

    def lift(self):
        pass

    def focus_force(self):
        pass


def test_tray_1_fallback():
    calls = []
    tray = TrayManager(
        _DummyApp(),
        _DummyConfig({"tray_enabled": True}),
        lock_callback=lambda: calls.append("lock"),
        unlock_callback=lambda: calls.append("unlock"),
        show_callback=lambda: calls.append("show"),
        quick_search_callback=lambda: calls.append("search"),
        clear_clipboard_callback=lambda: calls.append("clear"),
        panic_callback=lambda: calls.append("panic"),
        settings_callback=lambda: calls.append("settings"),
        exit_callback=lambda: calls.append("exit"),
    )

    assert tray.start()
    assert tray.state.running
    assert tray.state.backend in {"fallback", "pystray"}
    tray.update_security_state(False)
    tray.command_lock_or_unlock()
    tray.update_security_state(True)
    tray.command_lock_or_unlock()
    assert calls == ["lock", "unlock"]
    tray.stop()


def test_tray_2_menu():
    calls = []
    tray = TrayManager(
        _DummyApp(),
        _DummyConfig({"tray_enabled": True}),
        lock_callback=lambda: calls.append("lock"),
        unlock_callback=lambda: calls.append("unlock"),
        show_callback=lambda: calls.append("show"),
        quick_search_callback=lambda: calls.append("search"),
        clear_clipboard_callback=lambda: calls.append("clear"),
        panic_callback=lambda: calls.append("panic"),
        settings_callback=lambda: calls.append("settings"),
        exit_callback=lambda: calls.append("exit"),
    )

    status = type("Status", (), {"active": True, "data_type": "password", "remaining_seconds": 12})()
    tray.update_clipboard_status(status)
    tray.command_show()
    tray.command_quick_search()
    tray.command_clear_clipboard()
    tray.command_panic()
    tray.command_settings()
    tray.command_exit()

    assert tray.state.clipboard_active is True
    assert "password" in tray.state.clipboard_text
    assert calls == ["show", "search", "clear", "panic", "settings", "exit"]


def test_tray_4_restore():
    app = _DummyApp()
    tray = TrayManager(
        app,
        _DummyConfig({"tray_enabled": True}),
        lock_callback=lambda: None,
        unlock_callback=lambda: None,
        show_callback=lambda: None,
        quick_search_callback=lambda: None,
        clear_clipboard_callback=lambda: None,
        panic_callback=lambda: None,
        settings_callback=lambda: None,
        exit_callback=lambda: None,
    )

    tray.hide_window()
    assert app.hidden is True
    tray.show_window()
    assert app.visible is True


def test_panic_1_activation():
    bus = _EventRecorder()
    panic = PanicMode({"panic_hotkey": "Ctrl+Alt+P", "panic_mouse_gesture_enabled": True}, bus=bus)

    assert panic.hotkey_sequence() == "<Control-Alt-p>"
    positions = [(0.0, 100), (0.1, 180), (0.2, 90), (0.3, 185), (0.4, 95), (0.5, 190), (0.6, 100)]
    detected = [panic.record_window_position(x, 10, now=now) for now, x in positions]

    assert detected[-1] is True
    assert "PanicMouseGestureDetected" in bus.names()


def test_panic_1_realistic_window_shake():
    panic = PanicMode({"panic_mouse_gesture_enabled": True}, bus=_EventRecorder())
    positions = [(0.0, 420), (0.18, 500), (0.36, 410), (0.54, 505), (0.72, 415), (0.9, 510), (1.08, 420)]

    detected = [panic.record_window_position(x, 10, now=now) for now, x in positions]

    assert detected[-1] is True


def test_panic_1_ignores_small_window_moves():
    panic = PanicMode({"panic_mouse_gesture_enabled": True}, bus=_EventRecorder())
    positions = [(0.0, 420), (0.2, 435), (0.4, 418), (0.6, 440), (0.8, 422), (1.0, 438), (1.2, 425)]

    detected = [panic.record_window_position(x, 10, now=now) for now, x in positions]

    assert not any(detected)


def test_panic_1_pointer_drag_gesture():
    panic = PanicMode({"panic_mouse_gesture_enabled": True}, bus=_EventRecorder())
    positions = [(0.0, 500), (0.2, 560), (0.4, 510), (0.6, 565)]

    detected = [panic.record_pointer_position(x, 10, now=now) for now, x in positions]

    assert detected[-1] is True


def test_panic_2_handlers():
    bus = _EventRecorder()
    calls = []
    panic = PanicMode({"panic_mode_enabled": True, "panic_close_application": True}, bus=bus)
    panic.register_handler(lambda method: calls.append(method))

    assert panic.activate("hotkey")
    assert not panic.activate("tray")
    assert calls == ["hotkey"]
    assert bus.events[0][0] == "PanicModeActivated"
    assert bus.events[0][1]["method"] == "hotkey"
    assert bus.events[0][1]["close_application"] is True
    assert "SecureMemoryWiped" in bus.names()


def test_panic_3_stealth():
    bus = _EventRecorder()
    panic = PanicMode(
        {
            "panic_stealth_mode": True,
            "panic_show_fake_error": True,
            "panic_fake_error_message": "Fake crash",
            "panic_launch_decoy": True,
            "panic_decoy_command": "notepad",
            "panic_redirect_url": "https://example.com",
        },
        bus=bus,
    )

    assert panic.activate("manual")
    stealth_events = [data for name, data in bus.events if name == "PanicStealthActionRequested"]

    assert [event["type"] for event in stealth_events] == ["fake_error", "launch_decoy", "redirect_url"]
    assert stealth_events[0]["message"] == "Fake crash"


def test_panic_4_recovery():
    bus = _EventRecorder()
    panic = PanicMode(bus=bus)

    assert panic.activate("mouse_gesture")
    assert panic.activated is True
    assert panic.recover("master_password")
    assert panic.activated is False
    assert bus.names()[-2:] == ["PanicModeRecoveryStarted", "PanicModeDeactivated"]


def test_test_1_timing():
    suite = SecurityValidationSuite(bus=_EventRecorder())

    result = suite.timing_attack_test(iterations=20, max_ratio_delta=1.0)

    assert result.name == "timing_attack"
    assert result.passed is True
    assert result.details["iterations"] == 20


def test_test_2_memory_scan():
    suite = SecurityValidationSuite(bus=_EventRecorder())
    memory = SecureMemory({"memory_lock_enabled": False})
    secret = b"dump-secret"

    with SecretBuffer(secret, memory=memory):
        assert suite.memory_plaintext_scan(secret, memory=memory).passed is False

    assert suite.memory_plaintext_scan(secret, memory=memory).passed is True


def test_test_3_auto_lock():
    suite = SecurityValidationSuite(bus=_EventRecorder())
    monitor = ActivityMonitor(lambda reason: None, {"activity_lock_timeout_seconds": 60})

    result = suite.auto_lock_reliability_test(monitor, idle_seconds=61)

    assert result.name == "auto_lock_reliability"
    assert result.passed is True


def test_test_4_panic_stress():
    suite = SecurityValidationSuite(bus=_EventRecorder())
    panic = PanicMode(bus=_EventRecorder())

    result = suite.panic_stress_test(panic, ["hotkey", "tray", "mouse_gesture"])

    assert result.passed is True
    assert result.details["activations"] == 3
    assert panic.activated is False


def test_test_5_usability():
    message = friendly_error_message(PermissionError("access denied"), "export")
    batches = list(batched([1, 2, 3, 4, 5], 2))

    assert "прав" in message.title.lower()
    assert batches == [[1, 2], [3, 4], [5]]
    assert COMMON_SHORTCUTS["search"] == "<Control-f>"
    assert security_state_color("locked") != security_state_color("unlocked")


def test_int_1_4_report():
    suite = SecurityValidationSuite(bus=_EventRecorder())

    result = suite.integration_report(
        {
            "vault_memory_protection": True,
            "clipboard_memory_protection": True,
            "panic_clipboard_clear": True,
            "audit_security_events": True,
            "import_export_panic_interrupt": True,
        }
    )

    assert result.passed is True
    assert result.details["missing"] == []


def test_int_4_panic_interrupt():
    bus = _EventRecorder()
    importer = VaultImporter(bus=bus)
    exporter = VaultExporter(type("EntryManager", (), {"get_all_entries": lambda self, include_decrypted_password=True: []})(), bus=bus)

    bus.publish("PanicModeActivated", {"method": "unit_test"})

    for component in (importer, exporter):
        try:
            component._check_panic_interrupt()
        except RuntimeError as exc:
            assert "panic mode" in str(exc)
        else:
            raise AssertionError("panic interruption must abort import/export operations")


def test_perf_1_ct_overhead():
    suite = SecurityValidationSuite(bus=_EventRecorder())

    result = suite.constant_time_overhead_test(
        baseline=lambda: (sum(range(200)), constant_time_compare(b"A" * 32, b"A" * 32)),
        protected=lambda: constant_time_compare(b"A" * 32, b"A" * 32),
        iterations=20,
        max_overhead_ratio=0.10,
    )

    assert result.name == "constant_time_overhead"
    assert result.passed is True
    assert result.details["max_overhead_ratio"] == 0.10


def test_perf_2_memory_overhead():
    suite = SecurityValidationSuite(bus=_EventRecorder())

    result = suite.memory_overhead_test(allocation_size=4096, max_overhead_ratio=0.05)

    assert result.name == "memory_overhead"
    assert result.passed is True
    assert result.details["overhead_ratio"] <= 0.05


def test_perf_3_idle_cpu():
    suite = SecurityValidationSuite(bus=_EventRecorder())

    result = suite.idle_cpu_overhead_test(duration_seconds=0.02, max_cpu_fraction=1.0)

    assert result.name == "idle_cpu_overhead"
    assert result.passed is True
    assert "cpu_fraction" in result.details


def test_perf_4_startup(tmp_path, monkeypatch):
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    suite = SecurityValidationSuite(bus=_EventRecorder())

    result = suite.startup_time_test(lambda: ConfigManager(profile="perf_startup").get_security_settings(), max_seconds=3.0)

    assert result.name == "startup_time"
    assert result.passed is True


def test_sec_1_4_report(tmp_path, monkeypatch):
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    config = ConfigManager(profile="sec_defaults")
    suite = SecurityValidationSuite(bus=_EventRecorder())

    result = suite.security_requirements_report(
        config.settings,
        degradation_checks={
            "clipboard_backend_fallback": True,
            "tray_backend_fallback": True,
            "panic_handler_isolated": True,
        },
    )

    assert result.name == "security_requirements"
    assert result.passed is True
    assert result.details["fail_secure_defaults"] is True
    assert result.details["graceful_degradation"] is True
    assert "constant_time_compare" in result.details["public_mechanisms"]


def test_sec_1_missing_layer(tmp_path, monkeypatch):
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    config = ConfigManager(profile="sec_missing")
    suite = SecurityValidationSuite(bus=_EventRecorder())

    result = suite.security_requirements_report({**config.settings, "memory_protection_enabled": False})

    assert result.passed is False
    assert "memory" in result.details["missing_layers"]
    assert any("memory" in warning for warning in result.warnings)


def test_plat_1_windows():
    bus = _EventRecorder()
    manager = PlatformSecurityManager(
        {
            "platform_secure_storage_enabled": True,
            "windows_credential_guard_enabled": True,
            "windows_secure_desktop_enabled": True,
        },
        bus=bus,
        system_name="Windows",
    )

    status = manager.detect_capabilities()

    assert status.system == "Windows"
    assert {"credential_guard", "windows_hello", "secure_desktop"} <= set(status.capabilities)
    assert manager.should_use_secure_desktop() is True
    assert status.secure_storage_backend in {"windows-credential-guard", "encrypted-config-fallback"}
    assert "PlatformSecurityChecked" in bus.names()


def test_plat_2_macos():
    manager = PlatformSecurityManager(system_name="Darwin", bus=_EventRecorder())

    status = manager.detect_capabilities()
    report = manager.platform_requirements_report()

    assert status.system == "Darwin"
    assert {"keychain_services", "touch_id", "gatekeeper"} <= set(status.capabilities)
    assert status.secure_storage_backend in {"macos-keychain", "encrypted-config-fallback"}
    assert "policy_hints" in report


def test_plat_3_linux():
    manager = PlatformSecurityManager(system_name="Linux", bus=_EventRecorder())

    status = manager.detect_capabilities()

    assert status.system == "Linux"
    assert {"kernel_keyring", "systemd_user_service", "lsm_policy"} <= set(status.capabilities)
    assert status.secure_storage_backend in {"linux-kernel-keyring", "encrypted-config-fallback"}
    assert manager.should_use_secure_desktop() is False


def test_plat_unknown():
    manager = PlatformSecurityManager(system_name="Plan9", bus=_EventRecorder())

    status = manager.detect_capabilities()

    assert status.system == "Plan9"
    assert status.secure_storage_backend == "encrypted-config-fallback"
    assert status.warnings

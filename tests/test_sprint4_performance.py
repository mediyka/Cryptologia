import gc
import os
import sys
import time
import tracemalloc

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from core.clipboard.clipboard_monitor import ClipboardMonitor
from core.clipboard.clipboard_service import ClipboardService
from core.clipboard.platform_adapter import InMemoryClipboardAdapter
from core.events import EventBus


class UnlockedState:
    is_locked = False


class MemoryConfig(dict):
    def set(self, key, value):
        self[key] = value


def make_service():
    adapter = InMemoryClipboardAdapter()
    service = ClipboardService(
        platform_adapter=adapter,
        event_system=EventBus(),
        config=MemoryConfig({"clipboard_timeout": "never"}),
        state=UnlockedState(),
        register_exit_handler=False,
    )
    return service, adapter


def test_perf_1_copy_operation_completes_under_100ms():
    service, adapter = make_service()
    samples = []

    for index in range(50):
        start = time.perf_counter()
        assert service.copy_password(f"perf-secret-{index}", source_entry_id=f"entry-{index}")
        elapsed = time.perf_counter() - start
        samples.append(elapsed)

    assert adapter.get_clipboard_content() == "perf-secret-49"
    assert max(samples) < 0.100


def test_perf_2_clipboard_monitor_uses_less_than_one_percent_cpu_when_idle():
    service, _ = make_service()
    monitor = ClipboardMonitor(service, interval_seconds=1.0)

    cpu_start = time.process_time()
    wall_start = time.perf_counter()
    monitor.start()
    try:
        time.sleep(2.2)
    finally:
        monitor.stop()

    cpu_elapsed = time.process_time() - cpu_start
    wall_elapsed = time.perf_counter() - wall_start
    cpu_percent = (cpu_elapsed / wall_elapsed) * 100

    assert cpu_percent < 1.0


def test_perf_3_clipboard_system_memory_overhead_is_under_10mb():
    gc.collect()
    tracemalloc.start()
    try:
        service, _ = make_service()
        payload = "x" * 1024

        for index in range(100):
            assert service.copy_password(f"{payload}-{index}", source_entry_id=f"entry-{index}")

        current, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()

    ten_mb = 10 * 1024 * 1024
    assert current < ten_mb
    assert peak < ten_mb

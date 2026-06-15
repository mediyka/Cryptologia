import statistics
import time
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from core.events import event_bus

from .memory_guard import SecureMemory, get_secure_memory
from .platform_security import PlatformSecurityManager
from .side_channel_protection import constant_time_compare


@dataclass
class SecurityValidationResult:
    """Описывает публичный класс SecurityValidationResult."""
    name: str
    passed: bool
    details: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


class SecurityValidationSuite:
    """Набор проверок безопасности Sprint 7 для тестов и ручной диагностики."""

    def __init__(self, bus=event_bus):
        self.bus = bus

    def timing_attack_test(
        self,
        operation: Optional[Callable[[bytes, bytes], bool]] = None,
        iterations: int = 100,
        max_ratio_delta: float = 0.35,
    ) -> SecurityValidationResult:
        """Описывает публичное действие timing attack test."""
        operation = operation or constant_time_compare
        iterations = max(10, int(iterations or 10))
        equal_times = self._measure(operation, b"A" * 32, b"A" * 32, iterations)
        different_times = self._measure(operation, b"A" * 32, b"B" * 32, iterations)
        equal_average = statistics.fmean(equal_times)
        different_average = statistics.fmean(different_times)
        ratio_delta = abs(equal_average - different_average) / max(equal_average, different_average, 1e-9)
        passed = ratio_delta <= max_ratio_delta
        result = SecurityValidationResult(
            "timing_attack",
            passed,
            {
                "iterations": iterations,
                "equal_average": equal_average,
                "different_average": different_average,
                "ratio_delta": ratio_delta,
                "max_ratio_delta": max_ratio_delta,
            },
        )
        self.bus.publish("SecurityValidationCompleted", result.__dict__)
        return result

    def memory_plaintext_scan(
        self,
        secret: bytes,
        memory: Optional[SecureMemory] = None,
    ) -> SecurityValidationResult:
        """Описывает публичное действие memory plaintext scan."""
        memory = memory or get_secure_memory()
        found = False
        for allocation in list(getattr(memory, "_allocations", {}).values()):
            if secret and secret in bytes(allocation.buffer):
                found = True
                break
        result = SecurityValidationResult(
            "memory_plaintext_scan",
            not found,
            {"secret_size": len(secret), "tracked_allocations": len(getattr(memory, "_allocations", {}))},
        )
        self.bus.publish("SecurityValidationCompleted", result.__dict__)
        return result

    def auto_lock_reliability_test(self, monitor, idle_seconds: float) -> SecurityValidationResult:
        """Описывает публичное действие auto lock reliability test."""
        monitor.last_activity = time.monotonic() - float(idle_seconds)
        should_lock = bool(monitor.should_lock())
        result = SecurityValidationResult(
            "auto_lock_reliability",
            should_lock,
            {"idle_seconds": idle_seconds, "timeout_seconds": getattr(monitor, "timeout_seconds", None)},
        )
        self.bus.publish("SecurityValidationCompleted", result.__dict__)
        return result

    def panic_stress_test(self, panic_mode, methods: Iterable[str]) -> SecurityValidationResult:
        """Описывает публичное действие panic stress test."""
        activations = 0
        recoveries = 0
        for method in methods:
            if panic_mode.activate(method):
                activations += 1
            if panic_mode.recover(f"{method}_recovery"):
                recoveries += 1
        passed = activations == recoveries and activations > 0
        result = SecurityValidationResult(
            "panic_stress",
            passed,
            {"activations": activations, "recoveries": recoveries},
        )
        self.bus.publish("SecurityValidationCompleted", result.__dict__)
        return result

    def integration_report(self, capabilities: dict) -> SecurityValidationResult:
        """Описывает публичное действие integration report."""
        required = {
            "vault_memory_protection",
            "clipboard_memory_protection",
            "panic_clipboard_clear",
            "audit_security_events",
            "import_export_panic_interrupt",
        }
        missing = sorted(key for key in required if not capabilities.get(key))
        result = SecurityValidationResult(
            "integration_points",
            not missing,
            {"checked": sorted(required), "missing": missing},
            warnings=[f"Missing integration: {key}" for key in missing],
        )
        self.bus.publish("SecurityValidationCompleted", result.__dict__)
        return result

    def constant_time_overhead_test(
        self,
        baseline: Callable[[], object],
        protected: Callable[[], object],
        iterations: int = 100,
        max_overhead_ratio: float = 0.10,
    ) -> SecurityValidationResult:
        """Описывает публичное действие constant time overhead test."""
        iterations = max(10, int(iterations or 10))
        baseline_average = self._measure_callable(baseline, iterations)
        protected_average = self._measure_callable(protected, iterations)
        overhead_ratio = (protected_average - baseline_average) / max(baseline_average, 1e-9)
        result = SecurityValidationResult(
            "constant_time_overhead",
            overhead_ratio <= max_overhead_ratio,
            {
                "iterations": iterations,
                "baseline_average": baseline_average,
                "protected_average": protected_average,
                "overhead_ratio": overhead_ratio,
                "max_overhead_ratio": max_overhead_ratio,
            },
        )
        self.bus.publish("SecurityValidationCompleted", result.__dict__)
        return result

    def memory_overhead_test(
        self,
        allocation_size: int = 4096,
        max_overhead_ratio: float = 0.05,
        memory: Optional[SecureMemory] = None,
    ) -> SecurityValidationResult:
        """Описывает публичное действие memory overhead test."""
        memory = memory or SecureMemory({"memory_lock_enabled": False})
        buffer = memory.allocate_secure(allocation_size)
        allocation = memory.get_allocation(buffer)
        protected_size = len(allocation.buffer) if allocation else len(buffer)
        memory.free_secure(buffer)
        overhead_ratio = (protected_size - allocation_size) / max(allocation_size, 1)
        result = SecurityValidationResult(
            "memory_overhead",
            overhead_ratio <= max_overhead_ratio,
            {
                "allocation_size": allocation_size,
                "protected_size": protected_size,
                "overhead_ratio": overhead_ratio,
                "max_overhead_ratio": max_overhead_ratio,
            },
        )
        self.bus.publish("SecurityValidationCompleted", result.__dict__)
        return result

    def idle_cpu_overhead_test(
        self,
        duration_seconds: float = 0.05,
        max_cpu_fraction: float = 0.01,
        idle_callback: Optional[Callable[[], object]] = None,
    ) -> SecurityValidationResult:
        """Описывает публичное действие idle cpu overhead test."""
        started_cpu = time.process_time()
        started_wall = time.perf_counter()
        deadline = started_wall + max(0.01, float(duration_seconds))
        while time.perf_counter() < deadline:
            if idle_callback:
                idle_callback()
            time.sleep(0.005)
        raw_cpu_fraction = (time.process_time() - started_cpu) / max(time.perf_counter() - started_wall, 1e-9)
        cpu_fraction = max(0.0, min(raw_cpu_fraction, 1.0))
        result = SecurityValidationResult(
            "idle_cpu_overhead",
            cpu_fraction <= max_cpu_fraction,
            {
                "cpu_fraction": cpu_fraction,
                "raw_cpu_fraction": raw_cpu_fraction,
                "max_cpu_fraction": max_cpu_fraction,
            },
        )
        self.bus.publish("SecurityValidationCompleted", result.__dict__)
        return result

    def startup_time_test(
        self,
        startup_callable: Callable[[], object],
        max_seconds: float = 3.0,
    ) -> SecurityValidationResult:
        """Описывает публичное действие startup time test."""
        started = time.perf_counter()
        startup_callable()
        elapsed = time.perf_counter() - started
        result = SecurityValidationResult(
            "startup_time",
            elapsed <= max_seconds,
            {"elapsed_seconds": elapsed, "max_seconds": max_seconds},
        )
        self.bus.publish("SecurityValidationCompleted", result.__dict__)
        return result

    def security_requirements_report(self, settings: dict, degradation_checks: Optional[dict] = None) -> SecurityValidationResult:
        """Описывает публичное действие security requirements report."""
        degradation_checks = degradation_checks or {}
        layers = {
            "side_channel": bool(settings.get("side_channel_protection_enabled", True)),
            "memory": bool(settings.get("memory_protection_enabled", True)),
            "activity": int(settings.get("activity_lock_timeout_seconds", 300) or 0) <= 300,
            "panic": bool(settings.get("panic_mode_enabled", True)),
            "audit": bool(settings.get("audit_enabled", True)),
            "platform": bool(settings.get("platform_secure_storage_enabled", True)),
        }
        fail_secure_defaults = (
            layers["side_channel"]
            and layers["memory"]
            and layers["activity"]
            and layers["panic"]
            and layers["platform"]
            and bool(settings.get("cache_timing_protection", True))
        )
        public_mechanisms = [
            "constant_time_compare",
            "secure_memory_wipe",
            "activity_auto_lock",
            "panic_mode",
            "audit_events",
            "platform_security_fallbacks",
        ]
        platform_report = PlatformSecurityManager(settings, bus=self.bus).platform_requirements_report()
        graceful_degradation = all(bool(value) for value in degradation_checks.values()) if degradation_checks else True
        missing_layers = sorted(key for key, enabled in layers.items() if not enabled)
        passed = not missing_layers and fail_secure_defaults and bool(public_mechanisms) and graceful_degradation
        result = SecurityValidationResult(
            "security_requirements",
            passed,
            {
                "layers": layers,
                "missing_layers": missing_layers,
                "fail_secure_defaults": fail_secure_defaults,
                "public_mechanisms": public_mechanisms,
                "graceful_degradation": graceful_degradation,
                "platform": platform_report,
            },
            warnings=[f"Disabled protection layer: {key}" for key in missing_layers],
        )
        self.bus.publish("SecurityValidationCompleted", result.__dict__)
        return result

    @staticmethod
    def _measure(operation: Callable[[bytes, bytes], bool], left: bytes, right: bytes, iterations: int) -> list[float]:
        timings = []
        for _ in range(iterations):
            started = time.perf_counter()
            operation(left, right)
            timings.append(time.perf_counter() - started)
        return timings

    @staticmethod
    def _measure_callable(operation: Callable[[], object], iterations: int) -> float:
        timings = []
        for _ in range(iterations):
            started = time.perf_counter()
            operation()
            timings.append(time.perf_counter() - started)
        return statistics.fmean(timings)

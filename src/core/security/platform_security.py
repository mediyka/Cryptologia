import os
import platform
import shutil
from dataclasses import dataclass, field
from typing import Optional

from core.events import event_bus


@dataclass
class PlatformCapability:
    """Состояние одной платформенной возможности безопасности."""

    name: str
    available: bool
    enabled: bool = False
    details: str = ""
    fallback: str = ""


@dataclass
class PlatformSecurityStatus:
    """Сводка платформенных возможностей и выбранного безопасного fallback."""

    system: str
    capabilities: dict[str, PlatformCapability] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    secure_storage_backend: str = "encrypted-config-fallback"


class PlatformSecurityManager:
    """Best-effort интеграция с механизмами безопасности конкретной ОС.

    Класс намеренно не требует внешних пакетов и привилегированных вызовов:
    он обнаруживает доступные точки интеграции, выбирает безопасный backend
    хранения и публикует события для аудита. Реальные нативные адаптеры можно
    подключить позднее за этим стабильным интерфейсом.
    """

    def __init__(self, config: Optional[dict] = None, bus=event_bus, system_name: Optional[str] = None):
        self.config = config or {}
        self.bus = bus
        self.system = system_name or platform.system()
        self._last_status: Optional[PlatformSecurityStatus] = None

    def detect_capabilities(self) -> PlatformSecurityStatus:
        """Описывает публичное действие detect capabilities."""
        normalized = self._normalize_system(self.system)
        if normalized == "Windows":
            status = self._detect_windows()
        elif normalized == "Darwin":
            status = self._detect_macos()
        elif normalized == "Linux":
            status = self._detect_linux()
        else:
            status = PlatformSecurityStatus(
                system=self.system or "Unknown",
                warnings=["Unsupported platform; encrypted local fallback is used."],
            )

        status.secure_storage_backend = self.select_secure_storage_backend(status)
        self._last_status = status
        self.bus.publish(
            "PlatformSecurityChecked",
            {
                "system": status.system,
                "secure_storage_backend": status.secure_storage_backend,
                "capabilities": {
                    key: {
                        "available": capability.available,
                        "enabled": capability.enabled,
                        "fallback": capability.fallback,
                    }
                    for key, capability in status.capabilities.items()
                },
                "warnings": list(status.warnings),
            },
        )
        return status

    def select_secure_storage_backend(self, status: Optional[PlatformSecurityStatus] = None) -> str:
        """Описывает публичное действие select secure storage backend."""
        status = status or self._last_status or self.detect_capabilities()
        if not self._enabled("platform_secure_storage_enabled", True):
            return "encrypted-config-fallback"
        if status.system == "Windows" and status.capabilities.get("credential_guard", PlatformCapability("", False)).enabled:
            return "windows-credential-guard"
        if status.system == "Darwin" and status.capabilities.get("keychain_services", PlatformCapability("", False)).enabled:
            return "macos-keychain"
        if status.system == "Linux" and status.capabilities.get("kernel_keyring", PlatformCapability("", False)).enabled:
            return "linux-kernel-keyring"
        return "encrypted-config-fallback"

    def should_use_secure_desktop(self) -> bool:
        """Описывает публичное действие should use secure desktop."""
        if self._normalize_system(self.system) != "Windows":
            return False
        status = self._last_status or self.detect_capabilities()
        capability = status.capabilities.get("secure_desktop")
        return bool(capability and capability.enabled)

    def build_policy_hints(self, status: Optional[PlatformSecurityStatus] = None) -> list[str]:
        """Описывает публичное действие build policy hints."""
        status = status or self._last_status or self.detect_capabilities()
        hints = []
        if status.system == "Windows":
            hints.append("Use Secure Desktop for master password prompts.")
            if not status.capabilities.get("credential_guard", PlatformCapability("", False)).available:
                hints.append("Enable Windows Credential Guard where supported by the OS and hardware.")
        elif status.system == "Darwin":
            hints.append("Store integration secrets in Keychain Services.")
            hints.append("Distribute signed and notarized builds for Gatekeeper.")
        elif status.system == "Linux":
            hints.append("Prefer kernel keyring for short-lived secrets.")
            hints.append("Install systemd user service and SELinux/AppArmor profile where available.")
        else:
            hints.append("Use encrypted application storage and fail closed when native APIs are unavailable.")
        return hints

    def platform_requirements_report(self) -> dict:
        """Описывает публичное действие platform requirements report."""
        status = self.detect_capabilities()
        required = {
            "Windows": {"credential_guard", "secure_desktop"},
            "Darwin": {"keychain_services", "gatekeeper"},
            "Linux": {"kernel_keyring", "systemd_user_service", "lsm_policy"},
        }.get(status.system, set())
        missing = sorted(
            key
            for key in required
            if key not in status.capabilities or not status.capabilities[key].available
        )
        return {
            "system": status.system,
            "secure_storage_backend": status.secure_storage_backend,
            "missing": missing,
            "warnings": list(status.warnings),
            "policy_hints": self.build_policy_hints(status),
        }

    def _detect_windows(self) -> PlatformSecurityStatus:
        status = PlatformSecurityStatus(system="Windows")
        credential_guard_available = self._windows_credential_guard_hint()
        self._add_capability(
            status,
            "credential_guard",
            credential_guard_available,
            "windows_credential_guard_enabled",
            "Credential Guard API integration point is enabled.",
            "Use encrypted local storage and require master password re-authentication.",
        )
        self._add_capability(
            status,
            "windows_hello",
            self._windows_hello_hint(),
            "windows_hello_enabled",
            "Windows Hello can be used as an optional unlock factor.",
            "Continue using master password authentication.",
            optional=True,
        )
        self._add_capability(
            status,
            "secure_desktop",
            True,
            "windows_secure_desktop_enabled",
            "Secure Desktop password prompt mode is available on Windows.",
            "Keep password prompts modal and clear sensitive fields on failure.",
        )
        return status

    def _detect_macos(self) -> PlatformSecurityStatus:
        status = PlatformSecurityStatus(system="Darwin")
        self._add_capability(
            status,
            "keychain_services",
            bool(shutil.which("security")),
            "macos_keychain_enabled",
            "Keychain Services command line bridge is available.",
            "Use encrypted local storage protected by the master password.",
        )
        self._add_capability(
            status,
            "touch_id",
            os.path.exists("/System/Library/Frameworks/LocalAuthentication.framework"),
            "macos_touch_id_enabled",
            "LocalAuthentication framework is available for optional Touch ID.",
            "Continue using master password authentication.",
            optional=True,
        )
        self._add_capability(
            status,
            "gatekeeper",
            bool(shutil.which("spctl")),
            "macos_gatekeeper_check_enabled",
            "Gatekeeper assessment tool is available for notarization checks.",
            "Document notarization requirement for release builds.",
        )
        return status

    def _detect_linux(self) -> PlatformSecurityStatus:
        status = PlatformSecurityStatus(system="Linux")
        self._add_capability(
            status,
            "kernel_keyring",
            os.path.exists("/proc/keys") or bool(shutil.which("keyctl")),
            "linux_kernel_keyring_enabled",
            "Kernel keyring or keyctl is available for short-lived secrets.",
            "Use process memory guarded by SecureMemory.",
        )
        self._add_capability(
            status,
            "systemd_user_service",
            bool(shutil.which("systemctl")) and (os.path.exists("/run/systemd/system") or bool(os.environ.get("XDG_RUNTIME_DIR"))),
            "linux_systemd_integration_enabled",
            "systemd user service integration is available.",
            "Run background tasks inside the application process.",
        )
        self._add_capability(
            status,
            "lsm_policy",
            os.path.exists("/sys/fs/selinux")
            or os.path.exists("/sys/module/apparmor")
            or os.path.exists("/sys/kernel/security/lsm"),
            "linux_lsm_policy_enabled",
            "SELinux/AppArmor policy hook is available.",
            "Use strict file permissions and application-level validation.",
        )
        return status

    def _add_capability(
        self,
        status: PlatformSecurityStatus,
        key: str,
        available: bool,
        config_key: str,
        details: str,
        fallback: str,
        optional: bool = False,
    ):
        enabled = bool(available and self._enabled(config_key, True))
        status.capabilities[key] = PlatformCapability(
            name=key,
            available=bool(available),
            enabled=enabled,
            details=details if available else "",
            fallback=fallback,
        )
        if not available and not optional:
            status.warnings.append(f"{key} is unavailable; fallback: {fallback}")
            self.bus.publish(
                "PlatformCapabilityMissing",
                {
                    "system": status.system,
                    "capability": key,
                    "fallback": fallback,
                },
            )

    def _enabled(self, key: str, default: bool) -> bool:
        value = self.config.get(key, default)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in {"1", "true", "yes", "on"}
        return bool(value)

    @staticmethod
    def _normalize_system(system_name: str) -> str:
        normalized = (system_name or "").lower()
        if normalized.startswith("win"):
            return "Windows"
        if normalized in {"darwin", "mac", "macos"}:
            return "Darwin"
        if normalized == "linux":
            return "Linux"
        return system_name or "Unknown"

    @staticmethod
    def _windows_credential_guard_hint() -> bool:
        return os.environ.get("VBS_ENCLAVE_AVAILABLE") == "1" or os.environ.get("CREDENTIAL_GUARD_ENABLED") == "1"

    @staticmethod
    def _windows_hello_hint() -> bool:
        return os.environ.get("WINDOWS_HELLO_AVAILABLE") == "1"

"""
Фреймворк усиления безопасности для Sprint 7.

Пакет скрывает защиту от side-channel атак, управление памятью, мониторинг
активности и panic mode за небольшими сервисными классами, чтобы существующий
код хранилища, буфера обмена и GUI мог подключать их без изменения публичных API.
"""

from .side_channel_protection import SideChannelProtection, constant_time_compare
from .memory_guard import SecureMemory, SecretBuffer, SensitiveScope, StackCanary, get_secure_memory, sensitive_scope
from .activity_monitor import ActivityMonitor
from .panic_mode import PanicMode
from .platform_security import PlatformCapability, PlatformSecurityManager, PlatformSecurityStatus
from .security_validator import SecurityValidationResult, SecurityValidationSuite

__all__ = [
    "ActivityMonitor",
    "PanicMode",
    "PlatformCapability",
    "PlatformSecurityManager",
    "PlatformSecurityStatus",
    "SecretBuffer",
    "SecureMemory",
    "SensitiveScope",
    "SecurityValidationResult",
    "SecurityValidationSuite",
    "SideChannelProtection",
    "StackCanary",
    "constant_time_compare",
    "get_secure_memory",
    "sensitive_scope",
]

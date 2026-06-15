import hashlib
import hmac
import logging
import secrets
import time
from dataclasses import dataclass
from typing import Optional, Union

logger = logging.getLogger("SideChannelProtection")

BytesLike = Union[bytes, bytearray, memoryview]


@dataclass(frozen=True)
class SideChannelConfig:
    """Описывает публичный класс SideChannelConfig."""
    enabled: bool = True
    cache_timing_protection: bool = True
    normalize_crypto_timing: bool = True
    random_crypto_delay: bool = False
    random_delay_min_ms: int = 0
    random_delay_max_ms: int = 0
    max_compare_bytes: int = 4096
    max_search_bytes: int = 16384


class SideChannelProtection:
    """Помощники с постоянным временем выполнения для чувствительных сравнений и поиска."""

    def __init__(self, config: Optional[dict] = None):
        config = config or {}
        self.config = SideChannelConfig(
            enabled=bool(config.get("side_channel_protection_enabled", True)),
            cache_timing_protection=bool(config.get("cache_timing_protection", True)),
            normalize_crypto_timing=bool(config.get("normalize_crypto_timing", True)),
            random_crypto_delay=bool(config.get("random_crypto_delay", False)),
            random_delay_min_ms=int(config.get("random_delay_min_ms", 0) or 0),
            random_delay_max_ms=int(config.get("random_delay_max_ms", 0) or 0),
            max_compare_bytes=int(config.get("side_channel_max_compare_bytes", 4096) or 4096),
            max_search_bytes=int(config.get("side_channel_max_search_bytes", 16384) or 16384),
        )

    def compare(self, left: Union[str, BytesLike], right: Union[str, BytesLike]) -> bool:
        """Сравнить строки/байты без раннего выхода и ветвлений по типу."""
        if not self.config.enabled:
            return left == right
        return constant_time_compare(left, right, max_length=self.config.max_compare_bytes)

    def digest_compare(self, left: Union[str, BytesLike], right: Union[str, BytesLike]) -> bool:
        """Сравнить SHA-256 дайджесты значений, нормализуя разную длину входа."""
        left_digest = hashlib.sha256(_to_bytes(left)).digest()
        right_digest = hashlib.sha256(_to_bytes(right)).digest()
        return hmac.compare_digest(left_digest, right_digest)

    def contains(self, needle: str, haystack: str) -> bool:
        """
        Проверка подстроки фиксированным проходом по ограниченному буферу.

        Python не может сделать произвольный текстовый поиск полностью
        constant-time, но этот вариант избегает явных ранних выходов и числа
        итераций, зависящего от секрета, для ограниченного входа. Метод нужен
        для сравнений метаданных и поиска в хранилище, где важна совместимость.
        """
        if not self.config.enabled or not self.config.cache_timing_protection:
            return needle in haystack

        needle_bytes = _to_bytes(needle.lower().strip())
        haystack_bytes = _to_bytes(haystack.lower().strip())
        if not needle_bytes or not haystack_bytes:
            return False

        max_len = max(1, self.config.max_search_bytes)
        scan_len = min(max_len, max(len(haystack_bytes), len(needle_bytes)))
        haystack_padded = haystack_bytes[:scan_len].ljust(scan_len, b"\x00")
        needle_len = min(len(needle_bytes), scan_len)
        needle_padded = needle_bytes[:needle_len]

        found = 0
        last_start = scan_len - needle_len
        for index in range(scan_len):
            in_range = int(index <= last_start)
            window = haystack_padded[index:index + needle_len]
            equal = int(hmac.compare_digest(window, needle_padded))
            found |= equal & in_range
        return bool(found)

    def all_tokens_contained(self, tokens: list[str], haystack: str) -> bool:
        """Описывает публичное действие all tokens contained."""
        result = 1
        for token in tokens:
            result &= int(self.contains(token, haystack))
        return bool(result)

    def apply_crypto_jitter(self):
        """Опциональный шум против анализа энергопотребления; по безопасному умолчанию выключен."""
        if not self.config.enabled or not self.config.random_crypto_delay:
            return

        minimum = max(0, self.config.random_delay_min_ms)
        maximum = max(minimum, self.config.random_delay_max_ms)
        if maximum <= 0:
            return
        delay_ms = minimum + secrets.randbelow(maximum - minimum + 1)
        time.sleep(delay_ms / 1000.0)


def constant_time_compare(
    left: Union[str, BytesLike],
    right: Union[str, BytesLike],
    max_length: int = 4096,
) -> bool:
    """Описывает публичную операцию constant time compare."""
    left_bytes = _to_bytes(left)
    right_bytes = _to_bytes(right)
    max_length = max(1, int(max_length or 4096))

    left_len = len(left_bytes)
    right_len = len(right_bytes)
    bounded_len = min(max(left_len, right_len), max_length)

    left_padded = left_bytes[:max_length].ljust(bounded_len, b"\x00")
    right_padded = right_bytes[:max_length].ljust(bounded_len, b"\x00")
    same_content = hmac.compare_digest(left_padded, right_padded)
    same_length = hmac.compare_digest(
        left_len.to_bytes(8, "big", signed=False),
        right_len.to_bytes(8, "big", signed=False),
    )
    within_limit = left_len <= max_length and right_len <= max_length
    return bool(same_content & same_length & within_limit)


def _to_bytes(value: Union[str, BytesLike]) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8", "surrogatepass")
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, memoryview):
        return value.tobytes()
    return str(value).encode("utf-8", "surrogatepass")

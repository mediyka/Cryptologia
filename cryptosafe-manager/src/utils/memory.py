"""
Модуль для безопасной работы с памятью.
"""
import ctypes
from typing import Union


def zero_memory(data: Union[bytearray, memoryview]) -> None:
    """Безопасно затирает содержимое памяти."""
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0
        
        try:
            addr = id(data) + 32  # Смещение для CPython
            ctypes.memset(addr, 0, len(data))
        except Exception:
            pass
    
    elif isinstance(data, memoryview):
        data.release()


def secure_compare(a: bytes, b: bytes) -> bool:
    """Безопасное сравнение двух байтовых строк."""
    if len(a) != len(b):
        return False
    
    result = 0
    for x, y in zip(a, b):
        result |= x ^ y
    
    return result == 0


class SecureBytes:
    """Контекстный менеджер для безопасной работы с байтовыми данными."""
    
    def __init__(self, data: bytearray):
        self.data = data
    
    @classmethod
    def from_string(cls, data: str, encoding='utf-8'):
        return cls(bytearray(data.encode(encoding)))
    
    def __enter__(self):
        return self.data
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        zero_memory(self.data)

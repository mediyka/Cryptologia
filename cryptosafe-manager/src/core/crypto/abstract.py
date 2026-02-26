"""
Абстрактный базовый класс для криптографических сервисов.
"""
from abc import ABC, abstractmethod


class EncryptionService(ABC):
    """Абстрактный класс, определяющий интерфейс для всех шифровальных сервисов."""
    
    @abstractmethod
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        """Шифрует данные с использованием ключа."""
        pass
    
    @abstractmethod
    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        """Расшифровывает данные с использованием ключа."""
        pass
    
    @abstractmethod
    def get_name(self) -> str:
        """Возвращает название алгоритма шифрования."""
        pass


from abc import ABC, abstractmethod

class EncryptionService(ABC):
    """Определяет общий интерфейс сервиса шифрования."""

    @abstractmethod
    def encrypt(self, data: bytes) -> bytes:
        """Зашифровать данные, используя ключ из KeyManager."""
        pass

    @abstractmethod
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Расшифровать данные."""
        pass

    def set_key_manager(self, key_manager):
        """ARC-2: Метод для внедрения KeyManager."""
        self.key_manager = key_manager

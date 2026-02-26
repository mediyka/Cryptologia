"""
Реализация криптографического сервиса-заглушки на основе XOR.
ВНИМАНИЕ: Этот алгоритм НЕ безопасен и используется только для обучения!
"""
from .abstract import EncryptionService
import hashlib


class XORPlaceholder(EncryptionService):
    """Класс-заглушка, реализующий шифрование XOR."""
    
    def __init__(self):
        self._name = "XOR Placeholder (INSECURE - FOR EDUCATION ONLY)"
        self._key_size = 32
    
    def _prepare_key(self, key: bytes) -> bytes:
        """Подготавливает ключ: дополняет до нужной длины через SHA256."""
        if len(key) >= self._key_size:
            return key[:self._key_size]
        
        hasher = hashlib.sha256()
        hasher.update(key)
        return hasher.digest()
    
    def encrypt(self, data: bytes, key: bytes) -> bytes:
        """Шифрует данные XOR с подготовленным ключом."""
        if not data:
            return b''
        
        prepared_key = self._prepare_key(key)
        result = bytearray()
        
        key_len = len(prepared_key)
        for i, byte in enumerate(data):
            result.append(byte ^ prepared_key[i % key_len])
        
        return bytes(result)
    
    def decrypt(self, ciphertext: bytes, key: bytes) -> bytes:
        """Расшифровывает данные (XOR симметричен)."""
        return self.encrypt(ciphertext, key)
    
    def get_name(self) -> str:
        return self._name

"""
Менеджер ключей.
"""
import os
import hashlib
from typing import Optional, Tuple
from ..utils.memory import zero_memory


class KeyManager:
    """Управляет ключами шифрования."""
    
    def __init__(self):
        self.current_key = None
        self.current_salt = None
    
    def derive_key(self, password: str, salt: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """Генерирует ключ из пароля с солью."""
        if salt is None:
            salt = os.urandom(16)
        
        # Упрощенная KDF для демонстрации
        key_material = password.encode('utf-8') + salt
        key = hashlib.sha256(key_material).digest()
        
        return key, salt
    
    def clear_key(self) -> None:
        """Безопасно удаляет текущий ключ из памяти."""
        if self.current_key:
            zero_memory(bytearray(self.current_key))
            self.current_key = None
        self.current_salt = None

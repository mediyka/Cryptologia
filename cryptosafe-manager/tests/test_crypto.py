"""
Тесты криптографического модуля.
"""
import pytest
from src.core.crypto.placeholder import XORPlaceholder


def test_xor_encrypt_decrypt():
    """Тест шифрования и расшифровки."""
    crypto = XORPlaceholder()
    key = b"test_key_123"
    data = b"secret_password"
    
    encrypted = crypto.encrypt(data, key)
    decrypted = crypto.decrypt(encrypted, key)
    
    assert decrypted == data
    assert encrypted != data


def test_xor_different_keys():
    """Тест с разными ключами."""
    crypto = XORPlaceholder()
    data = b"test_data"
    
    enc1 = crypto.encrypt(data, b"key1")
    enc2 = crypto.encrypt(data, b"key2")
    
    assert enc1 != enc2

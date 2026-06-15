"""
AES-256-GCM Encryption Service.
Реализует требования ENC-1 — ENC-5:
  ENC-1: AES-256-GCM через cryptography.hazmat.primitives.ciphers.aead.AESGCM
  ENC-2: Уникальный 12-byte nonce через os.urandom(12)
  ENC-3: Payload — JSON с полями + timestamp + version
  ENC-4: Формат хранения: nonce (12B) || ciphertext || tag (16B)
  ENC-5: Валидация authentication tag при расшифровке
"""

import os
import json
import logging
from typing import Optional, Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag
from core.security.side_channel_protection import SideChannelProtection

logger = logging.getLogger("AES256GCMService")

NONCE_SIZE = 12
TAG_SIZE = 16
VERSION = 1


class AES256GCMService:
    """Сервис аутентифицированного шифрования AES-256-GCM."""

    def __init__(self):
        self._aesgcm: Optional[AESGCM] = None
        self._key_manager = None
        self._active_key: Optional[bytes] = None
        self._side_channel = SideChannelProtection()

    def set_key_manager(self, key_manager):
        """ARC-2: Внедрение зависимости KeyManager."""
        self._key_manager = key_manager
        self._side_channel = SideChannelProtection(getattr(key_manager, "config", {}) or {})
        self._aesgcm = None
        self._active_key = None

    def _get_normalized_key(self) -> bytes:
        """Инициализация AESGCM с ключом из KeyManager."""
        if self._key_manager is None:
            raise RuntimeError("KeyManager not set. Call set_key_manager() first.")

        key = self._key_manager.storage.get_key()
        if key is None:
            self._aesgcm = None
            self._active_key = None
            raise RuntimeError("Encryption key not available in KeyManager.")

        if len(key) != 32:
            raise ValueError(f"AES-256-GCM requires a 32-byte key, got {len(key)} bytes.")

        return key

    def _ensure_cipher(self):
        """Ленивая инициализация шифра после появления ключа в памяти."""
        key = self._get_normalized_key()
        key_changed = self._active_key is None or not self._side_channel.compare(self._active_key, key)
        if self._aesgcm is None or key_changed:
            self._aesgcm = AESGCM(key)
            self._active_key = key
            logger.debug("AES-256-GCM cipher initialized")

    def encrypt(self, data: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Зашифровать данные.

        Args:
            data: Байты для шифрования
            associated_data: Опциональные данные для аутентификации (AAD)

        Returns:
            BLOB формата: nonce (12B) || ciphertext || tag (16B)
        """
        self._side_channel.apply_crypto_jitter()
        self._ensure_cipher()

        # ENC-2: Уникальный 12-байтовый nonce
        nonce = os.urandom(NONCE_SIZE)

        # Шифрование (AESGCM.encrypt автоматически добавляет 16-byte tag)
        ciphertext = self._aesgcm.encrypt(nonce, data, associated_data)

        # ENC-4: Формат nonce || шифртекст || tag
        # Шифртекст уже включает tag в конце (AESGCM.encrypt возвращает шифртекст + tag)
        encrypted_blob = nonce + ciphertext

        logger.debug(f"Encrypted {len(data)} bytes -> {len(encrypted_blob)} bytes")
        return encrypted_blob

    def decrypt(self, encrypted_blob: bytes, associated_data: Optional[bytes] = None) -> bytes:
        """
        Расшифровать данные с валидацией authentication tag.

        Args:
            encrypted_blob: BLOB формата nonce (12B) || ciphertext || tag (16B)
            associated_data: Опциональные данные для аутентификации (AAD)

        Returns:
            Расшифрованные байты

        Raises:
            ValueError: Если blob слишком короткий или tag невалиден
        """
        self._side_channel.apply_crypto_jitter()
        self._ensure_cipher()

        # ENC-4: Извлекаем nonce и шифртекст + tag
        if len(encrypted_blob) < NONCE_SIZE + TAG_SIZE:
            raise ValueError(f"Encrypted blob too short: {len(encrypted_blob)} bytes")

        nonce = encrypted_blob[:NONCE_SIZE]
        ciphertext_with_tag = encrypted_blob[NONCE_SIZE:]

        try:
            # ENC-5: Валидация тега аутентификации происходит автоматически
            plaintext = self._aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
            logger.debug(f"Decrypted {len(encrypted_blob)} bytes -> {len(plaintext)} bytes")
            return plaintext
        except InvalidTag:
            logger.error("Authentication tag validation failed — possible tampering!")
            raise ValueError("Не удалось расшифровать данные: проверка подлинности не пройдена. Возможно, данные были изменены.")

    @staticmethod
    def encrypt_dict(data: Dict[str, Any], key_manager=None, associated_data: Optional[bytes] = None) -> bytes:
        """
        Зашифровать словарь как JSON payload (ENC-3).

        Args:
            data: Словарь с данными записи
            key_manager: KeyManager с ключом
            associated_data: AAD

        Returns:
            Зашифрованный BLOB
        """
        service = AES256GCMService()
        if key_manager:
            service.set_key_manager(key_manager)

        payload = json.dumps(data, ensure_ascii=False).encode('utf-8')
        return service.encrypt(payload, associated_data)

    @staticmethod
    def decrypt_dict(encrypted_blob: bytes, key_manager=None, associated_data: Optional[bytes] = None) -> Dict[str, Any]:
        """
        Расшифровать BLOB в словарь (ENC-3).

        Args:
            encrypted_blob: Зашифрованный BLOB
            key_manager: KeyManager с ключом
            associated_data: AAD

        Returns:
            Расшифрованный словарь
        """
        service = AES256GCMService()
        if key_manager:
            service.set_key_manager(key_manager)

        plaintext = service.decrypt(encrypted_blob, associated_data)
        return json.loads(plaintext.decode('utf-8'))

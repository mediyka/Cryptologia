import logging
import threading
import time
from typing import TYPE_CHECKING, Optional, Callable
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from .crypto.key_derivation import KeyDerivationService
from .crypto.key_storage import SecureMemoryCache
from .crypto.authentication import AuthenticationService, DEFAULT_AUTO_LOCK_TIMEOUT
from .events import event_bus

if TYPE_CHECKING:
    from src.database.db import DatabaseHelper
    from src.core.vault_manager import VaultManager

logger = logging.getLogger("KeyManager")

AUDIT_SIGNING_PURPOSE = "audit-signing"


class KeyManager:
    """Управляет мастер-ключом, сессией и блокировкой хранилища."""
    def __init__(self, db_helper: 'DatabaseHelper', config: dict = None):
        self.db = db_helper
        self.config = config or {}
        self.derivation = KeyDerivationService(self.config)
        self.storage = SecureMemoryCache(self.config)
        self.auth = AuthenticationService()
        
        # Таймер авто-блокировки (CACHE-2, FUTURE-3)
        self._auto_lock_timer: Optional[threading.Timer] = None
        self._auto_lock_callback: Optional[Callable] = None
        self._lock = threading.Lock()
        
        # Настройка из конфига
        auto_lock_timeout = self.config.get('auto_lock_timeout', DEFAULT_AUTO_LOCK_TIMEOUT)
        self.auth.set_auto_lock_timeout(auto_lock_timeout)
        self.auth.set_auto_lock_on_minimize(self.config.get('auto_lock_on_minimize', True))

    def set_auto_lock_callback(self, callback: Callable):
        """Установка callback-функции для авто-блокировки (FUTURE-3)."""
        self._auto_lock_callback = callback

    def _start_auto_lock_timer(self):
        """Запуск таймера авто-блокировки (CACHE-2, FUTURE-3)."""
        self._cancel_auto_lock_timer()
        
        timeout = self.auth.session.auto_lock_timeout
        if timeout > 0:
            self._auto_lock_timer = threading.Timer(timeout, self._auto_lock_trigger)
            self._auto_lock_timer.daemon = True
            self._auto_lock_timer.start()
            logger.debug(f"Auto-lock timer started for {timeout}s")

    def _cancel_auto_lock_timer(self):
        """Отмена таймера авто-блокировки."""
        if self._auto_lock_timer is not None:
            self._auto_lock_timer.cancel()
            self._auto_lock_timer = None

    def _auto_lock_trigger(self):
        """Срабатывание авто-блокировки."""
        with self._lock:
            if self.auth.is_session_active() and self.auth.is_idle_expired():
                logger.info("Auto-lock triggered due to inactivity")
                self.lock()
                if self._auto_lock_callback:
                    try:
                        self._auto_lock_callback()
                    except Exception as e:
                        logger.error(f"Auto-lock callback error: {e}")

    def _check_and_lock_if_needed(self):
        """Проверка необходимости блокировки при активности."""
        with self._lock:
            if self.auth.is_session_active():
                self.auth.update_activity()
                self._start_auto_lock_timer()

    def setup_new_vault(self, password: str) -> bool:
        """Описывает публичное действие setup new vault."""
        try:
            auth_hash = self.derivation.create_auth_hash(password)
            enc_salt = self.derivation.generate_salt()
            
            self.db.execute("DELETE FROM key_store") 
            self.db.execute(
                "INSERT INTO key_store (key_type, key_data) VALUES (?, ?)", 
                ("auth_hash", auth_hash.encode('utf-8'))
            )
            self.db.execute(
                "INSERT INTO key_store (key_type, key_data) VALUES (?, ?)", 
                ("enc_salt", enc_salt)
            )
            
            enc_key = self.derivation.derive_encryption_key(password, enc_salt)
            self.storage.store_key(enc_key)
            logger.info("Vault setup complete.")
            return True
        except Exception as e:
            logger.error(f"Setup failed: {e}")
            return False

    def unlock(self, password: str) -> bool:
        """Разблокировка хранилища с запуском сессии (AUTH-4, CACHE-2)."""
        if self.auth.is_locked_out():
            raise PermissionError(f"Blocked. Wait {self.auth.get_remaining_lockout_time()}s.")

        row_hash = self.db.fetchone("SELECT key_data FROM key_store WHERE key_type = 'auth_hash'")
        row_salt = self.db.fetchone("SELECT key_data FROM key_store WHERE key_type = 'enc_salt'")

        if not row_hash or not row_salt:
            logger.error("Keys not found in DB.")
            return False

        stored_hash = row_hash[0].decode('utf-8')
        enc_salt = row_salt[0]

        if self.derivation.verify_password(password, stored_hash):
            self.auth.reset_attempts()
            enc_key = self.derivation.derive_encryption_key(password, enc_salt)
            self.storage.store_key(enc_key)
            
            # Запуск сессии (AUTH-4)
            self.auth.start_session()
            self._start_auto_lock_timer()
            
            # Публикация события (AUTH-2)
            event_bus.publish("UserLoggedIn", data={"timestamp": time.time()})
            
            logger.info("Vault unlocked.")
            return True
        else:
            self.auth.register_failed_attempt()
            return False

    def lock(self):
        """Блокировка хранилища с завершением сессии (AUTH-4, CACHE-2, FUTURE-3)."""
        self._cancel_auto_lock_timer()
        self.auth.end_session()
        self.storage.clear_key()
        event_bus.publish("UserLoggedOut")
        logger.info("Vault locked.")

    def touch(self):
        """Обновление активности пользователя (CACHE-2)."""
        self._check_and_lock_if_needed()

    def derive_key(self, purpose: str, length: int = 32) -> bytes:
        """Описывает публичное действие derive key."""
        base_key = self.storage.get_key()
        if base_key is None:
            raise RuntimeError("Vault key is not available. Unlock the vault first.")
        if not purpose:
            raise ValueError("Key derivation purpose is required.")

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=b"cryptosafe-manager:v1",
            info=purpose.encode("utf-8"),
        )
        return hkdf.derive(base_key)

    def derive_audit_signing_key(self, length: int = 32) -> bytes:
        """Вывести ключ подписи аудита Sprint 5 с разделением ключей."""
        return self.derive_key(AUDIT_SIGNING_PURPOSE, length)

    def on_minimize(self):
        """Обработчик сворачивания приложения (CACHE-2)."""
        if self.auth.session.auto_lock_on_minimize and self.auth.is_session_active():
            logger.info("Auto-lock on minimize triggered")
            self.lock()

    #СМЕНА ПАРОЛЯ 

    def change_password(self, old_password: str, new_password: str, entry_manager: 'EntryManager', crypto_service) -> bool:
        # 1. Валидация нового пароля ПЕРЕД любыми операциями
        """Описывает публичное действие change password."""
        valid, msg = self.auth.validate_password_strength(new_password)
        if not valid:
            raise ValueError(msg)

        # 2. Проверка старого пароля
        if not self.unlock(old_password):
            raise ValueError("Неверный текущий пароль.")

        # Сохраняем старые ключи для отката
        old_auth_hash = self.db.fetchone("SELECT key_data FROM key_store WHERE key_type = 'auth_hash'")[0]
        old_enc_salt = self.db.fetchone("SELECT key_data FROM key_store WHERE key_type = 'enc_salt'")[0]
        old_key_bytes = self.storage.get_key()

        try:
            # 3. Получаем все данные и готовим атомарную перешифровку.
            # CHANGE-2/CHANGE-4: либо перешифровываются все записи, либо не меняется ничего.
            raw_entries = self.db.fetchall("SELECT id, encrypted_data FROM vault_entries")

            # 4. Генерируем новые ключи
            new_auth_hash = self.derivation.create_auth_hash(new_password)
            new_enc_salt = self.derivation.generate_salt()
            new_enc_key = self.derivation.derive_encryption_key(new_password, new_enc_salt)

            re_encrypted_data = []
            failed_entries = []

            from core.vault.encryption_service import AES256GCMService

            decrypt_service = AES256GCMService()
            decrypt_service.set_key_manager(self)

            temp_storage = SecureMemoryCache(self.config)
            temp_storage.store_key(new_enc_key)
            encrypt_service = AES256GCMService()
            fake_km = type('FakeKM', (), {'storage': temp_storage, 'config': self.config})()
            encrypt_service.set_key_manager(fake_km)

            try:
                for entry_id, encrypted_data in raw_entries:
                    try:
                        plaintext = decrypt_service.decrypt(encrypted_data)
                        new_encrypted = encrypt_service.encrypt(plaintext)
                        re_encrypted_data.append((entry_id, new_encrypted))
                        del plaintext
                    except Exception as decrypt_error:
                        logger.error("Failed to re-encrypt entry %s: %s", entry_id, decrypt_error)
                        failed_entries.append(str(entry_id))
            finally:
                temp_storage.clear_key()

            if failed_entries or len(re_encrypted_data) != len(raw_entries):
                raise RuntimeError(
                    "Key rotation aborted: failed to re-encrypt all vault entries. "
                    f"Failed entries: {', '.join(failed_entries) or 'unknown'}"
                )

            # 5. Атомарное обновление БД: записи + auth_hash + enc_salt в одной транзакции.
            self.db.begin_transaction()
            try:
                for eid, new_enc_data in re_encrypted_data:
                    self.db.execute(
                        "UPDATE vault_entries SET encrypted_data = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                        (new_enc_data, eid),
                    )
                self.db.execute(
                    "UPDATE key_store SET key_data = ? WHERE key_type = 'auth_hash'",
                    (new_auth_hash.encode('utf-8'),),
                )
                self.db.execute(
                    "UPDATE key_store SET key_data = ? WHERE key_type = 'enc_salt'",
                    (new_enc_salt,),
                )
                self.db.commit_transaction()
            except Exception as db_error:
                self.db.rollback_transaction()
                raise RuntimeError(f"DB transaction failed: {db_error}")

            # 7. Обновляем ключ в оперативной памяти
            self.storage.store_key(new_enc_key)

            logger.info("Password changed successfully.")
            return True

        except Exception as e:
            logger.error(f"Password change failed: {e}")
            # Откат: восстанавливаем старые ключи в памяти
            if old_key_bytes:
                self.storage.store_key(old_key_bytes)
            raise RuntimeError(f"Ошибка при смене пароля: {e}")

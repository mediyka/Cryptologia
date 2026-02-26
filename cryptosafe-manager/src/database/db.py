"""
Помощник для работы с SQLite базой данных.
"""
import sqlite3
import threading
from contextlib import contextmanager
from typing import Optional, List, Dict, Any, Generator
from pathlib import Path

from .models import (
    CREATE_VAULT_ENTRIES, CREATE_AUDIT_LOG,
    CREATE_SETTINGS, CREATE_KEY_STORE,
    VaultEntry
)
from ..core.config import config
from ..core.events import event_bus, EventType


class Database:
    """Класс для работы с базой данных (Singleton)."""
    
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
            return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self.db_path = config.DB_PATH
        self._local = threading.local()
        self._initialize_database()
        self._initialized = True
    
    def _get_connection(self) -> sqlite3.Connection:
        """Возвращает соединение с БД для текущего потока."""
        if not hasattr(self._local, 'connection'):
            self._local.connection = sqlite3.connect(
                self.db_path,
                timeout=10,
                check_same_thread=False
            )
            self._local.connection.row_factory = sqlite3.Row
            self._local.connection.execute("PRAGMA foreign_keys = ON")
        
        return self._local.connection
    
    @contextmanager
    def transaction(self) -> Generator[sqlite3.Connection, None, None]:
        """Контекстный менеджер для транзакций."""
        conn = self._get_connection()
        try:
            conn.execute("BEGIN")
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
    
    def _initialize_database(self) -> None:
        """Инициализирует базу данных."""
        with self.transaction() as conn:
            conn.execute(CREATE_VAULT_ENTRIES)
            conn.execute(CREATE_AUDIT_LOG)
            conn.execute(CREATE_SETTINGS)
            conn.execute(CREATE_KEY_STORE)
    
    def add_entry(self, entry: VaultEntry) -> int:
        """Добавляет новую запись в хранилище."""
        data = entry.to_dict()
        data.pop('id', None)
        
        with self.transaction() as conn:
            cursor = conn.execute("""
                INSERT INTO vault_entries 
                (title, username, encrypted_password, url, notes, tags, updated_at)
                VALUES (:title, :username, :encrypted_password, :url, :notes, :tags, :updated_at)
            """, data)
            
            entry_id = cursor.lastrowid
            event_bus.emit(EventType.ENTRY_ADDED, {'id': entry_id, 'title': entry.title})
            return entry_id
    
    def get_all_entries(self) -> List[VaultEntry]:
        """Получает все записи из хранилища."""
        with self.transaction() as conn:
            cursor = conn.execute("SELECT * FROM vault_entries ORDER BY updated_at DESC")
            return [VaultEntry.from_db_row(dict(row)) for row in cursor.fetchall()]
    
    def update_entry(self, entry: VaultEntry) -> bool:
        """Обновляет существующую запись."""
        if not entry.id:
            return False
        
        data = entry.to_dict()
        with self.transaction() as conn:
            cursor = conn.execute("""
                UPDATE vault_entries 
                SET title = :title, username = :username, 
                    encrypted_password = :encrypted_password, url = :url,
                    notes = :notes, tags = :tags, updated_at = :updated_at
                WHERE id = :id
            """, data)
            
            if cursor.rowcount > 0:
                event_bus.emit(EventType.ENTRY_UPDATED, {'id': entry.id})
                return True
            return False
    
    def delete_entry(self, entry_id: int) -> bool:
        """Удаляет запись по ID."""
        with self.transaction() as conn:
            cursor = conn.execute("DELETE FROM vault_entries WHERE id = ?", (entry_id,))
            
            if cursor.rowcount > 0:
                event_bus.emit(EventType.ENTRY_DELETED, {'id': entry_id})
                return True
            return False
    
    def store_key(self, key_type: str, salt: bytes, key_hash: bytes) -> None:
        """Сохраняет информацию о ключе."""
        with self.transaction() as conn:
            conn.execute("""
                INSERT INTO key_store (key_type, salt, hash, created_at)
                VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            """, (key_type, salt, key_hash))
    
    def get_key(self, key_type: str) -> Optional[Dict[str, Any]]:
        """Получает информацию о ключе."""
        with self.transaction() as conn:
            cursor = conn.execute(
                "SELECT * FROM key_store WHERE key_type = ? ORDER BY created_at DESC LIMIT 1",
                (key_type,)
            )
            row = cursor.fetchone()
            return dict(row) if row else None


db = Database()

"""
Модели данных и SQL схемы.
"""
from datetime import datetime
from typing import Optional, Dict, Any
import json


# SQL схемы
CREATE_VAULT_ENTRIES = """
CREATE TABLE IF NOT EXISTS vault_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    username TEXT NOT NULL,
    encrypted_password BLOB NOT NULL,
    url TEXT,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    tags TEXT
);
"""

CREATE_AUDIT_LOG = """
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    entry_id INTEGER,
    details TEXT
);
"""

CREATE_SETTINGS = """
CREATE TABLE IF NOT EXISTS settings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    setting_key TEXT UNIQUE NOT NULL,
    setting_value TEXT,
    encrypted BOOLEAN DEFAULT 0,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""

CREATE_KEY_STORE = """
CREATE TABLE IF NOT EXISTS key_store (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_type TEXT NOT NULL,
    salt BLOB NOT NULL,
    hash BLOB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


class VaultEntry:
    """Модель записи в хранилище паролей."""
    
    def __init__(self, title: str, username: str, encrypted_password: bytes,
                 url: str = "", notes: str = "", tags=None, entry_id: int = None):
        self.id = entry_id
        self.title = title
        self.username = username
        self.encrypted_password = encrypted_password
        self.url = url
        self.notes = notes
        self.tags = tags or []
        self.created_at = datetime.now()
        self.updated_at = datetime.now()
    
    @classmethod
    def from_db_row(cls, row: Dict[str, Any]):
        """Создает экземпляр из строки БД."""
        tags = json.loads(row['tags']) if row.get('tags') else []
        return cls(
            entry_id=row['id'],
            title=row['title'],
            username=row['username'],
            encrypted_password=row['encrypted_password'],
            url=row.get('url', ''),
            notes=row.get('notes', ''),
            tags=tags
        )
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертирует в словарь для БД."""
        return {
            'id': self.id,
            'title': self.title,
            'username': self.username,
            'encrypted_password': self.encrypted_password,
            'url': self.url,
            'notes': self.notes,
            'tags': json.dumps(self.tags),
            'updated_at': datetime.now().isoformat()
        }

import json
from datetime import datetime, timezone
from typing import Dict, List

from core.crypto.abstract import EncryptionService
from database.db import DatabaseHelper


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class VaultManager:
    """Совместимая обёртка над моделью хранения encrypted_data из Sprint 3."""

    def __init__(self, db: DatabaseHelper, encryption_service: EncryptionService):
        self.db = db
        self.crypto = encryption_service

    def add_entry(self, title: str, username: str, password: str, url: str = "", notes: str = ""):
        """Добавляет entry."""
        now = _now_iso()
        payload = {
            "title": title,
            "username": username,
            "password": password,
            "url": url,
            "notes": notes,
            "category": "",
            "tags": [],
            "created_at": now,
            "updated_at": now,
            "version": 1,
        }
        encrypted_blob = self.crypto.encrypt(json.dumps(payload).encode("utf-8"))

        query = """
            INSERT INTO vault_entries (id, encrypted_data, created_at, updated_at, tags)
            VALUES (?, ?, ?, ?, ?)
        """
        entry_id = f"legacy-{int(datetime.now(timezone.utc).timestamp() * 1000000)}"
        self.db.execute(query, (entry_id, encrypted_blob, now, now, "[]"))

    def get_all_entries(self) -> List[Dict]:
        """Возвращает данные для all entries."""
        rows = self.db.fetchall("SELECT id, encrypted_data FROM vault_entries")
        result = []
        for row in rows:
            try:
                data = json.loads(self.crypto.decrypt(row[1]).decode())
                result.append({
                    "id": row[0],
                    "title": data.get("title", ""),
                    "username": data.get("username", ""),
                    "password": data.get("password", ""),
                    "url": data.get("url", ""),
                })
            except Exception:
                result.append({
                    "id": row[0],
                    "title": "[DECRYPT_ERROR]",
                    "username": "",
                    "password": "[DECRYPT_ERROR]",
                    "url": "",
                })
        return result

    def get_all_entries_raw(self) -> List[Dict]:
        """Возвращает данные для all entries raw."""
        rows = self.db.fetchall("SELECT id, encrypted_data FROM vault_entries")
        return [{"id": r[0], "enc_data": r[1]} for r in rows]

    def update_entry_password(self, entry_id: int, new_encrypted_data: bytes):
        """Обновляет entry password."""
        self.db.execute("UPDATE vault_entries SET encrypted_data = ? WHERE id = ?", (new_encrypted_data, entry_id))

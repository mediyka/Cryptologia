import json
import os
import sqlite3
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from database.db import DB_SCHEMA_VERSION, DatabaseHelper


def _columns(db, table_name):
    return {row[1] for row in db.fetchall(f"PRAGMA table_info({table_name})")}


def _indexes(db, table_name):
    return {row[1] for row in db.fetchall(f"PRAGMA index_list({table_name})")}


def test_db_1_shared_schema(tmp_path):
    db = DatabaseHelper(str(tmp_path / "shared-schema.db"))
    columns = _columns(db, "shared_entries")

    assert {
        "shared_id",
        "original_entry_id",
        "encryption_method",
        "recipient_info",
        "permissions",
        "shared_at",
        "expires_at",
    }.issubset(columns)
    assert {"idx_shared_entries_original", "idx_shared_entries_expires"}.issubset(_indexes(db, "shared_entries"))

    db.close()


def test_db_2_history_schema(tmp_path):
    db = DatabaseHelper(str(tmp_path / "history-schema.db"))
    columns = _columns(db, "import_export_history")

    assert {
        "operation_type",
        "export_format",
        "encryption_used",
        "entry_count",
        "file_size",
        "checksum",
        "verification_status",
        "created_at",
        "details",
    }.issubset(columns)
    assert {"idx_import_export_created", "idx_import_export_operation"}.issubset(
        _indexes(db, "import_export_history")
    )

    db.execute(
        """
        INSERT INTO import_export_history
        (operation_type, export_format, encryption_used, entry_count, file_size, checksum, verification_status, details)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        ("export", "encrypted_json", "encrypted", 3, 1024, "abc", "created", json.dumps({"ok": True})),
    )
    row = db.fetchone(
        "SELECT operation_type, export_format, encryption_used, entry_count FROM import_export_history"
    )
    assert row == ("export", "encrypted_json", "encrypted", 3)

    db.close()


def test_db_3_contacts_schema(tmp_path):
    db = DatabaseHelper(str(tmp_path / "contacts-schema.db"))
    columns = _columns(db, "contacts")

    assert {
        "contact_name",
        "identifier",
        "public_key",
        "key_fingerprint",
        "key_algorithm",
        "status",
        "verified",
        "revoked_at",
        "rotated_from",
        "last_used_at",
    }.issubset(columns)
    assert {"idx_contacts_identifier", "idx_contacts_fingerprint", "idx_contacts_status"}.issubset(
        _indexes(db, "contacts")
    )

    db.close()


def test_db_version(tmp_path):
    db = DatabaseHelper(str(tmp_path / "schema-version.db"))
    row = db.fetchone("PRAGMA user_version")

    assert row[0] == DB_SCHEMA_VERSION
    assert DB_SCHEMA_VERSION >= 7

    db.close()


def test_db_partial_migration(tmp_path):
    db_path = tmp_path / "partial-sprint6.db"
    conn = sqlite3.connect(db_path)
    try:
        conn.execute("CREATE TABLE import_export_history (id INTEGER PRIMARY KEY AUTOINCREMENT)")
        conn.execute("CREATE TABLE shared_entries (shared_id TEXT PRIMARY KEY)")
        conn.execute(
            """
            CREATE TABLE contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contact_name TEXT NOT NULL,
                identifier TEXT,
                public_key TEXT,
                key_fingerprint TEXT
            )
            """
        )
        conn.commit()
    finally:
        conn.close()

    db = DatabaseHelper(str(db_path))

    assert "verification_status" in _columns(db, "import_export_history")
    assert "expires_at" in _columns(db, "shared_entries")
    assert "key_algorithm" in _columns(db, "contacts")
    assert "status" in _columns(db, "contacts")

    db.close()

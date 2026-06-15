import logging
import os
import shutil
import sqlite3
import threading
import atexit
import weakref
from contextlib import contextmanager

logger = logging.getLogger("Database")

DB_SCHEMA_VERSION = 7
_OPEN_DATABASE_HELPERS = weakref.WeakSet()


def _close_open_database_helpers():
    DatabaseHelper.close_all()


atexit.register(_close_open_database_helpers)


class DatabaseHelper:
    """Инкапсулирует SQLite, миграции, запросы и резервное восстановление."""
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._local = threading.local()
        self._connections = []
        self._connections_lock = threading.RLock()
        self._audit_reads_allowed = False
        _OPEN_DATABASE_HELPERS.add(self)
        self._initialize_db()

    def _get_connection(self) -> sqlite3.Connection:
        if not hasattr(self._local, "connection"):
            self._local.connection = sqlite3.connect(self.db_path, check_same_thread=False)
            self._local.connection.execute("PRAGMA foreign_keys = ON")
            self._local.connection.execute("PRAGMA journal_mode = WAL")
            self._local.connection.execute("PRAGMA synchronous = NORMAL")
            self._local.connection.execute("PRAGMA temp_store = MEMORY")
            self._local.connection.execute("PRAGMA cache_size = -20000")
            self._local.explicit_transaction = False
            with self._connections_lock:
                self._connections.append(self._local.connection)
        return self._local.connection

    def _initialize_db(self):
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute("PRAGMA user_version")
        version = cursor.fetchone()[0]

        self._create_supporting_tables(cursor)
        self._migrate_audit_log(cursor)
        self._migrate_import_export_history(cursor)
        self._migrate_shared_entries(cursor)
        self._migrate_contacts(cursor)

        if self._table_exists(cursor, "vault_entries"):
            if self._vault_entries_needs_migration(cursor):
                self._migrate_vault_entries(cursor)
        else:
            self._create_vault_entries_table(cursor)

        self._create_indexes(cursor)

        if version < DB_SCHEMA_VERSION:
            cursor.execute(f"PRAGMA user_version = {DB_SCHEMA_VERSION}")

        conn.commit()

    def _create_supporting_tables(self, cursor):
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sequence_number INTEGER UNIQUE,
                previous_hash TEXT,
                entry_data BLOB,
                entry_hash TEXT,
                event_type TEXT,
                action TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                entry_id INTEGER,
                details TEXT,
                signature TEXT,
                public_key TEXT
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_type TEXT UNIQUE NOT NULL,
                public_key TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log_archive (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sequence_number INTEGER,
                previous_hash TEXT,
                entry_data BLOB,
                entry_hash TEXT,
                event_type TEXT,
                action TEXT,
                timestamp TIMESTAMP,
                entry_id INTEGER,
                details TEXT,
                signature TEXT,
                public_key TEXT,
                archived_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                details TEXT NOT NULL
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_rotation_policy (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                max_entries INTEGER NOT NULL DEFAULT 10000,
                max_age_days INTEGER NOT NULL DEFAULT 365,
                auto_archive INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        cursor.execute(
            """
            INSERT OR IGNORE INTO audit_rotation_policy
            (id, max_entries, max_age_days, auto_archive)
            VALUES (1, 10000, 365, 1)
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_export_schedule (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                export_format TEXT NOT NULL,
                frequency TEXT NOT NULL,
                output_dir TEXT NOT NULL,
                retention_days INTEGER NOT NULL DEFAULT 30,
                enabled INTEGER NOT NULL DEFAULT 1,
                last_run_at TIMESTAMP,
                next_run_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS import_export_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation_type TEXT NOT NULL,
                export_format TEXT NOT NULL,
                encryption_used TEXT NOT NULL,
                entry_count INTEGER NOT NULL DEFAULT 0,
                file_size INTEGER NOT NULL DEFAULT 0,
                checksum TEXT,
                verification_status TEXT NOT NULL DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                details TEXT
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS shared_entries (
                shared_id TEXT PRIMARY KEY,
                original_entry_id TEXT NOT NULL,
                encryption_method TEXT NOT NULL,
                recipient_info TEXT,
                permissions TEXT,
                shared_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                contact_name TEXT NOT NULL,
                identifier TEXT,
                public_key TEXT,
                key_fingerprint TEXT,
                key_algorithm TEXT DEFAULT 'RSA-2048',
                status TEXT NOT NULL DEFAULT 'active',
                revoked_at TIMESTAMP,
                rotated_from INTEGER,
                verified INTEGER NOT NULL DEFAULT 0,
                last_used_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                setting_key TEXT UNIQUE NOT NULL,
                setting_value TEXT,
                encrypted INTEGER DEFAULT 0
            )
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS key_store (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_type TEXT UNIQUE NOT NULL,
                key_data BLOB,
                version INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

    def _create_vault_entries_table(self, cursor):
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS vault_entries (
                id TEXT PRIMARY KEY,
                encrypted_data BLOB NOT NULL,
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL,
                tags TEXT
            )
            """
        )

    def _create_indexes(self, cursor):
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vault_created_at ON vault_entries(created_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vault_updated_at ON vault_entries(updated_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_vault_tags ON vault_entries(tags)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_settings_key ON settings(setting_key)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_event_type ON audit_log(event_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_sequence ON audit_log(sequence_number)")
        cursor.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_sequence_unique "
            "ON audit_log(sequence_number) WHERE sequence_number IS NOT NULL"
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_event_timestamp ON audit_log(event_type, timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_entry_id ON audit_log(entry_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_archive_sequence ON audit_log_archive(sequence_number)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_security_timestamp ON audit_security_events(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_export_schedule_next ON audit_export_schedule(next_run_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_import_export_created ON import_export_history(created_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_import_export_operation ON import_export_history(operation_type)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_shared_entries_original ON shared_entries(original_entry_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_shared_entries_expires ON shared_entries(expires_at)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_contacts_identifier ON contacts(identifier)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_contacts_fingerprint ON contacts(key_fingerprint)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_contacts_status ON contacts(status)")

    def _migrate_audit_log(self, cursor):
        cursor.execute("PRAGMA table_info(audit_log)")
        columns = {row[1] for row in cursor.fetchall()}
        # SQLite cannot add a UNIQUE column to an existing table via ALTER TABLE.
        # Use a plain INTEGER column for migrations and enforce uniqueness with a
        # partial unique index in _create_indexes instead.
        additions = {
            "sequence_number": "INTEGER",
            "previous_hash": "TEXT",
            "entry_data": "BLOB",
            "entry_hash": "TEXT",
            "event_type": "TEXT",
            "public_key": "TEXT",
        }
        if "signature" not in columns:
            additions["signature"] = "TEXT"

        for column, definition in additions.items():
            if column not in columns:
                cursor.execute(f"ALTER TABLE audit_log ADD COLUMN {column} {definition}")

        if "event_type" not in columns and "action" in columns:
            cursor.execute("UPDATE audit_log SET event_type = action WHERE event_type IS NULL")

    def _migrate_contacts(self, cursor):
        cursor.execute("PRAGMA table_info(contacts)")
        columns = {row[1] for row in cursor.fetchall()}
        if not columns:
            return

        additions = {
            "key_algorithm": "TEXT DEFAULT 'RSA-2048'",
            "status": "TEXT NOT NULL DEFAULT 'active'",
            "revoked_at": "TIMESTAMP",
            "rotated_from": "INTEGER",
            "verified": "INTEGER NOT NULL DEFAULT 0",
        }
        for column, definition in additions.items():
            if column not in columns:
                cursor.execute(f"ALTER TABLE contacts ADD COLUMN {column} {definition}")

    def _migrate_import_export_history(self, cursor):
        cursor.execute("PRAGMA table_info(import_export_history)")
        columns = {row[1] for row in cursor.fetchall()}
        if not columns:
            return

        additions = {
            "operation_type": "TEXT NOT NULL DEFAULT 'export'",
            "export_format": "TEXT NOT NULL DEFAULT 'unknown'",
            "encryption_used": "TEXT NOT NULL DEFAULT 'unknown'",
            "entry_count": "INTEGER NOT NULL DEFAULT 0",
            "file_size": "INTEGER NOT NULL DEFAULT 0",
            "checksum": "TEXT",
            "verification_status": "TEXT NOT NULL DEFAULT 'pending'",
            "created_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
            "details": "TEXT",
        }
        for column, definition in additions.items():
            if column not in columns:
                cursor.execute(f"ALTER TABLE import_export_history ADD COLUMN {column} {definition}")

    def _migrate_shared_entries(self, cursor):
        cursor.execute("PRAGMA table_info(shared_entries)")
        columns = {row[1] for row in cursor.fetchall()}
        if not columns:
            return

        additions = {
            "shared_id": "TEXT",
            "original_entry_id": "TEXT NOT NULL DEFAULT ''",
            "encryption_method": "TEXT NOT NULL DEFAULT 'unknown'",
            "recipient_info": "TEXT",
            "permissions": "TEXT",
            "shared_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
            "expires_at": "TIMESTAMP",
        }
        for column, definition in additions.items():
            if column not in columns:
                cursor.execute(f"ALTER TABLE shared_entries ADD COLUMN {column} {definition}")

    @staticmethod
    def _table_exists(cursor, table_name: str) -> bool:
        cursor.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = ?",
            (table_name,),
        )
        return cursor.fetchone()[0] > 0

    def _vault_entries_needs_migration(self, cursor) -> bool:
        cursor.execute("PRAGMA table_info(vault_entries)")
        columns = {row[1] for row in cursor.fetchall()}
        clean_columns = {"id", "encrypted_data", "created_at", "updated_at", "tags"}
        return columns != clean_columns

    def _migrate_vault_entries(self, cursor):
        logger.info("Migrating vault_entries to clean Sprint 3 schema")

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS vault_entries_new (
                id TEXT PRIMARY KEY,
                encrypted_data BLOB NOT NULL,
                created_at TIMESTAMP NOT NULL,
                updated_at TIMESTAMP NOT NULL,
                tags TEXT
            )
            """
        )

        cursor.execute("PRAGMA table_info(vault_entries)")
        columns = {row[1] for row in cursor.fetchall()}

        if "encrypted_data" in columns:
            cursor.execute(
                """
                INSERT INTO vault_entries_new (id, encrypted_data, created_at, updated_at, tags)
                SELECT
                    CAST(id AS TEXT),
                    encrypted_data,
                    COALESCE(created_at, CURRENT_TIMESTAMP),
                    COALESCE(updated_at, CURRENT_TIMESTAMP),
                    COALESCE(tags, '[]')
                FROM vault_entries
                WHERE encrypted_data IS NOT NULL
                """
            )

        cursor.execute("DROP TABLE IF EXISTS vault_entries_old")
        cursor.execute("ALTER TABLE vault_entries RENAME TO vault_entries_old")
        cursor.execute("ALTER TABLE vault_entries_new RENAME TO vault_entries")

    def execute(self, query: str, params: tuple = ()):
        """Описывает публичное действие execute."""
        self._guard_audit_mutation(query)
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(query, params)
        if not getattr(self._local, "explicit_transaction", False):
            conn.commit()
        return cursor.lastrowid

    def unsafe_audit_execute(self, query: str, params: tuple = ()):
        """Описывает публичное действие unsafe audit execute."""
        with self.audit_maintenance():
            return self.execute(query, params)

    def execute_many(self, queries: list):
        """Описывает публичное действие execute many."""
        conn = self._get_connection()
        cursor = conn.cursor()
        try:
            for query, params in queries:
                cursor.execute(query, params if params else ())
            conn.commit()
            return True
        except Exception as e:
            conn.rollback()
            logger.error(f"Transaction failed, rolled back: {e}")
            return False

    def begin_transaction(self):
        """Описывает публичное действие begin transaction."""
        conn = self._get_connection()
        self._local.explicit_transaction = True
        conn.execute("BEGIN IMMEDIATE")

    def commit_transaction(self):
        """Описывает публичное действие commit transaction."""
        conn = self._get_connection()
        conn.commit()
        self._local.explicit_transaction = False

    def rollback_transaction(self):
        """Описывает публичное действие rollback transaction."""
        conn = self._get_connection()
        conn.rollback()
        self._local.explicit_transaction = False
        logger.warning("Transaction rolled back")

    def fetchall(self, query: str, params: tuple = ()):
        """Описывает публичное действие fetchall."""
        self._guard_audit_read(query)
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchall()

    def fetchone(self, query: str, params: tuple = ()):
        """Описывает публичное действие fetchone."""
        self._guard_audit_read(query)
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(query, params)
        return cursor.fetchone()

    def iter_rows(self, query: str, params: tuple = (), batch_size: int = 500):
        """Описывает публичное действие iter rows."""
        self._guard_audit_read(query)
        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(query, params)
        while True:
            rows = cursor.fetchmany(batch_size)
            if not rows:
                break
            for row in rows:
                yield row

    def enable_audit_read(self):
        """Описывает публичное действие enable audit read."""
        self._audit_reads_allowed = True

    def disable_audit_read(self):
        """Описывает публичное действие disable audit read."""
        self._audit_reads_allowed = False

    @contextmanager
    def audit_read_access(self):
        """Описывает публичное действие audit read access."""
        old_value = self._audit_reads_allowed
        self._audit_reads_allowed = True
        try:
            yield
        finally:
            self._audit_reads_allowed = old_value

    @contextmanager
    def audit_maintenance(self):
        """Описывает публичное действие audit maintenance."""
        old_value = getattr(self._local, "audit_maintenance", False)
        self._local.audit_maintenance = True
        try:
            yield
        finally:
            self._local.audit_maintenance = old_value

    def _guard_audit_mutation(self, query: str):
        normalized = " ".join(str(query or "").lower().split())
        if getattr(self._local, "audit_maintenance", False):
            return
        if normalized.startswith("update audit_log") or normalized.startswith("delete from audit_log"):
            raise PermissionError("Audit log is append-only.")

    def _guard_audit_read(self, query: str):
        normalized = " ".join(str(query or "").lower().split())
        if "from audit_log" not in normalized:
            return
        if self._audit_reads_allowed or getattr(self._local, "audit_maintenance", False):
            return
        raise PermissionError("Audit log read requires authenticated access.")

    def get_audit_rotation_policy(self) -> dict:
        """Возвращает данные для audit rotation policy."""
        row = self.fetchone(
            "SELECT max_entries, max_age_days, auto_archive FROM audit_rotation_policy WHERE id = 1"
        )
        if not row:
            return {"max_entries": 10000, "max_age_days": 365, "auto_archive": True}
        return {
            "max_entries": int(row[0]),
            "max_age_days": int(row[1]),
            "auto_archive": bool(row[2]),
        }

    def set_audit_rotation_policy(
        self,
        max_entries: int = 10000,
        max_age_days: int = 365,
        auto_archive: bool = True,
    ):
        """Сохраняет или обновляет значение audit rotation policy."""
        self.execute(
            """
            INSERT INTO audit_rotation_policy (id, max_entries, max_age_days, auto_archive)
            VALUES (1, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                max_entries = excluded.max_entries,
                max_age_days = excluded.max_age_days,
                auto_archive = excluded.auto_archive
            """,
            (int(max_entries), int(max_age_days), 1 if auto_archive else 0),
        )

    def rotate_audit_logs(self) -> int:
        """Описывает публичное действие rotate audit logs."""
        policy = self.get_audit_rotation_policy()
        if not policy["auto_archive"]:
            return 0

        conn = self._get_connection()
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT sequence_number
            FROM audit_log
            WHERE sequence_number IS NOT NULL
            ORDER BY sequence_number DESC
            LIMIT 1 OFFSET ?
            """,
            (policy["max_entries"] - 1,),
        )
        cutoff_row = cursor.fetchone()
        cutoff_sequence = cutoff_row[0] if cutoff_row else None

        conditions = []
        params = []
        if cutoff_sequence is not None:
            conditions.append("sequence_number < ?")
            params.append(cutoff_sequence)
        if policy["max_age_days"] > 0:
            conditions.append("timestamp < datetime('now', ?)")
            params.append(f"-{policy['max_age_days']} days")
        if not conditions:
            return 0

        where_clause = " OR ".join(conditions)
        cursor.execute(f"SELECT COUNT(*) FROM audit_log WHERE {where_clause}", tuple(params))
        count = cursor.fetchone()[0]
        if count == 0:
            return 0

        cursor.execute(
            f"""
            INSERT INTO audit_log_archive
            (sequence_number, previous_hash, entry_data, entry_hash, event_type, action,
             timestamp, entry_id, details, signature, public_key)
            SELECT sequence_number, previous_hash, entry_data, entry_hash, event_type, action,
                   timestamp, entry_id, details, signature, public_key
            FROM audit_log
            WHERE {where_clause}
            """,
            tuple(params),
        )
        cursor.execute(f"DELETE FROM audit_log WHERE {where_clause}", tuple(params))
        conn.commit()
        return count

    def backup(self, backup_path: str) -> bool:
        """Описывает публичное действие backup."""
        try:
            if hasattr(self._local, "connection"):
                self._local.connection.close()
                del self._local.connection

            if os.path.exists(self.db_path):
                shutil.copy2(self.db_path, backup_path)
                return True
            return False
        except Exception as e:
            logger.error(f"Backup error: {e}")
            return False

    def validate_integrity(self) -> dict:
        """Проверяет integrity."""
        try:
            row = self.fetchone("PRAGMA integrity_check")
            ok = bool(row and row[0] == "ok")
            return {"ok": ok, "message": row[0] if row else "no result"}
        except Exception as error:
            return {"ok": False, "message": str(error)}

    def recover_to(self, recovered_db_path: str) -> dict:
        """Описывает публичное действие recover to."""
        source_ok = self.validate_integrity()
        recovered = DatabaseHelper(recovered_db_path)
        copied_entries = 0

        try:
            for table in ("audit_log", "audit_keys", "audit_security_events"):
                try:
                    rows = self.fetchall(f"SELECT * FROM {table}")
                    columns = [row[1] for row in self.fetchall(f"PRAGMA table_info({table})")]
                except Exception:
                    continue

                if not rows or not columns:
                    continue

                placeholders = ", ".join(["?"] * len(columns))
                column_list = ", ".join(columns)
                for row in rows:
                    recovered.execute(
                        f"INSERT OR IGNORE INTO {table} ({column_list}) VALUES ({placeholders})",
                        tuple(row),
                    )
                    if table == "audit_log":
                        copied_entries += 1
        finally:
            recovered.close()

        return {
            "source_ok": source_ok["ok"],
            "source_message": source_ok["message"],
            "recovered_db_path": recovered_db_path,
            "copied_audit_entries": copied_entries,
        }

    @staticmethod
    def recover_corrupt_database(corrupt_db_path: str, recovered_db_path: str) -> dict:
        """Описывает публичное действие recover corrupt database."""
        quarantine_path = f"{corrupt_db_path}.corrupt"
        if os.path.exists(corrupt_db_path):
            shutil.copy2(corrupt_db_path, quarantine_path)

        recovered = DatabaseHelper(recovered_db_path)
        recovered.close()
        return {
            "source_ok": False,
            "source_message": "database file is corrupt or unreadable",
            "quarantine_path": quarantine_path,
            "recovered_db_path": recovered_db_path,
        }

    def get_audit_timeline(self, include_archive: bool = True):
        """Возвращает данные для audit timeline."""
        query = """
            SELECT sequence_number, timestamp, COALESCE(event_type, action), entry_id, details, 'active' AS location
            FROM audit_log
            WHERE sequence_number IS NOT NULL
        """
        if include_archive:
            query += """
                UNION ALL
                SELECT sequence_number, timestamp, COALESCE(event_type, action), entry_id, details, 'archive' AS location
                FROM audit_log_archive
                WHERE sequence_number IS NOT NULL
            """
        query += " ORDER BY sequence_number ASC"
        with self.audit_read_access():
            return self.fetchall(query)

    def close(self):
        """Описывает публичное действие close."""
        if hasattr(self._local, "connection"):
            self._local.connection.close()
            del self._local.connection
        with self._connections_lock:
            for connection in list(self._connections):
                try:
                    connection.close()
                except Exception:
                    pass
            self._connections.clear()

    @classmethod
    def close_all(cls):
        """Описывает публичное действие close all."""
        for helper in list(_OPEN_DATABASE_HELPERS):
            try:
                helper.close()
            except Exception:
                pass

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

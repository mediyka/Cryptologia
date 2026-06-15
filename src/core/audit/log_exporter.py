import base64
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Callable, Dict, Any, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .log_formatters import AuditLogFormatter


EXPORT_KEY_PURPOSE = "audit-export"
EXPORT_AAD = b"cryptosafe-manager:audit-export:v1"


class AuditLogExporter:
    """Безопасный экспорт журнала аудита в форматы Sprint 5."""

    SUPPORTED_FORMATS = {"json", "csv", "pdf", "cef"}
    SUPPORTED_FREQUENCIES = {"daily", "weekly", "monthly"}

    def __init__(self, db_helper, key_manager=None, audit_logger=None):
        self.db = db_helper
        self.key_manager = key_manager
        self.audit_logger = audit_logger

    def export(
        self,
        output_path: str,
        export_format: str,
        exporter: str = "default_user",
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        encrypt: bool = True,
        confirm_password: Optional[Callable[[], bool]] = None,
    ) -> Dict[str, Any]:
        """Экспортирует данные в выбранном формате."""
        export_format = self._normalize_format(export_format)
        if confirm_password is None or not confirm_password():
            raise PermissionError("Export requires master password confirmation.")

        rows = self._fetch_rows(start_date=start_date, end_date=end_date)
        metadata = self._metadata(exporter, start_date, end_date, len(rows), encrypt)
        content, content_type = self._format_content(rows, export_format, metadata)

        if encrypt:
            content = self._encrypt_export(content, metadata)
            content_type = f"{content_type}+aes256gcm"

        self._write_file(output_path, content)
        self._log_export(export_format, output_path, metadata, encrypt)
        return {
            "path": output_path,
            "format": export_format,
            "content_type": content_type,
            "encrypted": encrypt,
            "entries": len(rows),
            "metadata": metadata,
        }

    def create_schedule(
        self,
        name: str,
        output_dir: str,
        export_format: str = "json",
        frequency: str = "daily",
        retention_days: int = 30,
        enabled: bool = True,
    ) -> int:
        """Создает schedule."""
        export_format = self._normalize_format(export_format)
        frequency = self._normalize_frequency(frequency)
        next_run_at = self._next_run_at(frequency)
        return self.db.execute(
            """
            INSERT INTO audit_export_schedule
            (name, export_format, frequency, output_dir, retention_days, enabled, next_run_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (name, export_format, frequency, output_dir, int(retention_days), 1 if enabled else 0, next_run_at),
        )

    def due_schedules(self, now: Optional[datetime] = None):
        """Описывает публичное действие due schedules."""
        now = now or datetime.now(timezone.utc)
        return self.db.fetchall(
            """
            SELECT id, name, export_format, frequency, output_dir, retention_days
            FROM audit_export_schedule
            WHERE enabled = 1 AND (next_run_at IS NULL OR next_run_at <= ?)
            ORDER BY id
            """,
            (now.isoformat(),),
        )

    def run_due_schedules(
        self,
        confirm_password: Optional[Callable[[], bool]] = None,
        now: Optional[datetime] = None,
    ):
        """Описывает публичное действие run due schedules."""
        now = now or datetime.now(timezone.utc)
        results = []
        for schedule_id, name, export_format, frequency, output_dir, retention_days in self.due_schedules(now):
            filename = f"audit-{name}-{now.strftime('%Y%m%d-%H%M%S')}.{export_format}.enc"
            output_path = os.path.join(output_dir, filename)
            result = self.export(
                output_path=output_path,
                export_format=export_format,
                exporter="scheduled-export",
                encrypt=True,
                confirm_password=confirm_password,
            )
            self.cleanup_old_exports(output_dir, retention_days)
            self.db.execute(
                """
                UPDATE audit_export_schedule
                SET last_run_at = ?, next_run_at = ?
                WHERE id = ?
                """,
                (now.isoformat(), self._next_run_at(frequency, now), schedule_id),
            )
            results.append(result)
        return results

    def cleanup_old_exports(self, export_dir: str, retention_days: int) -> int:
        """Описывает публичное действие cleanup old exports."""
        if not os.path.isdir(export_dir):
            return 0

        cutoff = datetime.now(timezone.utc) - timedelta(days=int(retention_days))
        removed = 0
        for name in os.listdir(export_dir):
            if not name.startswith("audit-") or not name.endswith(".enc"):
                continue
            path = os.path.join(export_dir, name)
            modified_at = datetime.fromtimestamp(os.path.getmtime(path), timezone.utc)
            if modified_at < cutoff:
                os.remove(path)
                removed += 1
        return removed

    def _fetch_rows(self, start_date: Optional[str] = None, end_date: Optional[str] = None):
        conditions = ["sequence_number IS NOT NULL"]
        params = []
        if start_date:
            conditions.append("timestamp >= ?")
            params.append(start_date)
        if end_date:
            conditions.append("timestamp <= ?")
            params.append(end_date)

        query = f"""
            SELECT sequence_number, previous_hash, entry_data, entry_hash, event_type,
                   timestamp, entry_id, details, signature, public_key
            FROM audit_log
            WHERE {' AND '.join(conditions)}
            ORDER BY sequence_number ASC
        """
        rows = []
        for row in self.db.fetchall(query, tuple(params)):
            rows.append(
                {
                    "sequence_number": row[0],
                    "previous_hash": row[1],
                    "entry_data": row[2],
                    "entry_hash": row[3],
                    "event_type": row[4],
                    "timestamp": row[5],
                    "entry_id": row[6],
                    "details": row[7],
                    "signature": row[8],
                    "public_key": row[9],
                }
            )
        return rows

    def _format_content(self, rows, export_format: str, metadata: Dict[str, Any]):
        public_key = self._public_key(rows)
        if export_format == "json":
            text = AuditLogFormatter.to_signed_json(rows, public_key=public_key, metadata=metadata)
            return text.encode("utf-8"), "application/json"
        if export_format == "csv":
            text = AuditLogFormatter.to_csv(rows, metadata=metadata)
            return text.encode("utf-8-sig"), "text/csv"
        if export_format == "pdf":
            return AuditLogFormatter.to_pdf(rows, metadata=metadata), "application/pdf"
        if export_format == "cef":
            return AuditLogFormatter.to_cef(rows).encode("utf-8"), "text/plain"
        raise ValueError(f"Unsupported export format: {export_format}")

    def _encrypt_export(self, content: bytes, metadata: Dict[str, Any]) -> bytes:
        if not self.key_manager or not hasattr(self.key_manager, "derive_key"):
            raise RuntimeError("KeyManager is required for encrypted audit export.")
        key = self.key_manager.derive_key(EXPORT_KEY_PURPOSE, 32)
        nonce = os.urandom(12)
        encrypted = AESGCM(key).encrypt(nonce, content, EXPORT_AAD)
        envelope = {
            "format": "cryptosafe-audit-encrypted-export-v1",
            "algorithm": "AES-256-GCM",
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "associated_data": EXPORT_AAD.decode("ascii"),
            "metadata": metadata,
            "ciphertext": base64.b64encode(encrypted).decode("ascii"),
        }
        return json.dumps(envelope, ensure_ascii=False, indent=2).encode("utf-8")

    def _write_file(self, output_path: str, content: bytes):
        folder = os.path.dirname(os.path.abspath(output_path))
        if folder:
            os.makedirs(folder, exist_ok=True)
        with open(output_path, "wb") as export_file:
            export_file.write(content)

    def _log_export(self, export_format: str, output_path: str, metadata: Dict[str, Any], encrypted: bool):
        if not self.audit_logger:
            return
        self.audit_logger.log_event(
            "AuditExportCreated",
            severity="WARN",
            source="audit",
            details={
                "format": export_format,
                "path": os.path.basename(output_path),
                "entry_count": metadata["entry_count"],
                "range": metadata["range"],
                "encrypted": encrypted,
            },
        )

    def _metadata(
        self,
        exporter: str,
        start_date: Optional[str],
        end_date: Optional[str],
        entry_count: int,
        encrypted: bool,
    ) -> Dict[str, Any]:
        return {
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "exporter": exporter or "default_user",
            "range": {"start": start_date, "end": end_date},
            "entry_count": entry_count,
            "encrypted": encrypted,
        }

    @staticmethod
    def _public_key(rows) -> str:
        for row in rows:
            if row.get("public_key"):
                return row["public_key"]
        return ""

    @classmethod
    def _normalize_format(cls, export_format: str) -> str:
        normalized = str(export_format or "").lower().lstrip(".")
        if normalized not in cls.SUPPORTED_FORMATS:
            raise ValueError(f"Unsupported export format: {export_format}")
        return normalized

    @classmethod
    def _normalize_frequency(cls, frequency: str) -> str:
        normalized = str(frequency or "").lower()
        if normalized not in cls.SUPPORTED_FREQUENCIES:
            raise ValueError(f"Unsupported export frequency: {frequency}")
        return normalized

    @staticmethod
    def _next_run_at(frequency: str, now: Optional[datetime] = None) -> str:
        now = now or datetime.now(timezone.utc)
        if frequency == "daily":
            next_run = now + timedelta(days=1)
        elif frequency == "weekly":
            next_run = now + timedelta(days=7)
        else:
            next_run = now + timedelta(days=30)
        return next_run.isoformat()

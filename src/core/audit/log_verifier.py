import hashlib
import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from core.events import event_bus
from core.security.side_channel_protection import constant_time_compare

ZERO_HASH = "0" * 64


class AuditLogVerifier:
    """Проверка подписей и цепочки хэшей журнала аудита Sprint 5."""

    def __init__(self, db_helper, signer, bus=event_bus):
        self.db = db_helper
        self.signer = signer
        self.bus = bus
        self.last_status: Dict[str, Any] = {}
        self.last_checked_at: Optional[str] = None
        self.verification_interval_hours = 24
        self.periodic_sample_size = 1000

    def verify_integrity(
        self,
        start_seq: int = 0,
        end_seq: Optional[int] = None,
        publish_on_tamper: bool = True,
    ) -> Dict[str, Any]:
        """Проверяет integrity."""
        query = """
            SELECT sequence_number, entry_data, signature, entry_hash, previous_hash, public_key
            FROM audit_log
            WHERE sequence_number IS NOT NULL AND sequence_number >= ?
        """
        params = [start_seq]
        if end_seq is not None:
            query += " AND sequence_number <= ?"
            params.append(end_seq)
        query += " ORDER BY sequence_number"

        rows = self._iter_rows(query, tuple(params))
        result = {
            "total_entries": 0,
            "valid_entries": 0,
            "invalid_entries": [],
            "chain_breaks": [],
            "verified": True,
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "range": {"start_seq": start_seq, "end_seq": end_seq},
        }

        previous_hash = ZERO_HASH if start_seq == 0 else None
        for sequence_number, entry_data, signature_hex, entry_hash, previous_hash_field, public_key in rows:
            result["total_entries"] += 1
            if not entry_data or not signature_hex or not entry_hash:
                self._mark_invalid(result, sequence_number, "missing integrity fields")
                continue

            entry_bytes = self._to_bytes(entry_data)
            computed_hash = hashlib.sha256(entry_bytes).hexdigest()
            if not constant_time_compare(computed_hash, entry_hash):
                self._mark_invalid(result, sequence_number, "hash mismatch")
                continue

            try:
                signature = bytes.fromhex(signature_hex)
            except ValueError:
                self._mark_invalid(result, sequence_number, "invalid signature encoding")
                continue

            if not self.signer.verify_with_public_key(entry_bytes, signature, public_key):
                self._mark_invalid(result, sequence_number, "invalid signature")
                continue

            if previous_hash is not None and not constant_time_compare(previous_hash_field or "", previous_hash):
                result["chain_breaks"].append(
                    {
                        "sequence": sequence_number,
                        "expected": previous_hash,
                        "actual": previous_hash_field,
                    }
                )
                result["verified"] = False

            result["valid_entries"] += 1
            previous_hash = entry_hash

        self._store_status(result)
        if publish_on_tamper and not result["verified"]:
            self._publish_tamper_detected(result)
        return result

    def verify_on_startup(self) -> Dict[str, Any]:
        """Проверить журнал при запуске приложения."""
        return self.verify_integrity(start_seq=0)

    def verify_periodic(self, sample_size: Optional[int] = None) -> Dict[str, Any]:
        """Проверить последние записи для периодической фоновой проверки."""
        sample_size = sample_size or self.periodic_sample_size
        start_seq = self._recent_start_sequence(sample_size)
        return self.verify_integrity(start_seq=start_seq)

    def verify_manual(
        self,
        start_seq: int = 0,
        end_seq: Optional[int] = None,
        export_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Запустить ручную проверку и при необходимости сохранить отчёт."""
        result = self.verify_integrity(start_seq=start_seq, end_seq=end_seq)
        report = self.build_report(result)
        if export_path:
            with open(export_path, "w", encoding="utf-8") as report_file:
                json.dump(report, report_file, ensure_ascii=False, indent=2)
        return report

    def build_report(self, result: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Сформировать подробный отчёт проверки для GUI или экспорта."""
        result = result or self.last_status or self.verify_integrity()
        return {
            "report_type": "audit-integrity-verification",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "verified": result["verified"],
            "total_entries": result["total_entries"],
            "valid_entries": result["valid_entries"],
            "invalid_entries": result["invalid_entries"],
            "chain_breaks": result["chain_breaks"],
            "range": result.get("range", {}),
        }

    def get_status(self) -> Dict[str, Any]:
        """Вернуть последний статус проверки для отображения в UI."""
        return self.last_status or {
            "verified": None,
            "checked_at": None,
            "total_entries": 0,
            "valid_entries": 0,
            "invalid_entries": [],
            "chain_breaks": [],
        }

    def _recent_start_sequence(self, sample_size: int) -> int:
        row = self.db.fetchone(
            """
            SELECT sequence_number
            FROM audit_log
            WHERE sequence_number IS NOT NULL
            ORDER BY sequence_number DESC
            LIMIT 1 OFFSET ?
            """,
            (max(0, int(sample_size) - 1),),
        )
        return int(row[0]) if row and row[0] is not None else 0

    def _store_status(self, result: Dict[str, Any]):
        self.last_status = result
        self.last_checked_at = result["checked_at"]

    def _publish_tamper_detected(self, result: Dict[str, Any]):
        self._write_security_event(result)
        if not self.bus:
            return
        self.bus.publish(
            "TamperDetected",
            {
                "audit_verification_event": True,
                "reason": "audit_integrity_failed",
                "invalid_entries": result["invalid_entries"],
                "chain_breaks": result["chain_breaks"],
                "checked_at": result["checked_at"],
            },
        )

    def _write_security_event(self, result: Dict[str, Any]):
        if not hasattr(self.db, "execute"):
            return
        try:
            self.db.execute(
                "INSERT INTO audit_security_events (event_type, details) VALUES (?, ?)",
                (
                    "TamperDetected",
                    json.dumps(
                        {
                            "reason": "audit_integrity_failed",
                            "invalid_entries": result["invalid_entries"],
                            "chain_breaks": result["chain_breaks"],
                            "checked_at": result["checked_at"],
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                    ),
                ),
            )
        except Exception:
            pass

    @staticmethod
    def _mark_invalid(result: Dict[str, Any], sequence_number: int, reason: str):
        result["invalid_entries"].append({"sequence": sequence_number, "reason": reason})
        result["verified"] = False

    @staticmethod
    def _to_bytes(value) -> bytes:
        if isinstance(value, bytes):
            return value
        if isinstance(value, bytearray):
            return bytes(value)
        return str(value).encode("utf-8")

    def _iter_rows(self, query: str, params: tuple):
        if hasattr(self.db, "iter_rows"):
            return self.db.iter_rows(query, params, batch_size=500)
        return iter(self.db.fetchall(query, params))

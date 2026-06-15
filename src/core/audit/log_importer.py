import hashlib
import json
from datetime import datetime, timezone
from typing import Dict, Any

from core.security.side_channel_protection import constant_time_compare

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ed25519
except Exception:
    InvalidSignature = None
    ed25519 = None


ZERO_HASH = "0" * 64


class AuditLogImportVerifier:
    """Проверка и импорт signed JSON для TEST-3."""

    def __init__(self, db_helper, audit_logger=None):
        self.db = db_helper
        self.audit_logger = audit_logger

    def verify_signed_json(self, signed_json) -> Dict[str, Any]:
        """Проверяет signed json."""
        data = self._load_json(signed_json)
        entries = data.get("entries", [])
        public_key = data.get("public_key", "")
        result = {
            "verified": True,
            "total_entries": len(entries),
            "valid_entries": 0,
            "invalid_entries": [],
            "chain_breaks": [],
            "public_key": public_key,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }

        previous_hash = ZERO_HASH
        for entry in entries:
            sequence_number = entry.get("sequence_number")
            entry_data = entry.get("entry_data") or ""
            entry_bytes = entry_data.encode("utf-8") if isinstance(entry_data, str) else bytes(entry_data)
            entry_hash = entry.get("entry_hash") or ""
            signature = entry.get("signature") or ""

            if not constant_time_compare(hashlib.sha256(entry_bytes).hexdigest(), entry_hash):
                self._mark_invalid(result, sequence_number, "hash mismatch")
                continue

            entry_public_key = entry.get("public_key") or public_key
            if not self._verify_signature(entry_public_key, entry_bytes, signature):
                self._mark_invalid(result, sequence_number, "invalid signature")
                continue

            previous_hash_field = entry.get("previous_hash")
            if not constant_time_compare(previous_hash_field or "", previous_hash):
                result["verified"] = False
                result["chain_breaks"].append(
                    {"sequence": sequence_number, "expected": previous_hash, "actual": previous_hash_field}
                )

            result["valid_entries"] += 1
            previous_hash = entry_hash

        return result

    def import_signed_json(self, signed_json, verify_first: bool = True) -> Dict[str, Any]:
        """Описывает публичное действие import signed json."""
        data = self._load_json(signed_json)
        verification = self.verify_signed_json(data) if verify_first else {"verified": True}
        if not verification["verified"]:
            raise ValueError("Signed audit JSON failed verification.")

        imported = 0
        for entry in data.get("entries", []):
            entry_data = entry.get("entry_data") or ""
            decoded_entry = json.loads(entry_data)
            self.db.execute(
                """
                INSERT OR REPLACE INTO audit_log
                (sequence_number, previous_hash, entry_data, entry_hash, event_type, action,
                 timestamp, entry_id, details, signature, public_key)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.get("sequence_number"),
                    entry.get("previous_hash"),
                    entry_data.encode("utf-8"),
                    entry.get("entry_hash"),
                    decoded_entry.get("event_type"),
                    decoded_entry.get("event_type"),
                    decoded_entry.get("timestamp"),
                    decoded_entry.get("entry_id"),
                    json.dumps(decoded_entry.get("details", {}), ensure_ascii=False, sort_keys=True),
                    entry.get("signature"),
                    entry.get("public_key") or data.get("public_key", ""),
                ),
            )
            imported += 1

        if hasattr(self.db, "enable_audit_read"):
            self.db.enable_audit_read()
        if self.audit_logger:
            self.audit_logger.log_event(
                "AuditImportCompleted",
                severity="WARN",
                source="audit",
                details={"imported": imported},
            )
        return {"imported": imported, "verification": verification}

    @staticmethod
    def _load_json(value):
        if isinstance(value, dict):
            return value
        if hasattr(value, "read_text"):
            return json.loads(value.read_text(encoding="utf-8"))
        if isinstance(value, (bytes, bytearray)):
            return json.loads(bytes(value).decode("utf-8"))
        text = str(value)
        if text.strip().startswith("{"):
            return json.loads(text)
        with open(text, "r", encoding="utf-8") as file:
            return json.load(file)

    @staticmethod
    def _verify_signature(public_key_hex: str, entry_data: bytes, signature_hex: str) -> bool:
        if not public_key_hex or ed25519 is None:
            return False
        try:
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
            public_key.verify(bytes.fromhex(signature_hex), entry_data)
            return True
        except Exception as exc:
            if InvalidSignature is None or isinstance(exc, InvalidSignature):
                return False
            return False

    @staticmethod
    def _mark_invalid(result: Dict[str, Any], sequence_number, reason: str):
        result["verified"] = False
        result["invalid_entries"].append({"sequence": sequence_number, "reason": reason})

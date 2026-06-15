import base64
import gzip
import hashlib
import hmac
import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from core.events import event_bus

from .formats import CSVFormatHandler, NativeJSONFormatHandler, PasswordManagerFormatHandler


EXPORT_VERSION = "1.0"
SOURCE_APPLICATION = "CryptoSafe Manager"
DEFAULT_PBKDF2_ITERATIONS = 100_000
EXPORT_AAD = b"cryptosafe-manager:sprint6:export:v1"
SUPPORTED_FORMATS = {
    "encrypted_json",
    "csv",
    "bitwarden_json",
    "bitwarden_encrypted_json",
    "lastpass_csv",
    "lastpass_json",
    "password_manager_json",
}
SENSITIVE_FIELDS = {"password", "totp_secret"}


@dataclass
class ExportOptions:
    """Описывает публичный класс ExportOptions."""
    format: str = "encrypted_json"
    entry_ids: Optional[List[str]] = None
    include_fields: Optional[List[str]] = None
    exclude_fields: List[str] = field(default_factory=list)
    encrypt: bool = True
    allow_plaintext: bool = False
    encryption_strength: int = 256
    compression: bool = False
    encryption_password: Optional[str] = None
    recipient_public_key: Optional[bytes] = None
    master_password: Optional[str] = None
    master_password_confirmed: bool = False
    require_master_password_confirmation: bool = True


@dataclass
class ExportResult:
    """Описывает публичный класс ExportResult."""
    format: str
    content: bytes
    checksum: str
    entry_count: int
    encrypted: bool
    metadata: Dict[str, Any]


class VaultExporter:
    """Описывает публичный класс VaultExporter."""
    def __init__(self, entry_manager, db_connection=None, bus=event_bus):
        self.entry_manager = entry_manager
        self.db = db_connection or getattr(entry_manager, "db", None)
        self.key_manager = getattr(entry_manager, "key_manager", None)
        self.bus = bus
        self._panic_interrupted = False
        self.json_handler = NativeJSONFormatHandler()
        self.csv_handler = CSVFormatHandler()
        self.password_manager_handler = PasswordManagerFormatHandler()
        if hasattr(self.bus, "subscribe"):
            self.bus.subscribe("PanicModeActivated", self._handle_panic_interrupt)

    def export(self, options: Optional[ExportOptions] = None) -> ExportResult:
        """Экспортирует данные в выбранном формате."""
        options = options or ExportOptions()
        self._panic_interrupted = False
        self._validate_options(options)

        try:
            self._check_panic_interrupt()
            entries = self._collect_entries(options.entry_ids)
            self._check_panic_interrupt()
            filtered_entries = [self._filter_entry(entry, options) for entry in entries]
            payload_bytes = self._serialize_payload(filtered_entries, options)
            self._check_panic_interrupt()
            metadata = self._metadata(options, len(filtered_entries), payload_bytes)

            if options.compression:
                if options.format == "bitwarden_encrypted_json":
                    raise ValueError("Bitwarden encrypted JSON does not support CryptoSafe GZIP compression.")
                payload_bytes = gzip.compress(payload_bytes)
                metadata["compression"] = "gzip"
            else:
                metadata["compression"] = None

            if options.format == "bitwarden_encrypted_json":
                content = payload_bytes
                encrypted = True
            elif options.encrypt:
                content = self._build_encrypted_export(payload_bytes, metadata, options)
                encrypted = True
            else:
                if not options.allow_plaintext:
                    raise ValueError("Plaintext export requires allow_plaintext=True.")
                content = payload_bytes
                encrypted = False
            self._check_panic_interrupt()

            metadata["estimated_peak_bytes"] = max(len(payload_bytes), len(content))
            metadata["memory_budget_bytes"] = max(1, len(content) * 2)
            checksum = hashlib.sha256(content).hexdigest()
            result = ExportResult(
                format=options.format,
                content=content,
                checksum=checksum,
                entry_count=len(filtered_entries),
                encrypted=encrypted,
                metadata=metadata,
            )
            self._record_history(result, options)
            self._publish_event("VaultExportCreated", result, options)
            return result
        except Exception as exc:
            self._publish_failure(exc, options)
            raise

    def export_to_file(self, path: str, options: Optional[ExportOptions] = None) -> ExportResult:
        """Описывает публичное действие export to file."""
        result = self.export(options)
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                delete=False,
                dir=str(target.parent),
                prefix=f".{target.name}.",
                suffix=".tmp",
            ) as temp_file:
                temp_file.write(result.content)
                temp_file.flush()
                os.fsync(temp_file.fileno())
                temp_path = Path(temp_file.name)
            os.replace(temp_path, target)
            temp_path = None
        finally:
            if temp_path and temp_path.exists():
                self._wipe_file_best_effort(temp_path)
        result.metadata["file_path"] = str(target)
        self._update_history_file_size(result, target.stat().st_size)
        return result

    def export_by_query(self, query: str, options: Optional[ExportOptions] = None) -> ExportResult:
        """Описывает публичное действие export by query."""
        if not hasattr(self.entry_manager, "search_entries"):
            raise RuntimeError("EntryManager with search_entries is required for query export.")
        matched_entries = self.entry_manager.search_entries(query or "")
        selected_ids = [entry.get("id") for entry in matched_entries if entry.get("id")]
        query_options = options or ExportOptions()
        query_options.entry_ids = selected_ids
        return self.export(query_options)

    def _handle_panic_interrupt(self, event=None):
        self._panic_interrupted = True

    def _check_panic_interrupt(self):
        if self._panic_interrupted:
            raise RuntimeError("Operation interrupted by panic mode.")

    def _validate_options(self, options: ExportOptions):
        if options.format not in SUPPORTED_FORMATS:
            raise ValueError(f"Unsupported export format: {options.format}")
        if options.encryption_strength not in (128, 256):
            raise ValueError("encryption_strength must be 128 or 256")
        if options.format == "encrypted_json":
            options.encrypt = True
        if options.format == "bitwarden_encrypted_json":
            options.encrypt = True
            if options.recipient_public_key:
                raise ValueError("Bitwarden encrypted JSON supports password-based encryption only.")
        if options.master_password:
            options.master_password_confirmed = self._verify_master_password(options.master_password)
        if options.require_master_password_confirmation and not options.master_password_confirmed:
            raise PermissionError("Master password confirmation is required before export.")
        if options.encrypt and not options.encryption_password and not options.recipient_public_key:
            raise ValueError("Encrypted export requires encryption_password or recipient_public_key.")
        if options.recipient_public_key and options.encryption_password:
            raise ValueError("Choose either password-based or public-key encryption, not both.")
        if not options.encrypt and any(field in set(options.exclude_fields or []) for field in SENSITIVE_FIELDS):
            return

    def _verify_master_password(self, master_password: str) -> bool:
        if not self.key_manager or not self.db:
            return False
        row_hash = self.db.fetchone("SELECT key_data FROM key_store WHERE key_type = 'auth_hash'")
        if not row_hash:
            return False
        stored_hash = row_hash[0].decode("utf-8") if isinstance(row_hash[0], bytes) else str(row_hash[0])
        return bool(self.key_manager.derivation.verify_password(master_password, stored_hash))

    def _collect_entries(self, entry_ids: Optional[List[str]]) -> List[Dict[str, Any]]:
        if entry_ids:
            return [self.entry_manager.get_entry(entry_id) for entry_id in entry_ids]
        return self.entry_manager.get_all_entries(include_decrypted_password=True)

    def _filter_entry(self, entry: Dict[str, Any], options: ExportOptions) -> Dict[str, Any]:
        if options.include_fields:
            allowed = set(options.include_fields)
            allowed.update({"id", "created_at", "updated_at", "version"})
            filtered = {key: value for key, value in entry.items() if key in allowed}
        else:
            filtered = dict(entry)

        for field_name in options.exclude_fields:
            filtered.pop(field_name, None)
        return filtered

    def _serialize_payload(self, entries: List[Dict[str, Any]], options: ExportOptions) -> bytes:
        if options.format == "csv":
            return self.csv_handler.serialize(entries, self._format_fields(options))
        if options.format in {"bitwarden_json", "password_manager_json"}:
            return self.password_manager_handler.serialize_bitwarden(entries, self._format_fields(options))
        if options.format == "bitwarden_encrypted_json":
            return self.password_manager_handler.serialize_bitwarden_encrypted(
                entries,
                options.encryption_password or "",
                self._format_fields(options),
            )
        if options.format == "lastpass_csv":
            return self.password_manager_handler.serialize_lastpass_csv(entries, self._format_fields(options))
        if options.format == "lastpass_json":
            return self.password_manager_handler.serialize_lastpass_json(entries, self._format_fields(options))

        payload = {
            "version": EXPORT_VERSION,
            "source": SOURCE_APPLICATION,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "entry_count": len(entries),
            "entries": entries,
        }
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def _format_fields(self, options: ExportOptions) -> Optional[List[str]]:
        if options.include_fields:
            fields = list(options.include_fields)
        else:
            fields = ["title", "username", "password", "url", "notes", "category", "tags"]
        return [field for field in fields if field not in set(options.exclude_fields or [])]

    def _metadata(self, options: ExportOptions, entry_count: int, payload_bytes: bytes) -> Dict[str, Any]:
        return {
            "export_date": datetime.now(timezone.utc).isoformat(),
            "version": EXPORT_VERSION,
            "source_application": SOURCE_APPLICATION,
            "format": options.format,
            "entry_count": entry_count,
            "selected_entries": bool(options.entry_ids),
            "included_fields": options.include_fields,
            "excluded_fields": options.exclude_fields,
            "payload_sha256": hashlib.sha256(payload_bytes).hexdigest(),
            "payload_size": len(payload_bytes),
        }

    def _build_encrypted_export(
        self,
        payload_bytes: bytes,
        metadata: Dict[str, Any],
        options: ExportOptions,
    ) -> bytes:
        if options.recipient_public_key:
            encrypted_payload, signing_key = self._encrypt_with_public_key(payload_bytes, options)
        else:
            encrypted_payload, signing_key = self._encrypt_with_password(payload_bytes, options)

        integrity = self._integrity(payload_bytes, encrypted_payload, signing_key)
        package = self.json_handler.build_package(encrypted_payload, integrity, metadata)
        return self.json_handler.dumps(package)

    def _encrypt_with_password(self, payload_bytes: bytes, options: ExportOptions):
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key_len = options.encryption_strength // 8
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_len,
            salt=salt,
            iterations=DEFAULT_PBKDF2_ITERATIONS,
        )
        encryption_key = kdf.derive((options.encryption_password or "").encode("utf-8"))
        signing_key = self._derive_signing_key(encryption_key)
        ciphertext = AESGCM(encryption_key).encrypt(nonce, payload_bytes, EXPORT_AAD)

        encrypted_payload = {
            "encryption": {
                "algorithm": f"AES-{options.encryption_strength}-GCM",
                "key_derivation": "PBKDF2-SHA256",
                "iterations": DEFAULT_PBKDF2_ITERATIONS,
                "salt": base64.b64encode(salt).decode("ascii"),
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "aad": base64.b64encode(EXPORT_AAD).decode("ascii"),
                "key_separation": "export password key; master vault key is not reused",
            },
            "data": base64.b64encode(ciphertext).decode("ascii"),
        }
        self._clear_bytearray(encryption_key)
        return encrypted_payload, signing_key

    def _encrypt_with_public_key(self, payload_bytes: bytes, options: ExportOptions):
        key_len = options.encryption_strength // 8
        public_key = serialization.load_pem_public_key(options.recipient_public_key)
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            if options.encryption_strength != 256:
                raise ValueError("ECC public-key export requires AES-256-GCM.")
            return self._encrypt_with_ecies(payload_bytes, public_key)
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ValueError("Unsupported recipient public key type.")

        data_key = os.urandom(key_len)
        nonce = os.urandom(12)
        ciphertext = AESGCM(data_key).encrypt(nonce, payload_bytes, EXPORT_AAD)

        encrypted_key = public_key.encrypt(
            data_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        encrypted_payload = {
            "encryption": {
                "algorithm": f"RSA-OAEP/AES-{options.encryption_strength}-GCM",
                "key_derivation": "random-export-data-key",
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "aad": base64.b64encode(EXPORT_AAD).decode("ascii"),
                "key_separation": "random export data key; master vault key is not reused",
            },
            "encrypted_key": base64.b64encode(encrypted_key).decode("ascii"),
            "data": base64.b64encode(ciphertext).decode("ascii"),
        }
        signing_key = self._derive_signing_key(data_key)
        self._clear_bytearray(data_key)
        return encrypted_payload, signing_key

    def _encrypt_with_ecies(self, payload_bytes: bytes, recipient_public_key):
        if recipient_public_key.curve.name != "secp256r1":
            raise ValueError("ECC public-key export requires a P-256 recipient key.")
        ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
        shared_secret = ephemeral_private_key.exchange(ec.ECDH(), recipient_public_key)
        data_key = self._derive_ecdh_data_key(shared_secret)
        nonce = os.urandom(12)
        ciphertext = AESGCM(data_key).encrypt(nonce, payload_bytes, EXPORT_AAD)
        ephemeral_public_pem = ephemeral_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        encrypted_payload = {
            "encryption": {
                "algorithm": "ECIES-P-256/AES-256-GCM",
                "key_derivation": "ECDH-HKDF-SHA256",
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "aad": base64.b64encode(EXPORT_AAD).decode("ascii"),
                "forward_secrecy": "ephemeral ECDH key per export",
                "key_separation": "ephemeral ECDH export data key; master vault key is not reused",
            },
            "ephemeral_public_key": base64.b64encode(ephemeral_public_pem).decode("ascii"),
            "data": base64.b64encode(ciphertext).decode("ascii"),
        }
        signing_key = self._derive_signing_key(data_key)
        self._clear_bytearray(data_key)
        return encrypted_payload, signing_key

    @staticmethod
    def _derive_ecdh_data_key(shared_secret: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"cryptosafe-manager:sprint6:ecies-export",
            info=b"ecies-p256-export-data-key",
        ).derive(shared_secret)

    @staticmethod
    def _derive_signing_key(encryption_key: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"cryptosafe-manager:sprint6:export-signature",
            info=b"export-integrity-signature",
        ).derive(encryption_key)

    @staticmethod
    def _integrity(payload_bytes: bytes, encrypted_payload: Dict[str, Any], signing_key: bytes) -> Dict[str, Any]:
        canonical = json.dumps(encrypted_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return {
            "hash_algorithm": "SHA-256",
            "hash": hashlib.sha256(payload_bytes).hexdigest(),
            "signature_algorithm": "HMAC-SHA256",
            "signature": hmac.new(signing_key, canonical, hashlib.sha256).hexdigest(),
        }

    def _record_history(self, result: ExportResult, options: ExportOptions):
        if not self.db:
            return
        details = {
            "selected_entries": bool(options.entry_ids),
            "included_fields": options.include_fields,
            "excluded_fields": options.exclude_fields,
            "compression": options.compression,
        }
        self.db.execute(
            """
            INSERT INTO import_export_history
            (operation_type, export_format, encryption_used, entry_count, file_size,
             checksum, verification_status, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "export",
                result.format,
                "encrypted" if result.encrypted else "plaintext",
                result.entry_count,
                len(result.content),
                result.checksum,
                "created",
                json.dumps(details, ensure_ascii=False),
            ),
        )

    def _update_history_file_size(self, result: ExportResult, file_size: int):
        if not self.db:
            return
        self.db.execute(
            """
            UPDATE import_export_history
            SET file_size = ?
            WHERE id = (
                SELECT id FROM import_export_history
                WHERE operation_type = 'export' AND checksum = ?
                ORDER BY id DESC LIMIT 1
            )
            """,
            (file_size, result.checksum),
        )

    def _publish_event(self, event_name: str, result: ExportResult, options: ExportOptions):
        self.bus.publish(
            event_name,
            data={
                "format": result.format,
                "entry_count": result.entry_count,
                "encrypted": result.encrypted,
                "checksum": result.checksum,
                "selected_entries": bool(options.entry_ids),
            },
        )

    def _publish_failure(self, exc: Exception, options: ExportOptions):
        self.bus.publish(
            "VaultExportFailed",
            data={
                "format": getattr(options, "format", None),
                "error": type(exc).__name__,
            },
        )

    @staticmethod
    def _clear_bytearray(value: bytes):
        if not isinstance(value, (bytes, bytearray)):
            return False
        try:
            if isinstance(value, bytearray):
                for index in range(len(value)):
                    value[index] = 0
                return True
            # Тип bytes в Python неизменяемый; очищаем временную копию, чтобы вызывающий код мог использовать общий API.
            shadow = bytearray(value)
            for index in range(len(shadow)):
                shadow[index] = 0
            return True
        except Exception:
            return False

    @staticmethod
    def _wipe_file_best_effort(path: Path):
        try:
            size = path.stat().st_size
            with path.open("r+b") as handle:
                handle.write(b"\x00" * size)
                handle.flush()
                os.fsync(handle.fileno())
            path.unlink()
        except OSError:
            pass

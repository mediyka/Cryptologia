import base64
import csv
import gzip
import hashlib
import hmac
import io
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.padding import PKCS7

from core.events import event_bus
from core.security.side_channel_protection import constant_time_compare

from .exporter import DEFAULT_PBKDF2_ITERATIONS, EXPORT_AAD, VaultExporter
from .formats import CSVFormatSpec, FormatValidationError, NativeExportFormatSpec


MAX_IMPORT_FILE_SIZE = 10 * 1024 * 1024
DEFAULT_IMPORT_TIMEOUT_SECONDS = 30.0
BITWARDEN_KDF_TYPE_PBKDF2_SHA256 = 0
IMPORT_MODES = {"dry-run", "merge", "replace"}
DUPLICATE_POLICIES = {"skip", "update", "rename", "error"}
MALICIOUS_PATTERNS = [
    re.compile(r"<\s*script\b", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"data\s*:\s*text/html", re.IGNORECASE),
    re.compile(r"on\w+\s*=", re.IGNORECASE),
    re.compile(r"<\s*(iframe|object|embed|link|meta)\b", re.IGNORECASE),
]
CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class ImportValidationError(ValueError):
    """Описывает публичный класс ImportValidationError."""
    pass


@dataclass
class ImportOptions:
    """Описывает публичный класс ImportOptions."""
    format: Optional[str] = None
    mode: str = "dry-run"
    duplicate_policy: str = "skip"
    encryption_password: Optional[str] = None
    private_key_pem: Optional[bytes] = None
    max_file_size: int = MAX_IMPORT_FILE_SIZE
    timeout_seconds: float = DEFAULT_IMPORT_TIMEOUT_SECONDS
    checkpoint_path: Optional[str] = None
    resume_from_checkpoint: bool = False


@dataclass
class ImportPreview:
    """Описывает публичный класс ImportPreview."""
    format: str
    entries: List[Dict[str, Any]]
    warnings: List[str] = field(default_factory=list)
    duplicates: List[str] = field(default_factory=list)
    rejected: List[str] = field(default_factory=list)


@dataclass
class ImportResult:
    """Описывает публичный класс ImportResult."""
    format: str
    mode: str
    imported_count: int
    updated_count: int
    skipped_count: int
    rejected_count: int
    duplicate_count: int
    checksum: str
    warnings: List[str]
    preview: List[Dict[str, Any]]
    checkpoint_path: Optional[str] = None
    estimated_peak_bytes: int = 0
    memory_budget_bytes: int = 0


@dataclass
class ImportErrorReport:
    """Описывает публичный класс ImportErrorReport."""
    error_type: str
    message: str
    detected_format: str
    checksum: str
    recovery_options: List[str]
    partial_import_available: bool = False
    checkpoint_path: Optional[str] = None


class VaultImporter:
    """Описывает публичный класс VaultImporter."""
    def __init__(self, entry_manager=None, db_connection=None, bus=event_bus):
        self.entry_manager = entry_manager
        self.db = db_connection or getattr(entry_manager, "db", None)
        self.bus = bus
        self._panic_interrupted = False
        self.native_spec = NativeExportFormatSpec()
        self.csv_spec = CSVFormatSpec()
        self.last_error_report: Optional[ImportErrorReport] = None
        if hasattr(self.bus, "subscribe"):
            self.bus.subscribe("PanicModeActivated", self._handle_panic_interrupt)

    def import_from_file(self, path: str, options: Optional[ImportOptions] = None) -> ImportResult:
        """Описывает публичное действие import from file."""
        file_path = Path(path)
        content = file_path.read_bytes()
        return self.import_from_bytes(content, options=options, filename=file_path.name)

    def import_from_bytes(
        self,
        content: bytes,
        options: Optional[ImportOptions] = None,
        filename: Optional[str] = None,
    ) -> ImportResult:
        """Описывает публичное действие import from bytes."""
        options = options or ImportOptions()
        self._panic_interrupted = False
        self._validate_options(options, content)
        deadline = time.monotonic() + float(options.timeout_seconds)
        checksum = hashlib.sha256(content).hexdigest()
        detected_format = options.format or self.detect_format(content, filename)
        self.last_error_report = None

        try:
            self._check_panic_interrupt()
            self._check_timeout(deadline)
            raw_entries = self._parse_entries(content, detected_format, options, deadline)
            self._check_panic_interrupt()
            self._check_timeout(deadline)
            preview = self._validate_and_sanitize_entries(raw_entries)
            self._check_panic_interrupt()
            self._check_timeout(deadline)
            duplicates = self._find_duplicates(preview.entries)
            preview.duplicates.extend(duplicates)

            imported, updated, skipped = 0, 0, len(preview.rejected)
            if options.mode != "dry-run":
                if options.mode == "replace" and self.db:
                    self.db.begin_transaction()
                    try:
                        imported, updated, skipped_entries = self._commit_entries(
                            preview.entries, options, duplicates, checksum
                        )
                        self.db.commit_transaction()
                    except Exception:
                        self.db.rollback_transaction()
                        raise
                else:
                    imported, updated, skipped_entries = self._commit_entries(
                        preview.entries, options, duplicates, checksum
                    )
                skipped += skipped_entries
            self._check_panic_interrupt()

            result = ImportResult(
                format=detected_format,
                mode=options.mode,
                imported_count=imported,
                updated_count=updated,
                skipped_count=skipped,
                rejected_count=len(preview.rejected),
                duplicate_count=len(duplicates),
                checksum=checksum,
                warnings=preview.warnings,
                preview=preview.entries,
                checkpoint_path=options.checkpoint_path,
                estimated_peak_bytes=max(len(content), sum(len(json.dumps(entry, ensure_ascii=False)) for entry in preview.entries)),
                memory_budget_bytes=max(1, len(content) * 2),
            )
            self._complete_checkpoint(options, checksum)
            self._record_history(result, len(content), "validated" if options.mode == "dry-run" else "imported")
            self._publish_success(result)
            return result
        except Exception as exc:
            self.last_error_report = self.build_error_report(exc, detected_format, checksum, options)
            self._record_failed_history(detected_format, checksum, len(content), exc)
            self._publish_failure(detected_format, exc)
            raise

    def _handle_panic_interrupt(self, event=None):
        self._panic_interrupted = True

    def _check_panic_interrupt(self):
        if self._panic_interrupted:
            raise RuntimeError("Operation interrupted by panic mode.")

    def build_error_report(
        self,
        exc: Exception,
        detected_format: str,
        checksum: str,
        options: Optional[ImportOptions] = None,
    ) -> ImportErrorReport:
        """Описывает публичное действие build error report."""
        options = options or ImportOptions()
        recovery_options = []
        message = str(exc) or type(exc).__name__
        if detected_format == "unknown":
            recovery_options.append("Select the import format manually and retry.")
        if isinstance(exc, TimeoutError):
            recovery_options.append("Increase timeout_seconds or split the import file into smaller batches.")
        if isinstance(exc, ImportValidationError):
            recovery_options.append("Review the validation message, fix the source file, and run dry-run again.")
        if "password" in message.lower() or "signature" in message.lower() or "decrypt" in message.lower():
            recovery_options.append("Verify the export password or private key and retry from the original file.")
        if options.checkpoint_path:
            recovery_options.append("Resume with resume_from_checkpoint=True after fixing the cause.")
        if not recovery_options:
            recovery_options.append("Retry as dry-run to preview validation errors before committing.")
        return ImportErrorReport(
            error_type=type(exc).__name__,
            message=message,
            detected_format=detected_format,
            checksum=checksum,
            recovery_options=recovery_options,
            partial_import_available=self._checkpoint_exists(options, checksum),
            checkpoint_path=options.checkpoint_path,
        )

    def detect_format(self, content: bytes, filename: Optional[str] = None) -> str:
        """Описывает публичное действие detect format."""
        sample = (content or b"")[:4096].lstrip()
        lower_name = (filename or "").lower()
        if sample.startswith(b"{") and b"cryptosafe_export" in sample:
            return "encrypted_json"
        if sample.startswith(b"{") and b"cryptosafe_share" in sample:
            return "shared_entry"
        if sample.startswith(b"{") and b"passwordProtected" in sample and b"encKeyValidation_DO_NOT_EDIT" in sample:
            return "bitwarden_encrypted_json"
        if sample.startswith(b"{") or sample.startswith(b"["):
            try:
                parsed = json.loads(sample.decode("utf-8-sig", errors="ignore"))
                if isinstance(parsed, dict) and isinstance(parsed.get("items"), list):
                    return "bitwarden_json"
            except Exception:
                pass
            return "json"
        if lower_name.endswith(".csv") or b"," in sample:
            if any(name in sample.lower() for name in (b"url,username,password", b"extra,name,grouping")):
                return "lastpass_csv"
            return "csv"
        return "unknown"

    def _validate_options(self, options: ImportOptions, content: bytes):
        if options.mode not in IMPORT_MODES:
            raise ValueError("mode must be one of: dry-run, merge, replace")
        if options.duplicate_policy not in DUPLICATE_POLICIES:
            raise ValueError("duplicate_policy must be one of: skip, update, rename, error")
        if len(content or b"") > int(options.max_file_size):
            raise ImportValidationError("Import file exceeds configured size limit.")
        if options.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")

    def _parse_entries(
        self,
        content: bytes,
        detected_format: str,
        options: ImportOptions,
        deadline: float,
    ) -> List[Dict[str, Any]]:
        if detected_format == "encrypted_json":
            return self._parse_native_encrypted_json(content, options, deadline)
        if detected_format == "bitwarden_encrypted_json":
            return self._parse_bitwarden_encrypted_json(content, options)
        if detected_format == "bitwarden_json":
            return self._parse_bitwarden_json(content)
        if detected_format == "lastpass_csv":
            return self._parse_csv(content, lastpass=True)
        if detected_format == "csv":
            return self._parse_csv(content, lastpass=False)
        if detected_format == "json":
            return self._parse_plain_json(content)
        raise ImportValidationError("Unsupported or unknown import format.")

    def _parse_native_encrypted_json(
        self,
        content: bytes,
        options: ImportOptions,
        deadline: float,
    ) -> List[Dict[str, Any]]:
        package = self._load_json_object(content)
        self._validate_native_package(package)
        self._check_timeout(deadline)

        encryption = package["encryption"]
        encrypted_payload = {"encryption": encryption, "data": package["data"]}
        encrypted_key = package.get("encrypted_key")
        if encrypted_key:
            encrypted_payload["encrypted_key"] = encrypted_key
        if package.get("ephemeral_public_key"):
            encrypted_payload["ephemeral_public_key"] = package["ephemeral_public_key"]

        public_key_encrypted = bool(encrypted_key or package.get("ephemeral_public_key"))
        if public_key_encrypted:
            data_key = self._decrypt_export_data_key(package, options)
            try:
                signing_key = VaultExporter._derive_signing_key(data_key)
                self._verify_signature(package, encrypted_payload, signing_key)
                plaintext = self._decrypt_payload_with_key(package, data_key)
            finally:
                VaultExporter._clear_bytearray(data_key)
        else:
            if not options.encryption_password:
                raise ImportValidationError("Encrypted JSON import requires encryption_password.")
            key = self._derive_password_export_key(encryption, options.encryption_password)
            try:
                signing_key = VaultExporter._derive_signing_key(key)
                self._verify_signature(package, encrypted_payload, signing_key)
                plaintext = self._decrypt_payload_with_key(package, key)
            finally:
                VaultExporter._clear_bytearray(key)

        if not constant_time_compare(hashlib.sha256(plaintext).hexdigest(), package["integrity"]["hash"]):
            raise ImportValidationError("Payload integrity hash mismatch.")

        if package.get("metadata", {}).get("compression") == "gzip":
            plaintext = gzip.decompress(plaintext)

        source_format = package.get("metadata", {}).get("format", "encrypted_json")
        if source_format == "csv":
            return self._parse_csv(plaintext, lastpass=False)
        if source_format == "lastpass_csv":
            return self._parse_csv(plaintext, lastpass=True)
        if source_format == "lastpass_json":
            return self._parse_plain_json(plaintext)
        if source_format in {"bitwarden_json", "password_manager_json"}:
            return self._parse_bitwarden_json(plaintext)

        payload = self._load_json_object(plaintext)
        if not isinstance(payload.get("entries"), list):
            raise ImportValidationError("Native export payload does not contain entries.")
        return payload["entries"]

    def _validate_native_package(self, package: Dict[str, Any]):
        try:
            self.native_spec.validate(package)
        except FormatValidationError as exc:
            raise ImportValidationError(str(exc)) from exc

    def _derive_password_export_key(self, encryption: Dict[str, Any], password: str) -> bytes:
        if encryption.get("key_derivation") != "PBKDF2-SHA256":
            raise ImportValidationError("Unsupported key derivation.")
        salt = self._safe_b64decode(encryption.get("salt"), "salt")
        try:
            iterations = int(encryption.get("iterations", DEFAULT_PBKDF2_ITERATIONS))
        except (TypeError, ValueError) as exc:
            raise ImportValidationError("Invalid PBKDF2 iteration count.") from exc
        if iterations < DEFAULT_PBKDF2_ITERATIONS:
            raise ImportValidationError("PBKDF2 iteration count is below policy.")
        key_len = 16 if encryption.get("algorithm") == "AES-128-GCM" else 32
        return PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_len,
            salt=salt,
            iterations=iterations,
        ).derive(password.encode("utf-8"))

    def _decrypt_export_data_key(self, package: Dict[str, Any], options: ImportOptions) -> bytes:
        if not options.private_key_pem:
            raise ImportValidationError("Public-key encrypted import requires private_key_pem.")
        private_key = serialization.load_pem_private_key(options.private_key_pem, password=None)
        algorithm = package["encryption"].get("algorithm")
        if algorithm == "ECIES-P-256/AES-256-GCM":
            if not isinstance(private_key, ec.EllipticCurvePrivateKey):
                raise ImportValidationError("ECC export requires an elliptic curve private key.")
            ephemeral_public_pem = self._safe_b64decode(package.get("ephemeral_public_key"), "ephemeral_public_key")
            ephemeral_public_key = serialization.load_pem_public_key(ephemeral_public_pem)
            if not isinstance(ephemeral_public_key, ec.EllipticCurvePublicKey):
                raise ImportValidationError("Invalid export ephemeral public key.")
            if ephemeral_public_key.curve.name != "secp256r1":
                raise ImportValidationError("Invalid export ephemeral public key curve.")
            shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)
            return VaultExporter._derive_ecdh_data_key(shared_secret)

        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ImportValidationError("RSA export requires an RSA private key.")
        encrypted_key = self._safe_b64decode(package.get("encrypted_key"), "encrypted_key")
        return private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    def _verify_signature(self, package: Dict[str, Any], encrypted_payload: Dict[str, Any], signing_key: bytes):
        canonical = json.dumps(encrypted_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected = hmac.new(signing_key, canonical, hashlib.sha256).hexdigest()
        actual = str(package["integrity"].get("signature", ""))
        if not hmac.compare_digest(expected, actual):
            raise ImportValidationError("Export package signature verification failed.")

    def _decrypt_payload_with_key(self, package: Dict[str, Any], key: bytes) -> bytes:
        encryption = package["encryption"]
        nonce = self._safe_b64decode(encryption.get("nonce"), "nonce")
        ciphertext = self._safe_b64decode(package["data"], "data")
        aad = self._safe_b64decode(encryption.get("aad"), "aad") if encryption.get("aad") else EXPORT_AAD
        return AESGCM(key).decrypt(nonce, ciphertext, aad)

    def _parse_plain_json(self, content: bytes) -> List[Dict[str, Any]]:
        parsed = self._load_json_object(content)
        if isinstance(parsed, list):
            return parsed
        if isinstance(parsed, dict) and isinstance(parsed.get("entries"), list):
            return parsed["entries"]
        if isinstance(parsed, dict) and isinstance(parsed.get("items"), list):
            return self._bitwarden_items_to_entries(parsed["items"])
        raise ImportValidationError("JSON import must contain an entries/items list.")

    def _parse_bitwarden_json(self, content: bytes) -> List[Dict[str, Any]]:
        parsed = self._load_json_object(content)
        if not isinstance(parsed, dict) or not isinstance(parsed.get("items"), list):
            raise ImportValidationError("Bitwarden JSON must contain items.")
        return self._bitwarden_payload_to_entries(parsed)

    def _parse_bitwarden_encrypted_json(self, content: bytes, options: ImportOptions) -> List[Dict[str, Any]]:
        if not options.encryption_password:
            raise ImportValidationError("Bitwarden encrypted JSON import requires encryption_password.")
        package = self._load_json_object(content)
        if not isinstance(package, dict):
            raise ImportValidationError("Bitwarden encrypted JSON must be an object.")
        if package.get("encrypted") is not True or package.get("passwordProtected") is not True:
            raise ImportValidationError("Bitwarden encrypted JSON must be password-protected.")
        if int(package.get("kdfType", -1)) != BITWARDEN_KDF_TYPE_PBKDF2_SHA256:
            raise ImportValidationError("Only Bitwarden PBKDF2-SHA256 encrypted exports are supported.")
        salt = package.get("salt")
        try:
            iterations = int(package.get("kdfIterations"))
        except (TypeError, ValueError) as exc:
            raise ImportValidationError("Invalid Bitwarden KDF iteration count.") from exc
        key = self._derive_bitwarden_key(options.encryption_password, salt, iterations)
        self._decrypt_bitwarden_string(package.get("encKeyValidation_DO_NOT_EDIT"), key, "encKeyValidation_DO_NOT_EDIT")
        plaintext = self._decrypt_bitwarden_string(package.get("data"), key, "data")
        payload = self._load_json_object(plaintext)
        if not isinstance(payload, dict) or not isinstance(payload.get("items"), list):
            raise ImportValidationError("Decrypted Bitwarden payload does not contain items.")
        return self._bitwarden_payload_to_entries(payload)

    def _bitwarden_payload_to_entries(self, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
        folders = payload.get("folders") or []
        folder_map = {
            str(folder.get("id")): str(folder.get("name", ""))
            for folder in folders
            if isinstance(folder, dict) and folder.get("id")
        }
        return self._bitwarden_items_to_entries(payload["items"], folder_map)

    def _bitwarden_items_to_entries(self, items: List[Dict[str, Any]], folder_map: Optional[Dict[str, str]] = None) -> List[Dict[str, Any]]:
        folder_map = folder_map or {}
        entries = []
        for item in items:
            login = item.get("login") or {}
            uris = login.get("uris") or []
            url = ""
            if uris and isinstance(uris[0], dict):
                url = uris[0].get("uri", "")
            entries.append(
                {
                    "title": item.get("name", ""),
                    "username": login.get("username", ""),
                    "password": login.get("password", ""),
                    "url": url,
                    "notes": item.get("notes", ""),
                    "category": folder_map.get(str(item.get("folderId")), item.get("folderId") or ""),
                    "tags": [],
                }
            )
        return entries

    @staticmethod
    def _derive_bitwarden_key(password: str, salt: str, iterations: int) -> bytes:
        if not isinstance(salt, str) or not salt:
            raise ImportValidationError("Bitwarden encrypted JSON is missing salt.")
        master_key = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt.encode("utf-8"),
            iterations=iterations,
        ).derive(password.encode("utf-8"))
        enc_key = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"enc").derive(master_key)
        mac_key = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"mac").derive(master_key)
        return enc_key + mac_key

    @staticmethod
    def _decrypt_bitwarden_string(value: Any, key: bytes, field_name: str) -> bytes:
        if not isinstance(value, str) or not value.startswith("2."):
            raise ImportValidationError(f"{field_name} is not a supported Bitwarden EncString.")
        try:
            encrypted = value.split(".", 1)[1]
            iv_text, ciphertext_text, mac_text = encrypted.split("|")
            iv = base64.b64decode(iv_text, validate=True)
            ciphertext = base64.b64decode(ciphertext_text, validate=True)
            mac = base64.b64decode(mac_text, validate=True)
        except Exception as exc:
            raise ImportValidationError(f"{field_name} is malformed.") from exc
        enc_key = key[:32]
        mac_key = key[32:]
        expected_mac = hmac.digest(mac_key, iv + ciphertext, "sha256")
        if not hmac.compare_digest(expected_mac, mac):
            raise ImportValidationError("Bitwarden encrypted JSON password or integrity check failed.")
        decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
        padded = decryptor.update(ciphertext) + decryptor.finalize()
        try:
            unpadder = PKCS7(128).unpadder()
            return unpadder.update(padded) + unpadder.finalize()
        except ValueError as exc:
            raise ImportValidationError("Bitwarden encrypted JSON padding validation failed.") from exc

    def _parse_csv(self, content: bytes, lastpass: bool = False) -> List[Dict[str, Any]]:
        text = content.decode("utf-8-sig")
        text = self.csv_spec.strip_metadata_header(text)
        sample = text[:4096]
        first_line = sample.splitlines()[0] if sample.splitlines() else ""
        normalized_header = first_line.replace(" ", "").lower()
        # Для известных CSV-экспортов сначала фиксируем запятую, иначе Sniffer может принять частую букву за разделитель.
        if "," in first_line and (
            normalized_header.startswith("title,")
            or normalized_header.startswith("url,username,password")
            or "password" in normalized_header
        ):
            dialect = csv.excel
        else:
            try:
                dialect = csv.Sniffer().sniff(sample)
            except csv.Error:
                dialect = csv.excel
        reader = csv.DictReader(io.StringIO(text), dialect=dialect)
        if not reader.fieldnames:
            raise ImportValidationError("CSV import requires a header row.")
        if not lastpass:
            try:
                self.csv_spec.validate_header(reader.fieldnames)
            except FormatValidationError as exc:
                raise ImportValidationError(str(exc)) from exc

        entries = []
        for row in reader:
            lowered = {str(key or "").strip().lower(): value for key, value in row.items()}
            if lastpass or {"name", "extra", "grouping"} & set(lowered):
                entries.append(
                    {
                        "title": lowered.get("name", ""),
                        "username": lowered.get("username", ""),
                        "password": lowered.get("password", ""),
                        "url": lowered.get("url", ""),
                        "notes": lowered.get("extra", ""),
                        "category": lowered.get("grouping", ""),
                        "tags": [],
                    }
                )
            else:
                tags = lowered.get("tags", "")
                entries.append(
                    {
                        "title": lowered.get("title", "") or lowered.get("name", ""),
                        "username": lowered.get("username", ""),
                        "password": lowered.get("password", ""),
                        "url": lowered.get("url", "") or lowered.get("uri", ""),
                        "notes": lowered.get("notes", "") or lowered.get("extra", ""),
                        "category": lowered.get("category", "") or lowered.get("folder", ""),
                        "tags": [tag.strip() for tag in tags.split(",") if tag.strip()] if tags else [],
                    }
                )
        return entries

    def _validate_and_sanitize_entries(self, entries: List[Dict[str, Any]]) -> ImportPreview:
        preview = ImportPreview(format="normalized", entries=[])
        for index, entry in enumerate(entries, start=1):
            try:
                hits = self._scan_entry_for_malicious_patterns(entry)
                normalized = self._normalize_entry(entry)
                preview.entries.append(normalized)
                if hits:
                    preview.warnings.append(f"Entry {index} contained sanitized suspicious content: {', '.join(hits)}")
            except ImportValidationError as exc:
                preview.rejected.append(f"entry {index}: {exc}")
                preview.warnings.append(f"Rejected entry {index}: {exc}")
        return preview

    def _normalize_entry(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(entry, dict):
            raise ImportValidationError("entry must be an object")

        normalized = {
            "title": self._sanitize_text(self._coerce_text_field(entry, "title", "name")),
            "username": self._sanitize_text(self._coerce_text_field(entry, "username")),
            "password": self._sanitize_text(self._coerce_text_field(entry, "password")),
            "url": self._sanitize_text(self._coerce_text_field(entry, "url", "uri")),
            "notes": self._sanitize_text(self._coerce_text_field(entry, "notes", "extra")),
            "category": self._sanitize_text(self._coerce_text_field(entry, "category", "folder", "grouping")),
            "tags": self._sanitize_tags(entry.get("tags", [])),
        }

        if not normalized["title"]:
            raise ImportValidationError("title is required")
        if not normalized["password"]:
            raise ImportValidationError("password is required")
        if len(normalized["title"]) > 255:
            raise ImportValidationError("title is too long")
        for field_name in ("username", "url", "category"):
            if len(normalized[field_name]) > 1024:
                raise ImportValidationError(f"{field_name} is too long")
        if len(normalized["notes"]) > 10000:
            raise ImportValidationError("notes is too long")
        return normalized

    def _coerce_text_field(self, entry: Dict[str, Any], *field_names: str) -> str:
        for field_name in field_names:
            value = entry.get(field_name)
            if value in (None, ""):
                continue
            if isinstance(value, (list, dict, tuple, set)):
                raise ImportValidationError(f"{field_name} must be a scalar text field")
            return str(value)
        return ""

    def _sanitize_text(self, value: Any) -> str:
        if value is None:
            return ""
        if not isinstance(value, str):
            value = str(value)
        value = CONTROL_CHARS.sub("", value).strip()
        for pattern in MALICIOUS_PATTERNS:
            value = pattern.sub("[removed]", value)
        return value

    def _sanitize_tags(self, value: Any) -> List[str]:
        if isinstance(value, str):
            raw_tags = [tag.strip() for tag in value.split(",")]
        elif isinstance(value, list):
            raw_tags = value
        else:
            raw_tags = []
        tags = []
        for tag in raw_tags:
            clean = self._sanitize_text(tag)
            if clean and clean not in tags:
                tags.append(clean[:64])
        return tags[:20]

    def _scan_entry_for_malicious_patterns(self, entry: Dict[str, Any]) -> List[str]:
        if not isinstance(entry, dict):
            return []
        hits = []
        for field_name, value in entry.items():
            if isinstance(value, list):
                values = [str(item) for item in value]
            else:
                values = [str(value)]
            for text in values:
                if any(pattern.search(text) for pattern in MALICIOUS_PATTERNS):
                    hits.append(str(field_name))
                    break
        return sorted(set(hits))

    def _find_duplicates(self, entries: List[Dict[str, Any]]) -> List[str]:
        if not self.entry_manager:
            return []
        existing = self._existing_fingerprint_map()
        return [entry["title"] for entry in entries if self._fingerprint(entry) in existing]

    def _commit_entries(
        self,
        entries: List[Dict[str, Any]],
        options: ImportOptions,
        duplicates: List[str],
        checksum: str,
    ) -> Tuple[int, int, int]:
        if not self.entry_manager:
            raise RuntimeError("EntryManager is required for committing imports.")
        if options.duplicate_policy == "error" and duplicates:
            raise ImportValidationError("Duplicate entries detected.")

        imported, updated, skipped = 0, 0, 0
        existing = self._existing_fingerprint_map()
        completed = self._load_checkpoint(options, checksum)

        if options.mode == "replace" and not completed:
            self._clear_vault_entries()
            existing = {}

        for entry in entries:
            fingerprint = self._fingerprint(entry)
            if fingerprint in completed:
                skipped += 1
                continue
            existing_id = existing.get(fingerprint)
            if existing_id and options.duplicate_policy == "skip":
                skipped += 1
                self._save_checkpoint(options, checksum, completed | {fingerprint})
                completed.add(fingerprint)
                continue
            if existing_id and options.duplicate_policy == "update":
                self.entry_manager.update_entry(existing_id, entry)
                updated += 1
                self._save_checkpoint(options, checksum, completed | {fingerprint})
                completed.add(fingerprint)
                continue
            if existing_id and options.duplicate_policy == "rename":
                entry = dict(entry)
                entry["title"] = self._unique_title(entry["title"])

            new_id = self.entry_manager.create_entry(entry)
            existing[self._fingerprint(entry)] = new_id
            imported += 1
            completed.add(fingerprint)
            self._save_checkpoint(options, checksum, completed)

        return imported, updated, skipped

    def _load_checkpoint(self, options: ImportOptions, checksum: str) -> set:
        if not options.checkpoint_path or not options.resume_from_checkpoint:
            return set()
        path = Path(options.checkpoint_path)
        if not path.exists():
            return set()
        try:
            checkpoint = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ImportValidationError("Import checkpoint is corrupted.") from exc
        if not constant_time_compare(checkpoint.get("checksum") or "", checksum):
            raise ImportValidationError("Import checkpoint belongs to a different source file.")
        return set(checkpoint.get("completed_fingerprints") or [])

    def _save_checkpoint(self, options: ImportOptions, checksum: str, completed: set):
        if not options.checkpoint_path:
            return
        path = Path(options.checkpoint_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        # Чекпоинт хранит только отпечатки записей, без секретов и plaintext-полей.
        path.write_text(
            json.dumps(
                {
                    "version": "1.0",
                    "checksum": checksum,
                    "completed_fingerprints": sorted(completed),
                    "updated_at": time.time(),
                },
                ensure_ascii=False,
                sort_keys=True,
            ),
            encoding="utf-8",
        )

    def _complete_checkpoint(self, options: ImportOptions, checksum: str):
        if not options.checkpoint_path:
            return
        path = Path(options.checkpoint_path)
        if not path.exists():
            return
        try:
            checkpoint = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return
        if constant_time_compare(checkpoint.get("checksum") or "", checksum):
            checkpoint["completed"] = True
            checkpoint["completed_at"] = time.time()
            path.write_text(json.dumps(checkpoint, ensure_ascii=False, sort_keys=True), encoding="utf-8")

    def _checkpoint_exists(self, options: ImportOptions, checksum: str) -> bool:
        if not options.checkpoint_path:
            return False
        path = Path(options.checkpoint_path)
        if not path.exists():
            return False
        try:
            checkpoint = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return False
        return constant_time_compare(checkpoint.get("checksum") or "", checksum) and bool(checkpoint.get("completed_fingerprints"))

    def _clear_vault_entries(self):
        if not self.db:
            raise RuntimeError("Database connection is required for replace import.")
        self.db.execute("DELETE FROM vault_entries")

    def _existing_fingerprint_map(self) -> Dict[str, str]:
        existing = {}
        for entry in self.entry_manager.get_all_entries(include_decrypted_password=True):
            existing[self._fingerprint(entry)] = entry.get("id")
        return existing

    def _fingerprint(self, entry: Dict[str, Any]) -> str:
        normalized = "|".join(
            [
                str(entry.get("title", "")).strip().casefold(),
                str(entry.get("username", "")).strip().casefold(),
                str(entry.get("url", "")).strip().casefold(),
            ]
        )
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    def _unique_title(self, title: str) -> str:
        existing_titles = {
            str(entry.get("title", "")).casefold()
            for entry in self.entry_manager.get_all_entries(include_decrypted_password=True)
        }
        candidate = f"{title} (imported)"
        counter = 2
        while candidate.casefold() in existing_titles:
            candidate = f"{title} (imported {counter})"
            counter += 1
        return candidate

    def _record_history(self, result: ImportResult, file_size: int, status: str):
        if not self.db:
            return
        self.db.execute(
            """
            INSERT INTO import_export_history
            (operation_type, export_format, encryption_used, entry_count, file_size,
             checksum, verification_status, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "import",
                result.format,
                "encrypted" if result.format == "encrypted_json" else "plaintext",
                result.imported_count + result.updated_count,
                file_size,
                result.checksum,
                status,
                json.dumps(
                    {
                        "mode": result.mode,
                        "duplicates": result.duplicate_count,
                        "rejected": result.rejected_count,
                        "warnings": result.warnings,
                    },
                    ensure_ascii=False,
                ),
            ),
        )

    def _record_failed_history(self, detected_format: str, checksum: str, file_size: int, exc: Exception):
        if not self.db:
            return
        self.db.execute(
            """
            INSERT INTO import_export_history
            (operation_type, export_format, encryption_used, entry_count, file_size,
             checksum, verification_status, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "import",
                detected_format,
                "encrypted" if detected_format == "encrypted_json" else "plaintext",
                0,
                file_size,
                checksum,
                "failed",
                json.dumps(
                    {
                        "error": type(exc).__name__,
                        "message": str(exc),
                        "recovery_options": self.last_error_report.recovery_options if self.last_error_report else [],
                        "checkpoint_path": self.last_error_report.checkpoint_path if self.last_error_report else None,
                    },
                    ensure_ascii=False,
                ),
            ),
        )

    def _publish_success(self, result: ImportResult):
        self.bus.publish(
            "VaultImportCompleted",
            data={
                "format": result.format,
                "mode": result.mode,
                "imported_count": result.imported_count,
                "updated_count": result.updated_count,
                "rejected_count": result.rejected_count,
            },
        )

    def _publish_failure(self, detected_format: str, exc: Exception):
        self.bus.publish(
            "VaultImportFailed",
            data={"format": detected_format, "error": type(exc).__name__},
        )

    @staticmethod
    def _load_json_object(content: bytes) -> Dict[str, Any]:
        try:
            parsed = json.loads(content.decode("utf-8-sig"))
        except Exception as exc:
            raise ImportValidationError(f"Invalid JSON: {exc}") from exc
        if not isinstance(parsed, (dict, list)):
            raise ImportValidationError("JSON root must be an object or list.")
        return parsed

    @staticmethod
    def _safe_b64decode(value: Any, field_name: str) -> bytes:
        if not isinstance(value, str):
            raise ImportValidationError(f"{field_name} must be base64 text.")
        try:
            return base64.b64decode(value.encode("ascii"), validate=True)
        except Exception as exc:
            raise ImportValidationError(f"{field_name} is not valid base64.") from exc

    @staticmethod
    def _check_timeout(deadline: float):
        if time.monotonic() > deadline:
            raise TimeoutError("Import processing timed out.")

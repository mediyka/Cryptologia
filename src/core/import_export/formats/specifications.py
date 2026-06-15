import base64
import csv
import io
import json
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List


FORMAT_VERSION = "1.0"
NATIVE_EXPORT_SCHEMA = "cryptosafe-native-export-v1"
SHARED_ENTRY_SCHEMA = "cryptosafe-shared-entry-v1"
CSV_METADATA_PREFIX = "# cryptosafe:"


class FormatValidationError(ValueError):
    """Описывает публичный класс FormatValidationError."""
    pass


def _require_mapping(value: Any, label: str) -> Dict[str, Any]:
    if not isinstance(value, dict):
        raise FormatValidationError(f"{label} must be a JSON object.")
    return value


def _require_keys(value: Dict[str, Any], required: Iterable[str], label: str):
    missing = [key for key in required if key not in value]
    if missing:
        raise FormatValidationError(f"{label} missing required keys: {', '.join(missing)}.")


def _require_base64(value: Any, label: str):
    if not isinstance(value, str):
        raise FormatValidationError(f"{label} must be base64 text.")
    try:
        base64.b64decode(value.encode("ascii"), validate=True)
    except Exception as exc:
        raise FormatValidationError(f"{label} is not valid base64.") from exc


@dataclass(frozen=True)
class NativeExportFormatSpec:
    """Описывает публичный класс NativeExportFormatSpec."""
    version: str = FORMAT_VERSION
    schema: str = NATIVE_EXPORT_SCHEMA
    required_top_level: tuple = (
        "version",
        "format_schema",
        "cryptosafe_export",
        "timestamp",
        "metadata",
        "encryption",
        "data",
        "integrity",
    )
    supported_algorithms: tuple = (
        "AES-128-GCM",
        "AES-256-GCM",
        "RSA-OAEP/AES-128-GCM",
        "RSA-OAEP/AES-256-GCM",
        "ECIES-P-256/AES-256-GCM",
    )

    def validate(self, package: Dict[str, Any]) -> bool:
        """Описывает публичное действие validate."""
        package = _require_mapping(package, "Native export package")
        _require_keys(package, self.required_top_level, "Native export package")
        if package.get("version") != self.version:
            raise FormatValidationError("Unsupported native export format version.")
        if package.get("format_schema") != self.schema:
            raise FormatValidationError("Unsupported native export schema.")
        if package.get("cryptosafe_export") is not True:
            raise FormatValidationError("Not a CryptoSafe native export package.")

        encryption = _require_mapping(package.get("encryption"), "Encryption metadata")
        if encryption.get("algorithm") not in self.supported_algorithms:
            raise FormatValidationError("Unsupported native export encryption algorithm.")
        _require_base64(package.get("data"), "data")
        if encryption.get("nonce"):
            _require_base64(encryption["nonce"], "nonce")
        if encryption.get("salt"):
            _require_base64(encryption["salt"], "salt")
        if encryption.get("aad"):
            _require_base64(encryption["aad"], "aad")
        if package.get("encrypted_key"):
            _require_base64(package["encrypted_key"], "encrypted_key")
        if package.get("ephemeral_public_key"):
            _require_base64(package["ephemeral_public_key"], "ephemeral_public_key")
        if encryption.get("algorithm", "").startswith("RSA-OAEP") and not package.get("encrypted_key"):
            raise FormatValidationError("RSA native export package requires encrypted_key.")
        if encryption.get("algorithm") == "ECIES-P-256/AES-256-GCM" and not package.get("ephemeral_public_key"):
            raise FormatValidationError("ECC native export package requires ephemeral_public_key.")

        integrity = _require_mapping(package.get("integrity"), "Integrity metadata")
        _require_keys(integrity, ("hash_algorithm", "hash", "signature_algorithm", "signature"), "Integrity metadata")
        return True


@dataclass(frozen=True)
class SharedEntryFormatSpec:
    """Описывает публичный класс SharedEntryFormatSpec."""
    version: str = FORMAT_VERSION
    schema: str = SHARED_ENTRY_SCHEMA
    required_top_level: tuple = (
        "version",
        "format_schema",
        "cryptosafe_share",
        "share_id",
        "created_at",
        "expires_at",
        "source_application",
        "recipient_info",
        "permissions",
        "encryption",
        "data",
        "integrity",
    )
    supported_algorithms: tuple = (
        "AES-256-GCM",
        "RSA-OAEP/AES-256-GCM",
        "ECIES-P-256/AES-256-GCM",
    )

    def validate(self, package: Dict[str, Any]) -> bool:
        """Описывает публичное действие validate."""
        package = _require_mapping(package, "Shared entry package")
        _require_keys(package, self.required_top_level, "Shared entry package")
        if package.get("version") != self.version:
            raise FormatValidationError("Unsupported shared entry format version.")
        if package.get("format_schema") != self.schema:
            raise FormatValidationError("Unsupported shared entry schema.")
        if package.get("cryptosafe_share") is not True:
            raise FormatValidationError("Not a CryptoSafe shared entry package.")

        encryption = _require_mapping(package.get("encryption"), "Shared encryption metadata")
        if encryption.get("algorithm") not in self.supported_algorithms:
            raise FormatValidationError("Unsupported shared entry encryption algorithm.")
        if encryption.get("method") not in {"password", "public_key"}:
            raise FormatValidationError("Unsupported shared entry encryption method.")
        if encryption.get("algorithm") == "RSA-OAEP/AES-256-GCM" and not package.get("encrypted_key"):
            raise FormatValidationError("RSA shared entry package requires encrypted_key.")
        if encryption.get("algorithm") == "ECIES-P-256/AES-256-GCM" and not package.get("ephemeral_public_key"):
            raise FormatValidationError("ECC shared entry package requires ephemeral_public_key.")
        _require_base64(package.get("data"), "data")
        if encryption.get("nonce"):
            _require_base64(encryption["nonce"], "nonce")
        if encryption.get("salt"):
            _require_base64(encryption["salt"], "salt")
        if encryption.get("aad"):
            _require_base64(encryption["aad"], "aad")
        if package.get("encrypted_key"):
            _require_base64(package["encrypted_key"], "encrypted_key")
        if package.get("ephemeral_public_key"):
            _require_base64(package["ephemeral_public_key"], "ephemeral_public_key")

        integrity = _require_mapping(package.get("integrity"), "Shared integrity metadata")
        _require_keys(integrity, ("hash_algorithm", "hash", "signature_algorithm", "signature"), "Shared integrity metadata")
        return True


@dataclass(frozen=True)
class CSVFormatSpec:
    """Описывает публичный класс CSVFormatSpec."""
    version: str = FORMAT_VERSION
    fields: tuple = ("title", "username", "password", "url", "notes", "category", "tags")
    required_fields: tuple = ("title", "password")

    def validate_header(self, fieldnames: Iterable[str], require_required: bool = True) -> bool:
        """Проверяет header."""
        normalized = {str(field or "").strip().lower() for field in fieldnames}
        if require_required:
            missing = [field for field in self.required_fields if field not in normalized]
            if missing:
                raise FormatValidationError(f"CSV header missing required fields: {', '.join(missing)}.")
        allowed = set(self.fields)
        unknown = sorted(field for field in normalized if field and field not in allowed and field not in {"name", "uri", "extra", "folder"})
        if unknown:
            raise FormatValidationError(f"CSV header contains unsupported fields: {', '.join(unknown)}.")
        return True

    def metadata_line(self, metadata: Dict[str, Any]) -> str:
        """Описывает публичное действие metadata line."""
        payload = {
            "schema": "cryptosafe-csv-v1",
            "version": self.version,
            **(metadata or {}),
        }
        return f"{CSV_METADATA_PREFIX} {json.dumps(payload, ensure_ascii=False, sort_keys=True)}"

    def strip_metadata_header(self, text: str) -> str:
        # Удаляем только служебные строки в начале файла, не трогая переносы внутри CSV-значений.
        """Описывает публичное действие strip metadata header."""
        lines = io.StringIO(text)
        data_lines: List[str] = []
        for line in lines:
            if not data_lines and line.startswith(CSV_METADATA_PREFIX):
                continue
            data_lines.append(line)
        return "".join(data_lines)

    def sniff_header(self, text: str) -> List[str]:
        """Описывает публичное действие sniff header."""
        clean_text = self.strip_metadata_header(text)
        reader = csv.DictReader(io.StringIO(clean_text))
        return list(reader.fieldnames or [])

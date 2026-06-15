import base64
import json
from datetime import datetime, timezone
from typing import Any, Dict

from .specifications import NATIVE_EXPORT_SCHEMA, NativeExportFormatSpec


class NativeJSONFormatHandler:
    """Описывает публичный класс NativeJSONFormatHandler."""
    format_name = "encrypted_json"
    spec = NativeExportFormatSpec()

    @staticmethod
    def build_package(
        encrypted_payload: Dict[str, Any],
        integrity: Dict[str, Any],
        metadata: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Описывает публичное действие build package."""
        package = {
            "version": "1.0",
            "format_schema": NATIVE_EXPORT_SCHEMA,
            "cryptosafe_export": True,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "metadata": metadata,
            "encryption": encrypted_payload["encryption"],
            "data": encrypted_payload["data"],
            "integrity": integrity,
        }
        for key in ("encrypted_key", "ephemeral_public_key"):
            if encrypted_payload.get(key):
                package[key] = encrypted_payload[key]
        return package

    @staticmethod
    def dumps(package: Dict[str, Any]) -> bytes:
        """Описывает публичное действие dumps."""
        NativeJSONFormatHandler.spec.validate(package)
        return json.dumps(package, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")

    @staticmethod
    def b64(value: bytes) -> str:
        """Описывает публичное действие b64."""
        return base64.b64encode(value).decode("ascii")

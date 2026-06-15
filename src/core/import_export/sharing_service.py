import base64
import hashlib
import hmac
import json
import os
from urllib.parse import quote, urlencode
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
import uuid

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from core.events import event_bus
from core.security.side_channel_protection import constant_time_compare

from .formats import FormatValidationError, SHARED_ENTRY_SCHEMA, SharedEntryFormatSpec
from .exporter import VaultExporter


SHARE_VERSION = "1.0"
SHARE_AAD = b"cryptosafe-manager:sprint6:share:v1"
SHARE_PBKDF2_ITERATIONS = 100_000
DEFAULT_SHARE_FIELDS = ["title", "username", "password", "url", "notes", "category", "tags"]
VALID_SHARE_METHODS = {"password", "public_key"}
MIN_EXPIRATION_DAYS = 1
MAX_EXPIRATION_DAYS = 30


class ShareValidationError(ValueError):
    """Описывает публичный класс ShareValidationError."""
    pass


@dataclass
class ShareOptions:
    """Описывает публичный класс ShareOptions."""
    method: str = "password"
    recipient_info: str = ""
    password: Optional[str] = None
    recipient_public_key: Optional[bytes] = None
    permissions: Dict[str, Any] = field(default_factory=lambda: {"read": True, "edit": False})
    expires_in_days: int = 7
    include_fields: Optional[List[str]] = None
    sharer: str = "default_user"
    sender_public_key: Optional[bytes] = None


@dataclass
class ShareMetadata:
    """Описывает публичный класс ShareMetadata."""
    shared_id: str
    original_entry_id: str
    encryption_method: str
    recipient_info: str
    permissions: Dict[str, Any]
    expires_at: str


@dataclass
class SharePackage:
    """Описывает публичный класс SharePackage."""
    shared_id: str
    content: bytes
    encryption_method: str
    expires_at: str
    checksum: str
    metadata: Dict[str, Any]


@dataclass
class SharedEntryResult:
    """Описывает публичный класс SharedEntryResult."""
    shared_id: str
    entry: Dict[str, Any]
    metadata: Dict[str, Any]
    permissions: Dict[str, Any]
    saved_entry_id: Optional[str] = None


class SharingService:
    """Описывает публичный класс SharingService."""
    def __init__(self, entry_manager=None, db_connection=None, bus=event_bus):
        self.entry_manager = entry_manager
        self.db = db_connection or getattr(entry_manager, "db", None)
        self.bus = bus
        self.share_spec = SharedEntryFormatSpec()

    def share_entry(self, entry_id: str, options: Optional[ShareOptions] = None) -> SharePackage:
        """Описывает публичное действие share entry."""
        options = options or ShareOptions()
        try:
            self._validate_share_options(options)
            if not self.entry_manager:
                raise RuntimeError("EntryManager is required to share entries.")

            entry = self.entry_manager.get_entry(entry_id)
            share_id = str(uuid.uuid4())
            now = datetime.now(timezone.utc)
            expires_at = now + timedelta(days=options.expires_in_days)
            permissions = self._normalize_permissions(options.permissions, expires_at)
            payload = {
                "version": SHARE_VERSION,
                "share_id": share_id,
                "created_at": now.isoformat(),
                "expires_at": expires_at.isoformat(),
                "permissions": permissions,
                "entry": self._filter_entry(entry, options.include_fields),
            }
            payload_bytes = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")

            if options.method == "password":
                encrypted_payload, signing_key = self._encrypt_with_password(payload_bytes, options.password)
            else:
                encrypted_payload, signing_key = self._encrypt_with_public_key(payload_bytes, options.recipient_public_key)

            metadata = {
                "version": SHARE_VERSION,
                "format_schema": SHARED_ENTRY_SCHEMA,
                "cryptosafe_share": True,
                "share_id": share_id,
                "created_at": now.isoformat(),
                "expires_at": expires_at.isoformat(),
                "source_application": "CryptoSafe Manager",
                "sharer": options.sharer,
                "recipient_info": options.recipient_info,
                "permissions": permissions,
                "sender_public_key": options.sender_public_key.decode("utf-8") if options.sender_public_key else None,
            }
            package = {
                **metadata,
                "encryption": encrypted_payload["encryption"],
                "data": encrypted_payload["data"],
                "integrity": self._integrity(payload_bytes, encrypted_payload, signing_key),
            }
            if "encrypted_key" in encrypted_payload:
                package["encrypted_key"] = encrypted_payload["encrypted_key"]
            if "ephemeral_public_key" in encrypted_payload:
                package["ephemeral_public_key"] = encrypted_payload["ephemeral_public_key"]

            content = json.dumps(package, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")
            checksum = hashlib.sha256(content).hexdigest()
            self.create_share_record(
                entry_id=entry_id,
                recipient_info=options.recipient_info,
                encryption_method=options.method,
                permissions=permissions,
                expires_in_days=options.expires_in_days,
                shared_id=share_id,
            )
            result = SharePackage(share_id, content, options.method, expires_at.isoformat(), checksum, metadata)
            self._publish_share_success(result, entry_id)
            return result
        except Exception as exc:
            self._publish_share_failure(entry_id, exc)
            raise

    def decrypt_share_package(
        self,
        content: bytes,
        password: Optional[str] = None,
        private_key_pem: Optional[bytes] = None,
        allow_expired: bool = False,
    ) -> SharedEntryResult:
        """Описывает публичное действие decrypt share package."""
        package = self._load_share_package(content)
        encryption = package["encryption"]
        encrypted_payload = {"encryption": encryption, "data": package["data"]}
        if package.get("encrypted_key"):
            encrypted_payload["encrypted_key"] = package["encrypted_key"]
        if package.get("ephemeral_public_key"):
            encrypted_payload["ephemeral_public_key"] = package["ephemeral_public_key"]

        if encryption.get("method") == "password":
            if not password:
                raise ShareValidationError("Password is required for password-protected share.")
            key = self._derive_password_key(encryption, password)
            signing_key = self._derive_signing_key(key)
            self._verify_signature(package, encrypted_payload, signing_key)
            plaintext = self._decrypt_payload(package, key)
        elif encryption.get("method") == "public_key":
            if not private_key_pem:
                raise ShareValidationError("Private key is required for public-key share.")
            key = self._decrypt_data_key(package, private_key_pem)
            signing_key = self._derive_signing_key(key)
            self._verify_signature(package, encrypted_payload, signing_key)
            plaintext = self._decrypt_payload(package, key)
        else:
            raise ShareValidationError("Unsupported share encryption method.")

        if not constant_time_compare(hashlib.sha256(plaintext).hexdigest(), package["integrity"]["hash"]):
            raise ShareValidationError("Shared payload integrity hash mismatch.")

        payload = json.loads(plaintext.decode("utf-8"))
        expires_at = self._parse_datetime(payload.get("expires_at"))
        if expires_at < datetime.now(timezone.utc) and not allow_expired:
            raise ShareValidationError("Shared entry package has expired.")

        permissions = payload.get("permissions") or {}
        return SharedEntryResult(
            shared_id=payload["share_id"],
            entry=payload["entry"],
            metadata={
                "created_at": payload.get("created_at"),
                "expires_at": payload.get("expires_at"),
                "sharer": package.get("sharer"),
                "recipient_info": package.get("recipient_info"),
            },
            permissions=permissions,
        )

    def import_shared_entry(
        self,
        content: bytes,
        password: Optional[str] = None,
        private_key_pem: Optional[bytes] = None,
        save_to_vault: bool = True,
        allow_expired: bool = False,
    ) -> SharedEntryResult:
        """Описывает публичное действие import shared entry."""
        result = self.decrypt_share_package(content, password, private_key_pem, allow_expired)
        if not save_to_vault:
            self.bus.publish("EntryShareImported", data={"share_id": result.shared_id, "saved": False})
            return result
        if not self.entry_manager:
            raise RuntimeError("EntryManager is required to save shared entries.")

        entry = dict(result.entry)
        if not result.permissions.get("edit", False):
            metadata = dict(entry.get("sharing_metadata") or {})
            metadata.update({"imported_read_only": True, "share_id": result.shared_id})
            entry["sharing_metadata"] = metadata
        result.saved_entry_id = self.entry_manager.create_entry(entry)
        self.bus.publish(
            "EntryShareImported",
            data={"share_id": result.shared_id, "saved": True, "entry_id": result.saved_entry_id},
        )
        return result

    def create_share_record(
        self,
        entry_id: str,
        recipient_info: str,
        encryption_method: str,
        permissions: Optional[Dict[str, Any]] = None,
        expires_in_days: int = 7,
        shared_id: Optional[str] = None,
    ) -> ShareMetadata:
        """Создает share record."""
        permissions = permissions or {"read": True, "edit": False}
        shared_id = shared_id or str(uuid.uuid4())
        expires_at = permissions.get("expiration") or (
            datetime.now(timezone.utc) + timedelta(days=expires_in_days)
        ).isoformat()
        if self.db:
            self.db.execute(
                """
                INSERT OR REPLACE INTO shared_entries
                (shared_id, original_entry_id, encryption_method, recipient_info, permissions, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    shared_id,
                    entry_id,
                    encryption_method,
                    recipient_info,
                    json.dumps(permissions, ensure_ascii=False),
                    expires_at,
                ),
            )
        return ShareMetadata(shared_id, entry_id, encryption_method, recipient_info, permissions, expires_at)

    def build_share_link(self, shared_id: str, base_url: str, expires_at: Optional[str] = None) -> str:
        """Описывает публичное действие build share link."""
        if not shared_id:
            raise ValueError("shared_id is required for share link.")
        if not base_url or not str(base_url).startswith(("https://", "http://localhost", "http://127.0.0.1")):
            raise ValueError("Share links require HTTPS or a local development URL.")
        base = str(base_url).rstrip("/")
        query = urlencode({"expires": expires_at}) if expires_at else ""
        suffix = f"?{query}" if query else ""
        return f"{base}/share/{quote(str(shared_id), safe='')}{suffix}"

    def copy_share_link_to_clipboard(self, clipboard_service, share_link: str, shared_id: Optional[str] = None) -> bool:
        """Копирует share link to clipboard."""
        if not clipboard_service or not hasattr(clipboard_service, "copy_text"):
            raise RuntimeError("ClipboardService integration is required to copy share links.")
        copied = clipboard_service.copy_text(share_link, source_entry_id=shared_id)
        if copied:
            self.bus.publish("EntryShareLinkCopied", data={"share_id": shared_id, "auto_clear": True})
        return copied

    def _validate_share_options(self, options: ShareOptions):
        if options.method not in VALID_SHARE_METHODS:
            raise ValueError("Share method must be 'password' or 'public_key'.")
        if not (MIN_EXPIRATION_DAYS <= int(options.expires_in_days) <= MAX_EXPIRATION_DAYS):
            raise ValueError("Share expiration must be between 1 and 30 days.")
        if options.method == "password" and not options.password:
            raise ValueError("Password-based sharing requires password.")
        if options.method == "public_key" and not options.recipient_public_key:
            raise ValueError("Public-key sharing requires recipient_public_key.")

    @staticmethod
    def _normalize_permissions(permissions: Dict[str, Any], expires_at: datetime) -> Dict[str, Any]:
        return {
            "read": bool(permissions.get("read", True)),
            "edit": bool(permissions.get("edit", False)),
            "expiration": expires_at.isoformat(),
        }

    @staticmethod
    def _filter_entry(entry: Dict[str, Any], include_fields: Optional[List[str]]) -> Dict[str, Any]:
        allowed = set(include_fields or DEFAULT_SHARE_FIELDS)
        allowed.update({"version"})
        return {key: value for key, value in entry.items() if key in allowed}

    def _encrypt_with_password(self, payload_bytes: bytes, password: str):
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=SHARE_PBKDF2_ITERATIONS,
        ).derive(password.encode("utf-8"))
        ciphertext = AESGCM(key).encrypt(nonce, payload_bytes, SHARE_AAD)
        encrypted_payload = {
            "encryption": {
                "method": "password",
                "protocol": "password-aes-gcm",
                "algorithm": "AES-256-GCM",
                "key_derivation": "PBKDF2-SHA256",
                "iterations": SHARE_PBKDF2_ITERATIONS,
                "salt": base64.b64encode(salt).decode("ascii"),
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "aad": base64.b64encode(SHARE_AAD).decode("ascii"),
                "key_separation": "share password key; master vault key is not reused",
            },
            "data": base64.b64encode(ciphertext).decode("ascii"),
        }
        signing_key = self._derive_signing_key(key)
        VaultExporter._clear_bytearray(key)
        return encrypted_payload, signing_key

    def _encrypt_with_public_key(self, payload_bytes: bytes, public_key_pem: bytes):
        public_key = serialization.load_pem_public_key(public_key_pem)
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            return self._encrypt_with_ecies(payload_bytes, public_key)
        if not isinstance(public_key, rsa.RSAPublicKey):
            raise ShareValidationError("Unsupported recipient public key type.")

        data_key = os.urandom(32)
        nonce = os.urandom(12)
        ciphertext = AESGCM(data_key).encrypt(nonce, payload_bytes, SHARE_AAD)
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
                "method": "public_key",
                "protocol": "rsa-oaep-hybrid",
                "algorithm": "RSA-OAEP/AES-256-GCM",
                "key_derivation": "random-share-data-key",
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "aad": base64.b64encode(SHARE_AAD).decode("ascii"),
                "key_separation": "random share data key; master vault key is not reused",
            },
            "encrypted_key": base64.b64encode(encrypted_key).decode("ascii"),
            "data": base64.b64encode(ciphertext).decode("ascii"),
        }
        signing_key = self._derive_signing_key(data_key)
        VaultExporter._clear_bytearray(data_key)
        return encrypted_payload, signing_key

    def _encrypt_with_ecies(self, payload_bytes: bytes, recipient_public_key):
        if recipient_public_key.curve.name != "secp256r1":
            raise ShareValidationError("ECIES sharing requires an ECC P-256 recipient key.")
        ephemeral_private_key = ec.generate_private_key(ec.SECP256R1())
        shared_secret = ephemeral_private_key.exchange(ec.ECDH(), recipient_public_key)
        data_key = self._derive_ecdh_data_key(shared_secret)
        nonce = os.urandom(12)
        ciphertext = AESGCM(data_key).encrypt(nonce, payload_bytes, SHARE_AAD)
        ephemeral_public_pem = ephemeral_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        encrypted_payload = {
            "encryption": {
                "method": "public_key",
                "protocol": "ecies-p256-hkdf-aes-gcm",
                "algorithm": "ECIES-P-256/AES-256-GCM",
                "key_derivation": "ECDH-HKDF-SHA256",
                "nonce": base64.b64encode(nonce).decode("ascii"),
                "aad": base64.b64encode(SHARE_AAD).decode("ascii"),
                "forward_secrecy": "ephemeral ECDH key per share",
                "key_separation": "ephemeral ECDH share data key; master vault key is not reused",
            },
            "ephemeral_public_key": base64.b64encode(ephemeral_public_pem).decode("ascii"),
            "data": base64.b64encode(ciphertext).decode("ascii"),
        }
        signing_key = self._derive_signing_key(data_key)
        VaultExporter._clear_bytearray(data_key)
        return encrypted_payload, signing_key

    def _derive_password_key(self, encryption: Dict[str, Any], password: str) -> bytes:
        if encryption.get("key_derivation") != "PBKDF2-SHA256":
            raise ShareValidationError("Unsupported share key derivation.")
        try:
            iterations = int(encryption.get("iterations", 0))
        except (TypeError, ValueError) as exc:
            raise ShareValidationError("Invalid share PBKDF2 iteration count.") from exc
        if iterations < SHARE_PBKDF2_ITERATIONS:
            raise ShareValidationError("Share PBKDF2 iteration count is below policy.")
        salt = self._safe_b64decode(encryption.get("salt"), "salt")
        return PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
        ).derive(password.encode("utf-8"))

    def _decrypt_data_key(self, package: Dict[str, Any], private_key_pem: bytes) -> bytes:
        private_key = serialization.load_pem_private_key(private_key_pem, password=None)
        algorithm = package["encryption"].get("algorithm")
        if algorithm == "ECIES-P-256/AES-256-GCM":
            if not isinstance(private_key, ec.EllipticCurvePrivateKey):
                raise ShareValidationError("ECC share requires an elliptic curve private key.")
            ephemeral_public_pem = self._safe_b64decode(package.get("ephemeral_public_key"), "ephemeral_public_key")
            ephemeral_public_key = serialization.load_pem_public_key(ephemeral_public_pem)
            if not isinstance(ephemeral_public_key, ec.EllipticCurvePublicKey):
                raise ShareValidationError("Invalid ephemeral public key.")
            if ephemeral_public_key.curve.name != "secp256r1":
                raise ShareValidationError("Invalid ephemeral public key curve.")
            shared_secret = private_key.exchange(ec.ECDH(), ephemeral_public_key)
            return self._derive_ecdh_data_key(shared_secret)

        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise ShareValidationError("RSA share requires an RSA private key.")
        encrypted_key = self._safe_b64decode(package.get("encrypted_key"), "encrypted_key")
        return private_key.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

    @staticmethod
    def _derive_ecdh_data_key(shared_secret: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"cryptosafe-manager:sprint6:ecies-share",
            info=b"ecies-p256-share-data-key",
        ).derive(shared_secret)

    @staticmethod
    def _derive_signing_key(encryption_key: bytes) -> bytes:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"cryptosafe-manager:sprint6:share-signature",
            info=b"share-integrity-signature",
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

    def _verify_signature(self, package: Dict[str, Any], encrypted_payload: Dict[str, Any], signing_key: bytes):
        canonical = json.dumps(encrypted_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected = hmac.new(signing_key, canonical, hashlib.sha256).hexdigest()
        actual = str(package["integrity"].get("signature", ""))
        if not hmac.compare_digest(expected, actual):
            raise ShareValidationError("Shared package signature verification failed.")

    def _decrypt_payload(self, package: Dict[str, Any], key: bytes) -> bytes:
        encryption = package["encryption"]
        nonce = self._safe_b64decode(encryption.get("nonce"), "nonce")
        ciphertext = self._safe_b64decode(package["data"], "data")
        aad = self._safe_b64decode(encryption.get("aad"), "aad") if encryption.get("aad") else SHARE_AAD
        return AESGCM(key).decrypt(nonce, ciphertext, aad)

    def _load_share_package(self, content: bytes) -> Dict[str, Any]:
        try:
            package = json.loads(content.decode("utf-8-sig"))
        except Exception as exc:
            raise ShareValidationError(f"Invalid share package JSON: {exc}") from exc
        try:
            self.share_spec.validate(package)
        except FormatValidationError as exc:
            raise ShareValidationError(str(exc)) from exc
        return package

    @staticmethod
    def _safe_b64decode(value: Any, field_name: str) -> bytes:
        if not isinstance(value, str):
            raise ShareValidationError(f"{field_name} must be base64 text.")
        try:
            return base64.b64decode(value.encode("ascii"), validate=True)
        except Exception as exc:
            raise ShareValidationError(f"{field_name} is not valid base64.") from exc

    @staticmethod
    def _parse_datetime(value: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except Exception as exc:
            raise ShareValidationError("Invalid share expiration timestamp.") from exc
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _publish_share_success(self, result: SharePackage, entry_id: str):
        self.bus.publish(
            "EntryShareCreated",
            data={
                "share_id": result.shared_id,
                "entry_id": entry_id,
                "encryption_method": result.encryption_method,
                "expires_at": result.expires_at,
            },
        )

    def _publish_share_failure(self, entry_id: str, exc: Exception):
        self.bus.publish(
            "EntryShareFailed",
            data={"entry_id": entry_id, "error": type(exc).__name__},
        )

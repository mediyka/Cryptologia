import base64
import hashlib
import json
import uuid
import zlib
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from core.events import event_bus
from core.security.side_channel_protection import constant_time_compare


QR_PAYLOAD_VERSION = "1.0"
QR_DEFAULT_TTL_SECONDS = 5 * 60
QR_DEFAULT_CHUNK_SIZE = 700
QR_MAX_VALIDITY_SECONDS = 30 * 60
SUPPORTED_QR_TYPES = {"public_key", "encrypted_entry", "share_link"}


@dataclass
class KeyPair:
    """Описывает публичный класс KeyPair."""
    private_key_pem: bytes
    public_key_pem: bytes
    fingerprint: str
    algorithm: str


@dataclass
class QRChunk:
    """Описывает публичный класс QRChunk."""
    index: int
    total: int
    encoded_text: str
    checksum: str
    image_svg: Optional[str] = None


@dataclass
class QRCodeBundle:
    """Описывает публичный класс QRCodeBundle."""
    payload_id: str
    payload_type: str
    expires_at: str
    checksum: str
    chunks: List[QRChunk]


class QRCodeValidationError(ValueError):
    """Описывает публичный класс QRCodeValidationError."""
    pass


class KeyExchangeService:
    """Сервис обмена ключами и QR-полезной нагрузки для Sprint 6."""

    def __init__(self, db_connection=None, bus=event_bus):
        self.db = db_connection
        self.bus = bus
        self._seen_nonces = set()

    def generate_rsa_key_pair(self, key_size: int = 2048) -> KeyPair:
        """Описывает публичное действие generate rsa key pair."""
        if key_size < 2048:
            raise ValueError("RSA key_size must be at least 2048 bits")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return KeyPair(private_pem, public_pem, self.fingerprint(public_pem), f"RSA-{key_size}")

    def generate_ecc_key_pair(self) -> KeyPair:
        """Описывает публичное действие generate ecc key pair."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return KeyPair(private_pem, public_pem, self.fingerprint(public_pem), "ECC-P-256")

    @staticmethod
    def fingerprint(public_key_pem: bytes) -> str:
        """Описывает публичное действие fingerprint."""
        digest = hashlib.sha256(public_key_pem).digest()
        return base64.b32encode(digest[:20]).decode("ascii").rstrip("=")

    def store_contact_key(
        self,
        db_connection,
        contact_name: str,
        public_key_pem: bytes,
        identifier: Optional[str] = None,
        algorithm: Optional[str] = None,
        verified: bool = False,
    ) -> int:
        """Описывает публичное действие store contact key."""
        fingerprint = self.fingerprint(public_key_pem)
        algorithm = algorithm or self.detect_public_key_algorithm(public_key_pem)
        contact_id = db_connection.execute(
            """
            INSERT INTO contacts
            (contact_name, identifier, public_key, key_fingerprint, key_algorithm, status, verified)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                contact_name,
                identifier,
                public_key_pem.decode("utf-8"),
                fingerprint,
                algorithm,
                "active",
                1 if verified else 0,
            ),
        )
        self.bus.publish(
            "PublicKeyAdded",
            data={"contact_id": contact_id, "fingerprint": fingerprint, "algorithm": algorithm},
        )
        return contact_id

    def list_contacts(self, db_connection=None, include_revoked: bool = False) -> List[Dict[str, Any]]:
        """Описывает публичное действие list contacts."""
        db = db_connection or self.db
        if not db:
            return []
        query = """
            SELECT id, contact_name, identifier, public_key, key_fingerprint,
                   key_algorithm, status, verified, last_used_at, created_at, revoked_at, rotated_from
            FROM contacts
        """
        params = ()
        if not include_revoked:
            query += " WHERE status != ?"
            params = ("revoked",)
        query += " ORDER BY contact_name ASC, created_at DESC"
        rows = db.fetchall(query, params)
        return [
            {
                "id": row[0],
                "contact_name": row[1],
                "identifier": row[2],
                "public_key": row[3],
                "key_fingerprint": row[4],
                "key_algorithm": row[5],
                "status": row[6],
                "verified": bool(row[7]),
                "last_used_at": row[8],
                "created_at": row[9],
                "revoked_at": row[10],
                "rotated_from": row[11],
            }
            for row in rows
        ]

    def verify_contact_fingerprint(self, contact_id: int, fingerprint: str, db_connection=None) -> bool:
        """Проверяет contact fingerprint."""
        db = db_connection or self.db
        if not db:
            raise RuntimeError("Database connection is required.")
        row = db.fetchone("SELECT key_fingerprint FROM contacts WHERE id = ?", (contact_id,))
        if not row:
            return False
        verified = str(row[0]).replace(" ", "").upper() == str(fingerprint).replace(" ", "").upper()
        if verified:
            db.execute("UPDATE contacts SET verified = 1 WHERE id = ?", (contact_id,))
            self.bus.publish("PublicKeyVerified", data={"contact_id": contact_id, "fingerprint": row[0]})
        return verified

    def revoke_contact_key(self, contact_id: int, db_connection=None) -> bool:
        """Описывает публичное действие revoke contact key."""
        db = db_connection or self.db
        if not db:
            raise RuntimeError("Database connection is required.")
        db.execute(
            "UPDATE contacts SET status = ?, revoked_at = ? WHERE id = ?",
            ("revoked", datetime.now(timezone.utc).isoformat(), contact_id),
        )
        self.bus.publish("PublicKeyRevoked", data={"contact_id": contact_id})
        return True

    def rotate_contact_key(
        self,
        contact_id: int,
        new_public_key_pem: bytes,
        db_connection=None,
        algorithm: Optional[str] = None,
    ) -> int:
        """Описывает публичное действие rotate contact key."""
        db = db_connection or self.db
        if not db:
            raise RuntimeError("Database connection is required.")
        row = db.fetchone("SELECT contact_name, identifier FROM contacts WHERE id = ?", (contact_id,))
        if not row:
            raise ValueError("Contact not found.")
        self.revoke_contact_key(contact_id, db)
        new_id = self.store_contact_key(db, row[0], new_public_key_pem, row[1], algorithm=algorithm)
        db.execute("UPDATE contacts SET rotated_from = ? WHERE id = ?", (contact_id, new_id))
        self.bus.publish("PublicKeyRotated", data={"old_contact_id": contact_id, "new_contact_id": new_id})
        return new_id

    def get_active_public_key(self, contact_id: int, db_connection=None) -> Optional[bytes]:
        """Возвращает данные для active public key."""
        db = db_connection or self.db
        if not db:
            return None
        row = db.fetchone("SELECT public_key FROM contacts WHERE id = ? AND status = 'active'", (contact_id,))
        if not row:
            return None
        db.execute("UPDATE contacts SET last_used_at = ? WHERE id = ?", (datetime.now(timezone.utc).isoformat(), contact_id))
        return row[0].encode("utf-8") if isinstance(row[0], str) else row[0]

    @staticmethod
    def detect_public_key_algorithm(public_key_pem: bytes) -> str:
        """Описывает публичное действие detect public key algorithm."""
        public_key = serialization.load_pem_public_key(public_key_pem)
        if isinstance(public_key, rsa.RSAPublicKey):
            return f"RSA-{public_key.key_size}"
        if isinstance(public_key, ec.EllipticCurvePublicKey):
            return "ECC-P-256" if public_key.curve.name == "secp256r1" else f"ECC-{public_key.curve.name}"
        return "unknown"

    def create_public_key_payload(
        self,
        public_key_pem: bytes,
        contact_name: str,
        identifier: Optional[str] = None,
        ttl_seconds: int = QR_DEFAULT_TTL_SECONDS,
    ) -> Dict[str, Any]:
        """Создает public key payload."""
        self._validate_ttl(ttl_seconds)
        now = datetime.now(timezone.utc)
        return {
            "version": QR_PAYLOAD_VERSION,
            "type": "public_key",
            "payload_id": str(uuid.uuid4()),
            "nonce": base64.b64encode(uuid.uuid4().bytes).decode("ascii"),
            "created_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=ttl_seconds)).isoformat(),
            "contact_name": contact_name,
            "identifier": identifier,
            "algorithm": self.detect_public_key_algorithm(public_key_pem),
            "fingerprint": self.fingerprint(public_key_pem),
            "public_key": public_key_pem.decode("utf-8"),
        }

    def create_encrypted_entry_payload(
        self,
        share_package_content: bytes,
        ttl_seconds: int = QR_DEFAULT_TTL_SECONDS,
    ) -> Dict[str, Any]:
        """Создает encrypted entry payload."""
        self._validate_ttl(ttl_seconds)
        now = datetime.now(timezone.utc)
        encoded = base64.b64encode(share_package_content).decode("ascii")
        return {
            "version": QR_PAYLOAD_VERSION,
            "type": "encrypted_entry",
            "payload_id": str(uuid.uuid4()),
            "nonce": base64.b64encode(uuid.uuid4().bytes).decode("ascii"),
            "created_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=ttl_seconds)).isoformat(),
            "content_type": "application/vnd.cryptosafe.share+json",
            "data": encoded,
            "data_sha256": hashlib.sha256(share_package_content).hexdigest(),
        }

    def create_share_link_payload(
        self,
        url: str,
        ttl_seconds: int = QR_DEFAULT_TTL_SECONDS,
    ) -> Dict[str, Any]:
        """Создает share link payload."""
        self._validate_ttl(ttl_seconds)
        now = datetime.now(timezone.utc)
        return {
            "version": QR_PAYLOAD_VERSION,
            "type": "share_link",
            "payload_id": str(uuid.uuid4()),
            "nonce": base64.b64encode(uuid.uuid4().bytes).decode("ascii"),
            "created_at": now.isoformat(),
            "expires_at": (now + timedelta(seconds=ttl_seconds)).isoformat(),
            "url": url,
            "url_sha256": hashlib.sha256(url.encode("utf-8")).hexdigest(),
        }

    def generate_qr_codes(
        self,
        payload: Dict[str, Any],
        chunk_size: int = QR_DEFAULT_CHUNK_SIZE,
        render_svg: bool = True,
    ) -> QRCodeBundle:
        """Описывает публичное действие generate qr codes."""
        self.validate_qr_payload(payload, mark_seen=False)
        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        compressed = zlib.compress(canonical)
        payload_checksum = hashlib.sha256(canonical).hexdigest()
        total = max(1, (len(compressed) + chunk_size - 1) // chunk_size)
        chunks = []
        for index in range(total):
            data = compressed[index * chunk_size : (index + 1) * chunk_size]
            chunk_payload = {
                "qr_version": QR_PAYLOAD_VERSION,
                "payload_id": payload["payload_id"],
                "payload_type": payload["type"],
                "chunk_index": index + 1,
                "chunk_total": total,
                "payload_checksum": payload_checksum,
                "chunk_checksum": hashlib.sha256(data).hexdigest(),
                "data": base64.b64encode(data).decode("ascii"),
            }
            encoded_text = json.dumps(chunk_payload, sort_keys=True, separators=(",", ":"))
            chunks.append(
                QRChunk(
                    index=index + 1,
                    total=total,
                    encoded_text=encoded_text,
                    checksum=chunk_payload["chunk_checksum"],
                    image_svg=self._render_svg(encoded_text) if render_svg else None,
                )
            )
        bundle = QRCodeBundle(payload["payload_id"], payload["type"], payload["expires_at"], payload_checksum, chunks)
        self.bus.publish(
            "QRCodeGenerated",
            data={"payload_id": bundle.payload_id, "payload_type": bundle.payload_type, "chunks": len(chunks)},
        )
        return bundle

    def decode_qr_chunks(self, encoded_chunks: List[str], allow_replay: bool = False) -> Dict[str, Any]:
        """Описывает публичное действие decode qr chunks."""
        parsed_chunks = []
        payload_id = None
        payload_checksum = None
        total = None
        for encoded in encoded_chunks:
            try:
                chunk = json.loads(encoded)
                data = base64.b64decode(chunk["data"], validate=True)
            except Exception as exc:
                raise QRCodeValidationError("Malformed QR chunk.") from exc
            if not constant_time_compare(hashlib.sha256(data).hexdigest(), chunk.get("chunk_checksum") or ""):
                raise QRCodeValidationError("QR chunk checksum mismatch.")
            payload_id = payload_id or chunk.get("payload_id")
            payload_checksum = payload_checksum or chunk.get("payload_checksum")
            total = total or int(chunk.get("chunk_total", 0))
            if not constant_time_compare(chunk.get("payload_id") or "", payload_id or "") or not constant_time_compare(chunk.get("payload_checksum") or "", payload_checksum or ""):
                raise QRCodeValidationError("QR chunks belong to different payloads.")
            parsed_chunks.append((int(chunk["chunk_index"]), data))

        if not total or len(parsed_chunks) != total:
            raise QRCodeValidationError("QR chunk set is incomplete.")
        if sorted(index for index, _ in parsed_chunks) != list(range(1, total + 1)):
            raise QRCodeValidationError("QR chunk sequence is invalid.")

        compressed = b"".join(data for _, data in sorted(parsed_chunks))
        try:
            canonical = zlib.decompress(compressed)
        except Exception as exc:
            raise QRCodeValidationError("QR payload decompression failed.") from exc
        if not constant_time_compare(hashlib.sha256(canonical).hexdigest(), payload_checksum or ""):
            raise QRCodeValidationError("QR payload checksum mismatch.")
        try:
            payload = json.loads(canonical.decode("utf-8"))
        except Exception as exc:
            raise QRCodeValidationError("QR payload JSON is invalid.") from exc
        self.validate_qr_payload(payload, mark_seen=not allow_replay)
        self.bus.publish(
            "QRCodeScanned",
            data={"payload_id": payload.get("payload_id"), "payload_type": payload.get("type")},
        )
        return payload

    def decode_qr_chunks_from_clipboard(self, clipboard_service, allow_replay: bool = False) -> Dict[str, Any]:
        """Описывает публичное действие decode qr chunks from clipboard."""
        if not clipboard_service or not hasattr(clipboard_service, "platform"):
            raise RuntimeError("ClipboardService integration is required for clipboard QR import.")
        text = clipboard_service.platform.get_clipboard_content()
        if not text:
            raise QRCodeValidationError("Clipboard does not contain QR payload text.")
        encoded_chunks = self._parse_clipboard_qr_text(text)
        payload = self.decode_qr_chunks(encoded_chunks, allow_replay=allow_replay)
        self.bus.publish(
            "QRCodeClipboardScanned",
            data={"payload_id": payload.get("payload_id"), "payload_type": payload.get("type")},
        )
        return payload

    @staticmethod
    def _parse_clipboard_qr_text(text: str) -> List[str]:
        value = str(text).strip()
        if not value:
            return []
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return [json.dumps(item, sort_keys=True, separators=(",", ":")) if isinstance(item, dict) else str(item) for item in parsed]
            if isinstance(parsed, dict) and isinstance(parsed.get("chunks"), list):
                return [str(chunk) for chunk in parsed["chunks"]]
            if isinstance(parsed, dict) and "chunk_index" in parsed:
                return [json.dumps(parsed, sort_keys=True, separators=(",", ":"))]
        except Exception:
            pass
        return [line.strip() for line in value.splitlines() if line.strip()]

    def validate_qr_payload(self, payload: Dict[str, Any], mark_seen: bool = True) -> bool:
        """Проверяет qr payload."""
        if not isinstance(payload, dict):
            raise QRCodeValidationError("QR payload must be an object.")
        if payload.get("version") != QR_PAYLOAD_VERSION:
            raise QRCodeValidationError("Unsupported QR payload version.")
        if payload.get("type") not in SUPPORTED_QR_TYPES:
            raise QRCodeValidationError("Unsupported QR payload type.")
        for key in ("payload_id", "nonce", "created_at", "expires_at"):
            if not payload.get(key):
                raise QRCodeValidationError(f"QR payload missing {key}.")
        expires_at = self._parse_datetime(payload["expires_at"])
        created_at = self._parse_datetime(payload["created_at"])
        now = datetime.now(timezone.utc)
        if expires_at < now:
            raise QRCodeValidationError("QR payload has expired.")
        if expires_at - created_at > timedelta(seconds=QR_MAX_VALIDITY_SECONDS):
            raise QRCodeValidationError("QR payload validity period is too long.")
        nonce = str(payload["nonce"])
        if mark_seen and nonce in self._seen_nonces:
            raise QRCodeValidationError("QR payload replay detected.")

        if payload["type"] == "public_key":
            public_key = str(payload.get("public_key", "")).encode("utf-8")
            self.detect_public_key_algorithm(public_key)
            if self.fingerprint(public_key) != payload.get("fingerprint"):
                raise QRCodeValidationError("Public key fingerprint mismatch.")
        elif payload["type"] == "encrypted_entry":
            raw = base64.b64decode(str(payload.get("data", "")).encode("ascii"), validate=True)
            if not constant_time_compare(hashlib.sha256(raw).hexdigest(), payload.get("data_sha256") or ""):
                raise QRCodeValidationError("Encrypted entry payload checksum mismatch.")
        elif payload["type"] == "share_link":
            url = str(payload.get("url", ""))
            if not constant_time_compare(hashlib.sha256(url.encode("utf-8")).hexdigest(), payload.get("url_sha256") or ""):
                raise QRCodeValidationError("Share link checksum mismatch.")
        if mark_seen:
            self._seen_nonces.add(nonce)
        return True

    def import_public_key_payload(self, payload: Dict[str, Any], db_connection=None, verified: bool = False) -> int:
        """Описывает публичное действие import public key payload."""
        self.validate_qr_payload(payload, mark_seen=False)
        if payload["type"] != "public_key":
            raise QRCodeValidationError("QR payload is not a public key.")
        db = db_connection or self.db
        if not db:
            raise RuntimeError("Database connection is required.")
        return self.store_contact_key(
            db,
            payload["contact_name"],
            payload["public_key"].encode("utf-8"),
            payload.get("identifier"),
            algorithm=payload.get("algorithm"),
            verified=verified,
        )

    def decode_qr_image_file(self, image_path: str) -> List[str]:
        """Описывает публичное действие decode qr image file."""
        try:
            from PIL import Image
            from pyzbar.pyzbar import decode
        except Exception as exc:
            raise RuntimeError("QR image scanning requires Pillow and pyzbar.") from exc
        image = Image.open(Path(image_path))
        return [item.data.decode("utf-8") for item in decode(image)]

    def scan_from_camera(self) -> List[str]:
        """Описывает публичное действие scan from camera."""
        try:
            import cv2
        except Exception as exc:
            raise RuntimeError("Camera scanning requires OpenCV and an available camera.") from exc

        capture = cv2.VideoCapture(0)
        detector = cv2.QRCodeDetector()
        try:
            ok, frame = capture.read()
            if not ok:
                return []
            data, _, _ = detector.detectAndDecode(frame)
            return [data] if data else []
        finally:
            capture.release()

    @staticmethod
    def _render_svg(encoded_text: str) -> Optional[str]:
        try:
            import qrcode
            import qrcode.image.svg
        except Exception:
            return None

        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=4,
        )
        qr.add_data(encoded_text)
        qr.make(fit=True)
        image = qr.make_image(image_factory=qrcode.image.svg.SvgImage)
        svg = image.to_string()
        return svg.decode("utf-8") if isinstance(svg, bytes) else str(svg)

    @staticmethod
    def _parse_datetime(value: str) -> datetime:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _validate_ttl(ttl_seconds: int):
        if ttl_seconds <= 0:
            raise ValueError("QR payload TTL must be positive.")
        if ttl_seconds > QR_MAX_VALIDITY_SECONDS:
            raise ValueError("QR payload TTL exceeds maximum validity period.")

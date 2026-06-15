import json
import csv
import io
import base64
import hmac
import os
import uuid
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.padding import PKCS7


BITWARDEN_KDF_TYPE_PBKDF2_SHA256 = 0
BITWARDEN_DEFAULT_KDF_ITERATIONS = 600_000


class PasswordManagerFormatHandler:
    """Описывает публичный класс PasswordManagerFormatHandler."""
    format_name = "password_manager_json"

    def serialize_bitwarden(self, entries: Iterable[Dict], include_fields: Optional[List[str]] = None) -> bytes:
        """Описывает публичное действие serialize bitwarden."""
        selected = set(include_fields or [])
        entry_list = list(entries)
        folder_ids = {}
        folders = []
        for entry in entry_list:
            category = entry.get("category", "")
            if category and category not in folder_ids:
                folder_id = str(uuid.uuid4())
                folder_ids[category] = folder_id
                folders.append({"id": folder_id, "name": category})

        items = []
        for entry in entry_list:
            login = {}
            if not selected or "username" in selected:
                login["username"] = entry.get("username", "")
            if not selected or "password" in selected:
                login["password"] = entry.get("password", "")
            if not selected or "url" in selected:
                login["uris"] = [{"match": None, "uri": entry.get("url", "")}] if entry.get("url") else []
            login["totp"] = entry.get("totp_secret") if (not selected or "totp_secret" in selected) else None

            item = {
                "id": str(uuid.uuid4()),
                "organizationId": None,
                "folderId": folder_ids.get(entry.get("category", "")),
                "type": 1,
                "reprompt": 0,
                "name": entry.get("title", ""),
                "notes": entry.get("notes", "") if (not selected or "notes" in selected) else None,
                "favorite": False,
                "login": login,
                "collectionIds": None,
            }
            items.append(item)

        payload = {
            "encrypted": False,
            "folders": folders,
            "source": "CryptoSafe Manager",
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "items": items,
        }
        return json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")

    def serialize_bitwarden_encrypted(
        self,
        entries: Iterable[Dict],
        password: str,
        include_fields: Optional[List[str]] = None,
        iterations: int = BITWARDEN_DEFAULT_KDF_ITERATIONS,
    ) -> bytes:
        """Описывает публичное действие serialize bitwarden encrypted."""
        if not password:
            raise ValueError("Bitwarden encrypted JSON export requires encryption_password.")
        plaintext = self.serialize_bitwarden(entries, include_fields)
        salt = base64.b64encode(os.urandom(16)).decode("ascii")
        key = self._derive_bitwarden_key(password, salt, iterations)
        package = {
            "encrypted": True,
            "passwordProtected": True,
            "salt": salt,
            "kdfType": BITWARDEN_KDF_TYPE_PBKDF2_SHA256,
            "kdfIterations": iterations,
            "kdfMemory": None,
            "kdfParallelism": None,
            "encKeyValidation_DO_NOT_EDIT": self._encrypt_bitwarden_string(str(uuid.uuid4()).encode("utf-8"), key),
            "data": self._encrypt_bitwarden_string(plaintext, key),
        }
        return json.dumps(package, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")

    def serialize_lastpass_json(self, entries: Iterable[Dict], include_fields: Optional[List[str]] = None) -> bytes:
        """Описывает публичное действие serialize lastpass json."""
        selected = set(include_fields or [])
        rows = []
        for entry in entries:
            rows.append(
                {
                    "name": entry.get("title", ""),
                    "username": entry.get("username", "") if (not selected or "username" in selected) else "",
                    "password": entry.get("password", "") if (not selected or "password" in selected) else "",
                    "url": entry.get("url", "") if (not selected or "url" in selected) else "",
                    "extra": entry.get("notes", "") if (not selected or "notes" in selected) else "",
                    "grouping": entry.get("category", ""),
                }
            )
        return json.dumps(rows, ensure_ascii=False, sort_keys=True, indent=2).encode("utf-8")

    def serialize_lastpass_csv(self, entries: Iterable[Dict], include_fields: Optional[List[str]] = None) -> bytes:
        """Описывает публичное действие serialize lastpass csv."""
        selected = set(include_fields or [])
        output = io.StringIO(newline="")
        fieldnames = ["url", "username", "password", "extra", "name", "grouping"]
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        for entry in entries:
            writer.writerow(
                {
                    "url": entry.get("url", "") if (not selected or "url" in selected) else "",
                    "username": entry.get("username", "") if (not selected or "username" in selected) else "",
                    "password": entry.get("password", "") if (not selected or "password" in selected) else "",
                    "extra": entry.get("notes", "") if (not selected or "notes" in selected) else "",
                    "name": entry.get("title", ""),
                    "grouping": entry.get("category", ""),
                }
            )
        return output.getvalue().encode("utf-8-sig")

    @staticmethod
    def _derive_bitwarden_key(password: str, salt: str, iterations: int) -> bytes:
        master_key = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt.encode("utf-8"),
            iterations=int(iterations),
        ).derive(password.encode("utf-8"))
        enc_key = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"enc").derive(master_key)
        mac_key = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"mac").derive(master_key)
        return enc_key + mac_key

    @staticmethod
    def _encrypt_bitwarden_string(plaintext: bytes, key: bytes) -> str:
        enc_key = key[:32]
        mac_key = key[32:]
        iv = os.urandom(16)
        padder = PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        encryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).encryptor()
        ciphertext = encryptor.update(padded) + encryptor.finalize()
        mac = hmac.digest(mac_key, iv + ciphertext, "sha256")
        return "2.{}|{}|{}".format(
            base64.b64encode(iv).decode("ascii"),
            base64.b64encode(ciphertext).decode("ascii"),
            base64.b64encode(mac).decode("ascii"),
        )

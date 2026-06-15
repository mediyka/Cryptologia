import base64
import json
import os
import sys
import hmac

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.padding import PKCS7

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from core.import_export import ExportOptions, ImportOptions, KeyExchangeService, VaultExporter, VaultImporter
from core.import_export.exporter import DEFAULT_PBKDF2_ITERATIONS, EXPORT_AAD
from core.key_manager import KeyManager
from core.vault.entry_manager import EntryManager
from database.db import DatabaseHelper


@pytest.fixture
def sprint6_vault(tmp_path):
    db = DatabaseHelper(str(tmp_path / "sprint6.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")
    entry_manager = EntryManager(db, key_manager)
    first_id = entry_manager.create_entry(
        {
            "title": "GitHub",
            "username": "dev@example.com",
            "password": "G1tHub_Pass!",
            "url": "https://github.com",
            "notes": "primary account",
            "category": "Dev",
            "tags": ["code", "git"],
        }
    )
    second_id = entry_manager.create_entry(
        {
            "title": "Bank",
            "username": "ivan",
            "password": "B4nk_Pass!",
            "url": "https://bank.example",
            "notes": "do not export notes in plaintext",
            "category": "Finance",
            "tags": ["money"],
        }
    )
    yield db, entry_manager, first_id, second_id
    db.close()


def _decrypt_native_export(content: bytes, password: str):
    package = json.loads(content.decode("utf-8"))
    encryption = package["encryption"]
    salt = base64.b64decode(encryption["salt"])
    nonce = base64.b64decode(encryption["nonce"])
    ciphertext = base64.b64decode(package["data"])
    bits = 128 if encryption["algorithm"] == "AES-128-GCM" else 256
    key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=bits // 8,
        salt=salt,
        iterations=DEFAULT_PBKDF2_ITERATIONS,
    ).derive(password.encode("utf-8"))
    return AESGCM(key).decrypt(nonce, ciphertext, EXPORT_AAD)


def _decrypt_bitwarden_string(value: str, password: str, salt: str, iterations: int) -> bytes:
    _kind, encrypted = value.split(".", 1)
    iv_text, ciphertext_text, mac_text = encrypted.split("|")
    iv = base64.b64decode(iv_text)
    ciphertext = base64.b64decode(ciphertext_text)
    mac = base64.b64decode(mac_text)
    master_key = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode("utf-8"),
        iterations=iterations,
    ).derive(password.encode("utf-8"))
    enc_key = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"enc").derive(master_key)
    mac_key = HKDFExpand(algorithm=hashes.SHA256(), length=32, info=b"mac").derive(master_key)
    assert hmac.compare_digest(hmac.digest(mac_key, iv + ciphertext, "sha256"), mac)
    decryptor = Cipher(algorithms.AES(enc_key), modes.CBC(iv)).decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def test_arc_1_schema(sprint6_vault):
    db, _, _, _ = sprint6_vault
    tables = {row[0] for row in db.fetchall("SELECT name FROM sqlite_master WHERE type = 'table'")}

    assert "import_export_history" in tables
    assert "shared_entries" in tables
    assert "contacts" in tables


def test_exp_2_native_roundtrip(sprint6_vault):
    db, entry_manager, _, _ = sprint6_vault
    exporter = VaultExporter(entry_manager)
    result = exporter.export(
        ExportOptions(
            format="encrypted_json",
            encryption_password="export-passphrase",
            master_password_confirmed=True,
        )
    )

    package = json.loads(result.content.decode("utf-8"))
    plaintext = _decrypt_native_export(result.content, "export-passphrase")
    payload = json.loads(plaintext.decode("utf-8"))
    history = db.fetchall("SELECT operation_type, export_format, encryption_used FROM import_export_history")

    assert package["cryptosafe_export"] is True
    assert package["encryption"]["algorithm"] == "AES-256-GCM"
    assert package["metadata"]["entry_count"] == 2
    assert package["integrity"]["hash"]
    assert package["integrity"]["signature"]
    assert payload["entry_count"] == 2
    assert {entry["title"] for entry in payload["entries"]} == {"GitHub", "Bank"}
    assert history[-1] == ("export", "encrypted_json", "encrypted")


def test_exp_3_selective_fields(sprint6_vault):
    _, entry_manager, first_id, _ = sprint6_vault
    exporter = VaultExporter(entry_manager)
    result = exporter.export(
        ExportOptions(
            format="encrypted_json",
            entry_ids=[first_id],
            exclude_fields=["notes"],
            encryption_password="export-passphrase",
            master_password_confirmed=True,
        )
    )

    payload = json.loads(_decrypt_native_export(result.content, "export-passphrase").decode("utf-8"))
    assert payload["entry_count"] == 1
    assert payload["entries"][0]["title"] == "GitHub"
    assert "notes" not in payload["entries"][0]


def test_exp_1_plaintext_opt_in(sprint6_vault):
    _, entry_manager, _, _ = sprint6_vault
    exporter = VaultExporter(entry_manager)

    with pytest.raises(ValueError):
        exporter.export(
            ExportOptions(
                format="csv",
                encrypt=False,
                master_password_confirmed=True,
            )
        )

    result = exporter.export(
        ExportOptions(
            format="csv",
            encrypt=False,
            allow_plaintext=True,
            exclude_fields=["notes"],
            master_password_confirmed=True,
        )
    )
    text = result.content.decode("utf-8-sig")
    assert "title,username,password,url,category,tags" in text
    assert "primary account" not in text


def test_exp_1_bitwarden_encrypted_json(sprint6_vault):
    _, entry_manager, _, _ = sprint6_vault
    result = VaultExporter(entry_manager).export(
        ExportOptions(
            format="bitwarden_encrypted_json",
            encryption_password="bitwarden-export-passphrase",
            master_password_confirmed=True,
        )
    )

    package = json.loads(result.content.decode("utf-8"))
    plaintext = _decrypt_bitwarden_string(
        package["data"],
        "bitwarden-export-passphrase",
        package["salt"],
        package["kdfIterations"],
    )
    payload = json.loads(plaintext.decode("utf-8"))

    assert result.encrypted is True
    assert package["encrypted"] is True
    assert package["passwordProtected"] is True
    assert package["kdfType"] == 0
    assert package["data"].startswith("2.")
    assert package["encKeyValidation_DO_NOT_EDIT"].startswith("2.")
    assert payload["encrypted"] is False
    assert {item["name"] for item in payload["items"]} == {"GitHub", "Bank"}


def test_exp_4_master_confirm(sprint6_vault):
    _, entry_manager, _, _ = sprint6_vault
    exporter = VaultExporter(entry_manager)

    with pytest.raises(PermissionError):
        exporter.export(ExportOptions(format="encrypted_json", encryption_password="export-passphrase"))

    result = exporter.export(
        ExportOptions(
            format="encrypted_json",
            encryption_password="export-passphrase",
            master_password="Str0ng!P@ssw0rd123",
        )
    )
    assert result.encrypted is True


def test_exp_2_ecc_public_key_roundtrip(sprint6_vault, tmp_path):
    _, source_entries, _, _ = sprint6_vault
    target_db = DatabaseHelper(str(tmp_path / "ecc-target.db"))
    target_key_manager = KeyManager(target_db)
    assert target_key_manager.setup_new_vault("Str0ng!P@ssw0rd123")
    target_entries = EntryManager(target_db, target_key_manager)
    keys = KeyExchangeService().generate_ecc_key_pair()

    try:
        exported = VaultExporter(source_entries).export(
            ExportOptions(
                format="encrypted_json",
                recipient_public_key=keys.public_key_pem,
                master_password_confirmed=True,
            )
        )
        package = json.loads(exported.content.decode("utf-8"))
        result = VaultImporter(target_entries).import_from_bytes(
            exported.content,
            ImportOptions(mode="merge", private_key_pem=keys.private_key_pem),
        )

        assert package["encryption"]["algorithm"] == "ECIES-P-256/AES-256-GCM"
        assert "ephemeral_public_key" in package
        assert "encrypted_key" not in package
        assert result.imported_count == 2
    finally:
        target_db.close()

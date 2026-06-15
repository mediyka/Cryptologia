import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from core.import_export import KeyExchangeService, ShareOptions, ShareValidationError, SharingService
from core.key_manager import KeyManager
from core.vault.entry_manager import EntryManager
from database.db import DatabaseHelper


@pytest.fixture
def sharing_vaults(tmp_path):
    source_db = DatabaseHelper(str(tmp_path / "source-share.db"))
    source_key_manager = KeyManager(source_db)
    assert source_key_manager.setup_new_vault("Str0ng!P@ssw0rd123")
    source_entries = EntryManager(source_db, source_key_manager)
    entry_id = source_entries.create_entry(
        {
            "title": "GitHub",
            "username": "dev@example.com",
            "password": "G1tHub_Pass!",
            "url": "https://github.com",
            "notes": "share me",
            "category": "Dev",
            "tags": ["git"],
        }
    )

    target_db = DatabaseHelper(str(tmp_path / "target-share.db"))
    target_key_manager = KeyManager(target_db)
    assert target_key_manager.setup_new_vault("Str0ng!P@ssw0rd123")
    target_entries = EntryManager(target_db, target_key_manager)

    yield source_db, source_entries, entry_id, target_db, target_entries
    source_db.close()
    target_db.close()


def test_shr_1_password_temp(sharing_vaults):
    source_db, source_entries, entry_id, _, target_entries = sharing_vaults
    service = SharingService(source_entries)
    package = service.share_entry(
        entry_id,
        ShareOptions(
            method="password",
            recipient_info="alice@example.com",
            password="share-passphrase",
            permissions={"read": True, "edit": False},
            expires_in_days=3,
        ),
    )

    decoded = SharingService(target_entries).import_shared_entry(
        package.content,
        password="share-passphrase",
        save_to_vault=False,
    )
    rows = source_db.fetchall("SELECT shared_id, original_entry_id, encryption_method FROM shared_entries")

    assert package.encryption_method == "password"
    assert decoded.entry["title"] == "GitHub"
    assert decoded.saved_entry_id is None
    assert target_entries.get_all_entries(include_decrypted_password=True) == []
    assert rows[-1] == (package.shared_id, entry_id, "password")


def test_shr_2_import_read_only(sharing_vaults):
    _, source_entries, entry_id, _, target_entries = sharing_vaults
    package = SharingService(source_entries).share_entry(
        entry_id,
        ShareOptions(
            method="password",
            recipient_info="alice@example.com",
            password="share-passphrase",
            permissions={"read": True, "edit": False},
        ),
    )

    result = SharingService(target_entries).import_shared_entry(
        package.content,
        password="share-passphrase",
        save_to_vault=True,
    )
    saved = target_entries.get_entry(result.saved_entry_id)

    assert result.saved_entry_id is not None
    assert saved["password"] == "G1tHub_Pass!"
    assert saved["sharing_metadata"]["imported_read_only"] is True


def test_shr_1_public_key(sharing_vaults):
    _, source_entries, entry_id, _, target_entries = sharing_vaults
    keys = KeyExchangeService().generate_rsa_key_pair()
    package = SharingService(source_entries).share_entry(
        entry_id,
        ShareOptions(
            method="public_key",
            recipient_info="alice",
            recipient_public_key=keys.public_key_pem,
            permissions={"read": True, "edit": True},
        ),
    )

    result = SharingService(target_entries).import_shared_entry(
        package.content,
        private_key_pem=keys.private_key_pem,
        save_to_vault=False,
    )

    assert package.encryption_method == "public_key"
    assert result.entry["username"] == "dev@example.com"
    assert result.permissions["edit"] is True


def test_cry_2_ecc_share(sharing_vaults):
    _, source_entries, entry_id, _, target_entries = sharing_vaults
    keys = KeyExchangeService().generate_ecc_key_pair()
    package = SharingService(source_entries).share_entry(
        entry_id,
        ShareOptions(
            method="public_key",
            recipient_info="alice",
            recipient_public_key=keys.public_key_pem,
        ),
    )
    payload = json.loads(package.content.decode("utf-8"))
    result = SharingService(target_entries).import_shared_entry(
        package.content,
        private_key_pem=keys.private_key_pem,
        save_to_vault=False,
    )

    assert payload["encryption"]["algorithm"] == "ECIES-P-256/AES-256-GCM"
    assert payload["encryption"]["key_derivation"] == "ECDH-HKDF-SHA256"
    assert payload["encryption"]["forward_secrecy"] == "ephemeral ECDH key per share"
    assert "ephemeral_public_key" in payload
    assert "encrypted_key" not in payload
    assert result.entry["title"] == "GitHub"


def test_cry_3_unique_ephemeral(sharing_vaults):
    _, source_entries, entry_id, _, _ = sharing_vaults
    keys = KeyExchangeService().generate_ecc_key_pair()
    service = SharingService(source_entries)

    first = json.loads(
        service.share_entry(
            entry_id,
            ShareOptions(method="public_key", recipient_info="alice", recipient_public_key=keys.public_key_pem),
        ).content.decode("utf-8")
    )
    second = json.loads(
        service.share_entry(
            entry_id,
            ShareOptions(method="public_key", recipient_info="alice", recipient_public_key=keys.public_key_pem),
        ).content.decode("utf-8")
    )

    assert first["ephemeral_public_key"] != second["ephemeral_public_key"]
    assert first["data"] != second["data"]


def test_cry_1_password_metadata(sharing_vaults):
    _, source_entries, entry_id, _, _ = sharing_vaults
    package = SharingService(source_entries).share_entry(
        entry_id,
        ShareOptions(method="password", recipient_info="alice", password="share-passphrase"),
    )
    payload = json.loads(package.content.decode("utf-8"))

    assert payload["encryption"]["algorithm"] == "AES-256-GCM"
    assert payload["encryption"]["key_derivation"] == "PBKDF2-SHA256"
    assert payload["encryption"]["iterations"] == 100000
    assert payload["integrity"]["signature_algorithm"] == "HMAC-SHA256"


def test_shr_2_tamper_reject(sharing_vaults):
    _, source_entries, entry_id, _, target_entries = sharing_vaults
    package = SharingService(source_entries).share_entry(
        entry_id,
        ShareOptions(method="password", recipient_info="alice", password="share-passphrase"),
    )
    payload = json.loads(package.content.decode("utf-8"))
    payload["data"] = payload["data"][:-4] + "AAAA"

    with pytest.raises(ShareValidationError):
        SharingService(target_entries).decrypt_share_package(
            json.dumps(payload).encode("utf-8"),
            password="share-passphrase",
        )


def test_shr_3_expiration_range(sharing_vaults):
    _, source_entries, entry_id, _, _ = sharing_vaults

    with pytest.raises(ValueError):
        SharingService(source_entries).share_entry(
            entry_id,
            ShareOptions(
                method="password",
                recipient_info="alice",
                password="share-passphrase",
                expires_in_days=31,
            ),
        )

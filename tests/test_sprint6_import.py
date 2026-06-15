import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from core.import_export import ExportOptions, ImportOptions, ImportValidationError, VaultExporter, VaultImporter
from core.key_manager import KeyManager
from core.vault.entry_manager import EntryManager
from database.db import DatabaseHelper


@pytest.fixture
def source_vault(tmp_path):
    db = DatabaseHelper(str(tmp_path / "source.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")
    entry_manager = EntryManager(db, key_manager)
    entry_manager.create_entry(
        {
            "title": "GitHub",
            "username": "dev@example.com",
            "password": "G1tHub_Pass!",
            "url": "https://github.com",
            "notes": "source notes",
            "category": "Dev",
            "tags": ["git"],
        }
    )
    yield db, entry_manager
    db.close()


@pytest.fixture
def empty_vault(tmp_path):
    db = DatabaseHelper(str(tmp_path / "target.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")
    entry_manager = EntryManager(db, key_manager)
    yield db, entry_manager
    db.close()


def test_imp_1_native_roundtrip(source_vault, empty_vault):
    _, source_entries = source_vault
    target_db, target_entries = empty_vault

    exported = VaultExporter(source_entries).export(
        ExportOptions(
            format="encrypted_json",
            encryption_password="import-passphrase",
            master_password_confirmed=True,
        )
    )

    importer = VaultImporter(target_entries)
    result = importer.import_from_bytes(
        exported.content,
        ImportOptions(mode="merge", encryption_password="import-passphrase"),
    )
    imported_entries = target_entries.get_all_entries(include_decrypted_password=True)
    history = target_db.fetchall("SELECT operation_type, export_format, verification_status FROM import_export_history")

    assert result.imported_count == 1
    assert imported_entries[0]["title"] == "GitHub"
    assert imported_entries[0]["password"] == "G1tHub_Pass!"
    assert history[-1] == ("import", "encrypted_json", "imported")


def test_imp_3_dry_run(source_vault, empty_vault):
    _, source_entries = source_vault
    _, target_entries = empty_vault
    exported = VaultExporter(source_entries).export(
        ExportOptions(
            format="encrypted_json",
            encryption_password="import-passphrase",
            master_password_confirmed=True,
        )
    )

    result = VaultImporter(target_entries).import_from_bytes(
        exported.content,
        ImportOptions(mode="dry-run", encryption_password="import-passphrase"),
    )

    assert result.imported_count == 0
    assert len(result.preview) == 1
    assert target_entries.get_all_entries(include_decrypted_password=True) == []


def test_imp_1_encrypted_csv(source_vault, empty_vault):
    _, source_entries = source_vault
    _, target_entries = empty_vault
    exported = VaultExporter(source_entries).export(
        ExportOptions(
            format="csv",
            encryption_password="csv-passphrase",
            master_password_confirmed=True,
        )
    )

    result = VaultImporter(target_entries).import_from_bytes(
        exported.content,
        ImportOptions(mode="merge", encryption_password="csv-passphrase"),
    )

    imported = target_entries.get_all_entries(include_decrypted_password=True)
    assert result.imported_count == 1
    assert imported[0]["title"] == "GitHub"


def test_imp_1_csv_sanitize(empty_vault):
    _, entry_manager = empty_vault
    content = (
        "title,username,password,url,notes,category,tags\n"
        "Mail,user@example.com,Secret123,https://mail.example,"
        "<script>alert(1)</script> safe,Personal,email,mail\n"
    ).encode("utf-8")

    result = VaultImporter(entry_manager).import_from_bytes(
        content,
        ImportOptions(format="csv", mode="merge"),
    )
    imported = entry_manager.get_all_entries(include_decrypted_password=True)[0]

    assert result.imported_count == 1
    assert "<script" not in imported["notes"].lower()
    assert imported["tags"] == ["email"]


def test_imp_1_bw_lastpass(empty_vault):
    _, entry_manager = empty_vault
    bitwarden = {
        "items": [
            {
                "name": "BW Item",
                "notes": "note",
                "folderId": "Work",
                "login": {
                    "username": "bw-user",
                    "password": "bw-pass",
                    "uris": [{"uri": "https://bw.example"}],
                },
            }
        ]
    }
    importer = VaultImporter(entry_manager)
    bw_result = importer.import_from_bytes(
        json.dumps(bitwarden).encode("utf-8"),
        ImportOptions(mode="merge"),
    )

    lastpass = "url,username,password,extra,name,grouping\nhttps://lp.example,lp-user,lp-pass,lp-note,LP Item,Work\n"
    lp_result = importer.import_from_bytes(
        lastpass.encode("utf-8"),
        ImportOptions(format="lastpass_csv", mode="merge"),
    )

    titles = {entry["title"] for entry in entry_manager.get_all_entries(include_decrypted_password=True)}
    assert bw_result.imported_count == 1
    assert lp_result.imported_count == 1
    assert titles == {"BW Item", "LP Item"}


def test_imp_1_bitwarden_encrypted_json(source_vault, empty_vault):
    _, source_entries = source_vault
    _, target_entries = empty_vault
    exported = VaultExporter(source_entries).export(
        ExportOptions(
            format="bitwarden_encrypted_json",
            encryption_password="bitwarden-passphrase",
            master_password_confirmed=True,
        )
    )

    result = VaultImporter(target_entries).import_from_bytes(
        exported.content,
        ImportOptions(mode="merge", encryption_password="bitwarden-passphrase"),
    )
    imported = target_entries.get_all_entries(include_decrypted_password=True)

    assert result.imported_count == 1
    assert result.format == "bitwarden_encrypted_json"
    assert imported[0]["title"] == "GitHub"
    assert imported[0]["password"] == "G1tHub_Pass!"


def test_imp_2_duplicate_update(empty_vault):
    _, entry_manager = empty_vault
    importer = VaultImporter(entry_manager)
    first = b"title,username,password,url\nGitHub,dev@example.com,old,https://github.com\n"
    second = b"title,username,password,url\nGitHub,dev@example.com,new,https://github.com\n"

    importer.import_from_bytes(first, ImportOptions(format="csv", mode="merge"))
    result = importer.import_from_bytes(
        second,
        ImportOptions(format="csv", mode="merge", duplicate_policy="update"),
    )
    entry = entry_manager.get_all_entries(include_decrypted_password=True)[0]

    assert result.duplicate_count == 1
    assert result.updated_count == 1
    assert entry["password"] == "new"


def test_imp_4_size_limit(empty_vault):
    _, entry_manager = empty_vault
    with pytest.raises(ImportValidationError):
        VaultImporter(entry_manager).import_from_bytes(
            b"x" * 32,
            ImportOptions(format="csv", max_file_size=4),
        )


def test_imp_2_tamper_reject(source_vault, empty_vault):
    _, source_entries = source_vault
    _, target_entries = empty_vault
    exported = VaultExporter(source_entries).export(
        ExportOptions(
            format="encrypted_json",
            encryption_password="import-passphrase",
            master_password_confirmed=True,
        )
    )
    package = json.loads(exported.content.decode("utf-8"))
    package["data"] = package["data"][:-4] + "AAAA"
    tampered = json.dumps(package).encode("utf-8")

    with pytest.raises(ImportValidationError):
        VaultImporter(target_entries).import_from_bytes(
            tampered,
            ImportOptions(mode="merge", encryption_password="import-passphrase"),
        )
    assert target_entries.get_all_entries(include_decrypted_password=True) == []

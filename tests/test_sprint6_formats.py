import csv
import io
import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from core.import_export import ExportOptions, ImportOptions, ShareOptions, VaultExporter, VaultImporter
from core.import_export.formats import CSVFormatHandler, CSVFormatSpec, NativeExportFormatSpec, SharedEntryFormatSpec
from core.import_export.sharing_service import SharingService
from core.key_manager import KeyManager
from core.vault.entry_manager import EntryManager
from database.db import DatabaseHelper


def _build_vault(tmp_path):
    db = DatabaseHelper(str(tmp_path / "formats.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")
    entry_manager = EntryManager(db, key_manager)
    entry_id = entry_manager.create_entry(
        {
            "title": "Mail, Work",
            "username": "dev@example.com",
            "password": "FmtSecret123!",
            "url": "https://mail.example",
            "notes": "line 1\nline 2, with comma",
            "category": "Work",
            "tags": ["email", "work"],
        }
    )
    return db, entry_manager, entry_id


def test_fmt_1_native_contract(tmp_path):
    db, entry_manager, _ = _build_vault(tmp_path)
    try:
        result = VaultExporter(entry_manager).export(
            ExportOptions(
                format="encrypted_json",
                encryption_password="format-passphrase",
                master_password_confirmed=True,
            )
        )
        package = json.loads(result.content.decode("utf-8"))

        assert NativeExportFormatSpec().validate(package) is True
        assert package["format_schema"] == "cryptosafe-native-export-v1"
        assert package["version"] == "1.0"
        assert package["cryptosafe_export"] is True
        assert {"metadata", "encryption", "data", "integrity"} <= set(package)
        assert package["encryption"]["key_derivation"] == "PBKDF2-SHA256"
    finally:
        db.close()


def test_fmt_2_share_contract(tmp_path):
    db, entry_manager, entry_id = _build_vault(tmp_path)
    try:
        shared = SharingService(entry_manager).share_entry(
            entry_id,
            ShareOptions(
                method="password",
                password="share-passphrase",
                recipient_info="recipient@example.com",
                sharer="ivan",
            ),
        )
        package = json.loads(shared.content.decode("utf-8"))

        assert SharedEntryFormatSpec().validate(package) is True
        assert package["format_schema"] == "cryptosafe-shared-entry-v1"
        assert package["cryptosafe_share"] is True
        assert package["permissions"]["read"] is True
        assert package["encryption"]["algorithm"] == "AES-256-GCM"
        assert "FmtSecret123!" not in shared.content.decode("utf-8")
    finally:
        db.close()


def test_fmt_3_csv_metadata():
    handler = CSVFormatHandler()
    content = handler.serialize(
        [
            {
                "title": "Mail, Work",
                "username": "dev@example.com",
                "password": "FmtSecret123!",
                "url": "https://mail.example",
                "notes": "line 1\nline 2, with comma",
                "category": "Work",
                "tags": ["email", "work"],
            }
        ],
        metadata={"source_application": "CryptoSafe Manager"},
    )
    text = content.decode("utf-8-sig")
    clean_text = CSVFormatSpec().strip_metadata_header(text)
    rows = list(csv.DictReader(io.StringIO(clean_text)))

    assert text.startswith("# cryptosafe:")
    assert CSVFormatSpec().validate_header(rows[0].keys()) is True
    assert rows[0]["title"] == "Mail, Work"
    assert rows[0]["notes"] == "line 1\nline 2, with comma"
    assert rows[0]["tags"] == "email,work"


def test_fmt_3_csv_header_import():
    content = (
        '# cryptosafe: {"schema":"cryptosafe-csv-v1","version":"1.0"}\n'
        "title,username,password,url,notes,category,tags\n"
        "Mail,user@example.com,Secret123,https://mail.example,note,Personal,email\n"
    ).encode("utf-8")

    result = VaultImporter().import_from_bytes(content, ImportOptions(format="csv"))

    assert result.imported_count == 0
    assert result.preview[0]["title"] == "Mail"
    assert result.preview[0]["tags"] == ["email"]

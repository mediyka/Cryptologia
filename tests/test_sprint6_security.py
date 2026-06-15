import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from core.import_export import ExportOptions, ImportOptions, ShareOptions, SharingService, VaultExporter, VaultImporter
from core.key_manager import KeyManager
from core.vault.entry_manager import EntryManager
from database.db import DatabaseHelper


def _vault(tmp_path, name="security"):
    db = DatabaseHelper(str(tmp_path / f"{name}.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")
    entry_manager = EntryManager(db, key_manager)
    entry_id = entry_manager.create_entry(
        {
            "title": "Security Entry",
            "username": "sec@example.com",
            "password": "PlaintextShouldNotLeak!",
            "url": "https://security.example",
            "notes": "sensitive notes",
            "category": "Security",
            "tags": ["sec"],
        }
    )
    return db, entry_manager, entry_id


def test_sec_1_encrypted_default(tmp_path):
    db, entry_manager, _ = _vault(tmp_path)
    try:
        exported = VaultExporter(entry_manager).export(
            ExportOptions(
                format="csv",
                encryption_password="security-passphrase",
                master_password_confirmed=True,
            )
        )

        assert exported.encrypted is True
        assert b"PlaintextShouldNotLeak!" not in exported.content
        assert json.loads(exported.content.decode("utf-8"))["cryptosafe_export"] is True

        try:
            VaultExporter(entry_manager).export(
                ExportOptions(format="csv", encrypt=False, master_password_confirmed=True)
            )
            assert False, "plaintext export without allow_plaintext must fail"
        except ValueError:
            pass
    finally:
        db.close()


def test_sec_2_validate_sanitize(tmp_path):
    db, entry_manager, _ = _vault(tmp_path)
    try:
        content = json.dumps(
            {
                "entries": [
                    {
                        "title": "Safe",
                        "username": "user",
                        "password": "secret",
                        "url": "https://safe.example",
                        "notes": "<script>alert(1)</script> safe",
                    },
                    {
                        "title": ["invalid"],
                        "password": "secret",
                    },
                ]
            }
        ).encode("utf-8")

        result = VaultImporter(entry_manager).import_from_bytes(content, ImportOptions(format="json", mode="merge"))
        imported = [entry for entry in entry_manager.get_all_entries(include_decrypted_password=True) if entry["title"] == "Safe"]

        assert result.imported_count == 1
        assert result.rejected_count == 1
        assert "[removed]" in imported[0]["notes"]
        assert "<script" not in imported[0]["notes"].lower()
    finally:
        db.close()


def test_sec_3_key_separation(tmp_path):
    db, entry_manager, entry_id = _vault(tmp_path)
    try:
        exported = VaultExporter(entry_manager).export(
            ExportOptions(
                format="encrypted_json",
                encryption_password="security-passphrase",
                master_password_confirmed=True,
            )
        )
        share = SharingService(entry_manager).share_entry(
            entry_id,
            ShareOptions(method="password", recipient_info="alice", password="share-passphrase"),
        )
        export_package = json.loads(exported.content.decode("utf-8"))
        share_package = json.loads(share.content.decode("utf-8"))

        assert "master vault key is not reused" in export_package["encryption"]["key_separation"]
        assert "master vault key is not reused" in share_package["encryption"]["key_separation"]
        assert export_package["encryption"]["salt"] != share_package["encryption"]["salt"]
        assert export_package["encryption"]["nonce"] != share_package["encryption"]["nonce"]
    finally:
        db.close()


def test_sec_4_wipe_buffers():
    buffer = bytearray(b"temporary-secret-key")

    assert VaultExporter._clear_bytearray(buffer) is True
    assert bytes(buffer) == b"\x00" * len(buffer)


def test_sec_5_malware_scan():
    content = (
        "title,username,password,url,notes,category,tags\n"
        "Malware,user,secret,javascript:alert(1),<iframe src=x></iframe>,Security,onload=bad\n"
    ).encode("utf-8")

    result = VaultImporter().import_from_bytes(content, ImportOptions(format="csv"))
    entry = result.preview[0]

    assert result.rejected_count == 0
    assert any("suspicious content" in warning for warning in result.warnings)
    assert "javascript:" not in entry["url"].lower()
    assert "<iframe" not in entry["notes"].lower()
    assert all("onload" not in tag.lower() for tag in entry["tags"])

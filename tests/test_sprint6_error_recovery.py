import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from core.import_export import ExportOptions, ImportOptions, ImportValidationError, VaultExporter, VaultImporter
from core.key_manager import KeyManager
from core.vault.entry_manager import EntryManager
from database.db import DatabaseHelper


def _vault(tmp_path, name):
    db = DatabaseHelper(str(tmp_path / f"{name}.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")
    return db, EntryManager(db, key_manager)


def _csv(entries):
    lines = ["title,username,password,url"]
    for title, username, password, url in entries:
        lines.append(f"{title},{username},{password},{url}")
    return ("\n".join(lines) + "\n").encode("utf-8")


class FailingEntryManager:
    def __init__(self, wrapped, fail_after):
        self.wrapped = wrapped
        self.db = wrapped.db
        self.key_manager = wrapped.key_manager
        self.created = 0
        self.fail_after = fail_after

    def get_all_entries(self, *args, **kwargs):
        return self.wrapped.get_all_entries(*args, **kwargs)

    def create_entry(self, entry):
        if self.created >= self.fail_after:
            raise RuntimeError("simulated import interruption")
        self.created += 1
        return self.wrapped.create_entry(entry)

    def update_entry(self, *args, **kwargs):
        return self.wrapped.update_entry(*args, **kwargs)


def test_err_1_corrupted_report(tmp_path):
    db, entry_manager = _vault(tmp_path, "err-corrupted")
    importer = VaultImporter(entry_manager)

    try:
        with pytest.raises(ImportValidationError):
            importer.import_from_bytes(b'{"entries": [', ImportOptions(format="json", mode="merge"))

        report = importer.last_error_report
        assert report is not None
        assert report.error_type == "ImportValidationError"
        assert report.detected_format == "json"
        assert any("dry-run" in option or "fix" in option.lower() for option in report.recovery_options)
    finally:
        db.close()


def test_err_2_resume_checkpoint(tmp_path):
    db, entry_manager = _vault(tmp_path, "err-resume")
    checkpoint = tmp_path / "resume.checkpoint.json"
    content = _csv(
        [
            ("First", "one@example.com", "one-secret", "https://one.example"),
            ("Second", "two@example.com", "two-secret", "https://two.example"),
            ("Third", "three@example.com", "three-secret", "https://three.example"),
        ]
    )
    failing = FailingEntryManager(entry_manager, fail_after=1)
    importer = VaultImporter(failing)

    try:
        with pytest.raises(RuntimeError):
            importer.import_from_bytes(
                content,
                ImportOptions(format="csv", mode="merge", checkpoint_path=str(checkpoint)),
            )

        checkpoint_text = checkpoint.read_text(encoding="utf-8")
        assert "one-secret" not in checkpoint_text
        assert importer.last_error_report.partial_import_available is True

        result = VaultImporter(entry_manager).import_from_bytes(
            content,
            ImportOptions(
                format="csv",
                mode="merge",
                checkpoint_path=str(checkpoint),
                resume_from_checkpoint=True,
            ),
        )
        titles = {entry["title"] for entry in entry_manager.get_all_entries(include_decrypted_password=True)}

        assert result.imported_count == 2
        assert result.skipped_count == 1
        assert titles == {"First", "Second", "Third"}
    finally:
        db.close()


def test_err_3_manual_format(tmp_path):
    db, entry_manager = _vault(tmp_path, "err-format")
    importer = VaultImporter(entry_manager)

    try:
        with pytest.raises(ImportValidationError):
            importer.import_from_bytes(b"not a supported vault export", ImportOptions(mode="merge"))

        assert importer.last_error_report.detected_format == "unknown"
        assert any("format manually" in option for option in importer.last_error_report.recovery_options)
    finally:
        db.close()


def test_err_4_decrypt_abort(tmp_path):
    source_db, source_entries = _vault(tmp_path, "err-source")
    target_db, target_entries = _vault(tmp_path, "err-target")
    source_entries.create_entry(
        {
            "title": "Encrypted",
            "username": "enc@example.com",
            "password": "enc-secret",
            "url": "https://enc.example",
        }
    )

    try:
        exported = VaultExporter(source_entries).export(
            ExportOptions(
                format="encrypted_json",
                encryption_password="correct-passphrase",
                master_password_confirmed=True,
            )
        )
        importer = VaultImporter(target_entries)

        with pytest.raises(Exception):
            importer.import_from_bytes(
                exported.content,
                ImportOptions(mode="merge", encryption_password="wrong-passphrase"),
            )

        assert target_entries.get_all_entries(include_decrypted_password=True) == []
        assert importer.last_error_report is not None
        assert any("password" in option.lower() or "private key" in option.lower() for option in importer.last_error_report.recovery_options)
    finally:
        source_db.close()
        target_db.close()


def test_err_replace_import_rolls_back_on_failure(tmp_path):
    db, entry_manager = _vault(tmp_path, "err-replace-rollback")
    entry_manager.create_entry(
        {
            "title": "Existing",
            "username": "old@example.com",
            "password": "old-secret",
            "url": "https://old.example",
        }
    )
    content = _csv(
        [
            ("First", "one@example.com", "one-secret", "https://one.example"),
            ("Second", "two@example.com", "two-secret", "https://two.example"),
        ]
    )
    failing = FailingEntryManager(entry_manager, fail_after=1)

    try:
        with pytest.raises(RuntimeError):
            VaultImporter(failing).import_from_bytes(
                content,
                ImportOptions(format="csv", mode="replace"),
            )

        entries = entry_manager.get_all_entries(include_decrypted_password=True)
        assert len(entries) == 1
        assert entries[0]["title"] == "Existing"
        assert entries[0]["password"] == "old-secret"
    finally:
        db.close()

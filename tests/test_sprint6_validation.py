import base64
import json
import os
import sys
import time
import tracemalloc

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from core.import_export import (
    ExportOptions,
    ImportOptions,
    KeyExchangeService,
    QRCodeValidationError,
    ShareOptions,
    ShareValidationError,
    SharingService,
    VaultExporter,
    VaultImporter,
)
from core.events import event_bus
from core.key_manager import KeyManager
from core.vault.entry_manager import EntryManager
from database.db import DatabaseHelper


def _create_vault(tmp_path, name):
    db = DatabaseHelper(str(tmp_path / f"{name}.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")
    return db, EntryManager(db, key_manager)


def _seed_entries(entry_manager, count=3):
    ids = []
    for index in range(count):
        ids.append(
            entry_manager.create_entry(
                {
                    "title": f"Service {index}",
                    "username": f"user{index}@example.com",
                    "password": f"Sprint6Pass!{index}",
                    "url": f"https://service{index}.example",
                    "notes": f"notes {index}",
                    "category": "Validation",
                    "tags": ["sprint6", f"entry-{index}"],
                }
            )
        )
    return ids


def _entry_map(entry_manager):
    return {
        entry["title"]: {
            "username": entry.get("username"),
            "password": entry.get("password"),
            "url": entry.get("url"),
        }
        for entry in entry_manager.get_all_entries(include_decrypted_password=True)
    }


def test_test_1_roundtrip_all(tmp_path):
    source_db, source_entries = _create_vault(tmp_path, "roundtrip-source")
    _seed_entries(source_entries)
    expected = _entry_map(source_entries)

    formats = ["encrypted_json", "csv", "bitwarden_json", "lastpass_csv", "lastpass_json", "password_manager_json"]
    try:
        for export_format in formats:
            target_db, target_entries = _create_vault(tmp_path, f"roundtrip-{export_format}")
            try:
                exported = VaultExporter(source_entries).export(
                    ExportOptions(
                        format=export_format,
                        encryption_password=f"{export_format}-passphrase",
                        master_password_confirmed=True,
                    )
                )
                result = VaultImporter(target_entries).import_from_bytes(
                    exported.content,
                    ImportOptions(mode="merge", encryption_password=f"{export_format}-passphrase"),
                )

                assert result.imported_count == 3
                assert _entry_map(target_entries) == expected
            finally:
                target_db.close()
    finally:
        source_db.close()


def test_test_2_interop(tmp_path):
    db, entry_manager = _create_vault(tmp_path, "interop")
    try:
        bitwarden = {
            "encrypted": False,
            "items": [
                {
                    "type": 1,
                    "name": "Bitwarden Login",
                    "notes": "bw note",
                    "folderId": "Work",
                    "login": {
                        "username": "bw@example.com",
                        "password": "bw-secret",
                        "uris": [{"uri": "https://bw.example"}],
                    },
                }
            ],
        }
        lastpass = (
            "url,username,password,extra,name,grouping\n"
            "https://lp.example,lp@example.com,lp-secret,lp note,LastPass Login,Work\n"
        )

        importer = VaultImporter(entry_manager)
        importer.import_from_bytes(json.dumps(bitwarden).encode("utf-8"), ImportOptions(format="bitwarden_json", mode="merge"))
        importer.import_from_bytes(lastpass.encode("utf-8"), ImportOptions(format="lastpass_csv", mode="merge"))

        bitwarden_export = VaultExporter(entry_manager).export(
            ExportOptions(
                format="bitwarden_json",
                encrypt=False,
                allow_plaintext=True,
                master_password_confirmed=True,
            )
        )
        lastpass_export = VaultExporter(entry_manager).export(
            ExportOptions(
                format="lastpass_csv",
                encrypt=False,
                allow_plaintext=True,
                master_password_confirmed=True,
            )
        )
        bw_payload = json.loads(bitwarden_export.content.decode("utf-8"))
        lp_payload = lastpass_export.content.decode("utf-8-sig")

        assert {entry["title"] for entry in entry_manager.get_all_entries(include_decrypted_password=True)} == {
            "Bitwarden Login",
            "LastPass Login",
        }
        assert bw_payload["items"][0]["login"]["password"]
        assert lp_payload.splitlines()[0] == "url,username,password,extra,name,grouping"
        assert "lp-secret" in lp_payload
    finally:
        db.close()


def test_test_3_share_security(tmp_path):
    source_db, source_entries = _create_vault(tmp_path, "share-source")
    target_db, target_entries = _create_vault(tmp_path, "share-target")
    entry_id = _seed_entries(source_entries, count=1)[0]
    keys = KeyExchangeService()
    rsa_pair = keys.generate_rsa_key_pair()
    ecc_pair = keys.generate_ecc_key_pair()

    cases = [
        (ShareOptions(method="password", recipient_info="alice", password="share-passphrase"), {"password": "share-passphrase"}),
        (ShareOptions(method="public_key", recipient_info="rsa", recipient_public_key=rsa_pair.public_key_pem), {"private_key_pem": rsa_pair.private_key_pem}),
        (ShareOptions(method="public_key", recipient_info="ecc", recipient_public_key=ecc_pair.public_key_pem), {"private_key_pem": ecc_pair.private_key_pem}),
    ]
    try:
        for options, decrypt_kwargs in cases:
            package = SharingService(source_entries).share_entry(entry_id, options)
            decoded = SharingService(target_entries).decrypt_share_package(package.content, **decrypt_kwargs)
            tampered = json.loads(package.content.decode("utf-8"))
            tampered["data"] = tampered["data"][:-4] + "AAAA"

            assert decoded.entry["password"] == "Sprint6Pass!0"
            with pytest.raises(ShareValidationError):
                SharingService(target_entries).decrypt_share_package(json.dumps(tampered).encode("utf-8"), **decrypt_kwargs)
    finally:
        source_db.close()
        target_db.close()


def test_test_4_qr_1kb():
    service = KeyExchangeService()
    payload_bytes = os.urandom(1024)
    payload = service.create_encrypted_entry_payload(payload_bytes)

    started = time.perf_counter()
    bundle = service.generate_qr_codes(payload, chunk_size=512, render_svg=False)
    elapsed = time.perf_counter() - started
    decoded = service.decode_qr_chunks([chunk.encoded_text for chunk in bundle.chunks])
    tampered = json.loads(bundle.chunks[0].encoded_text)
    tampered["data"] = tampered["data"][:-4] + "AAAA"

    assert elapsed < 0.1
    assert base64.b64decode(decoded["data"]) == payload_bytes
    assert decoded["data_sha256"] == payload["data_sha256"]
    with pytest.raises(QRCodeValidationError):
        service.decode_qr_chunks([json.dumps(tampered), *[chunk.encoded_text for chunk in bundle.chunks[1:]]], allow_replay=True)


def test_test_5_bulk_perf(tmp_path):
    subscribers = {name: callbacks[:] for name, callbacks in event_bus._subscribers.items()}
    # В performance-сценарии изолируем глобальную шину, чтобы замер не включал накопленные audit-подписчики.
    event_bus._subscribers = {}
    source_db, source_entries = _create_vault(tmp_path, "perf-source")
    target_db, target_entries = _create_vault(tmp_path, "perf-target")
    _seed_entries(source_entries, count=1000)

    try:
        tracemalloc.start()
        export_started = time.perf_counter()
        exported = VaultExporter(source_entries).export(
            ExportOptions(
                format="encrypted_json",
                encryption_password="performance-passphrase",
                master_password_confirmed=True,
            )
        )
        export_elapsed = time.perf_counter() - export_started
        _, export_peak = tracemalloc.get_traced_memory()

        tracemalloc.reset_peak()
        import_started = time.perf_counter()
        result = VaultImporter(target_entries).import_from_bytes(
            exported.content,
            ImportOptions(mode="merge", encryption_password="performance-passphrase"),
        )
        import_elapsed = time.perf_counter() - import_started
        _, import_peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        assert result.imported_count == 1000
        assert export_elapsed < 5.0
        assert import_elapsed < 10.0
        assert export_peak > 0
        assert import_peak > 0
    finally:
        if tracemalloc.is_tracing():
            tracemalloc.stop()
        event_bus._subscribers = subscribers
        source_db.close()
        target_db.close()

import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from core.events import event_bus
from core.import_export import ExportOptions, ImportOptions, KeyExchangeService, VaultExporter, VaultImporter
from core.key_manager import KeyManager
from core.vault.entry_manager import EntryManager
from database.db import DatabaseHelper


def _vault(tmp_path, name):
    db = DatabaseHelper(str(tmp_path / f"{name}.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")
    return db, EntryManager(db, key_manager)


def _seed(entry_manager, count):
    for index in range(count):
        entry_manager.create_entry(
            {
                "title": f"Perf {index}",
                "username": f"perf{index}@example.com",
                "password": f"PerfSecret!{index}",
                "url": f"https://perf{index}.example",
                "notes": "performance test",
                "category": "Perf",
                "tags": ["perf"],
            }
        )


def test_perf_1_2_4_bulk_io(tmp_path):
    subscribers = {name: callbacks[:] for name, callbacks in event_bus._subscribers.items()}
    event_bus._subscribers = {}
    source_db, source_entries = _vault(tmp_path, "perf13-source")
    target_db, target_entries = _vault(tmp_path, "perf13-target")
    _seed(source_entries, 1000)

    try:
        started = time.perf_counter()
        exported = VaultExporter(source_entries).export(
            ExportOptions(
                format="encrypted_json",
                encryption_password="perf-passphrase",
                master_password_confirmed=True,
            )
        )
        export_elapsed = time.perf_counter() - started

        started = time.perf_counter()
        imported = VaultImporter(target_entries).import_from_bytes(
            exported.content,
            ImportOptions(mode="merge", encryption_password="perf-passphrase"),
        )
        import_elapsed = time.perf_counter() - started

        assert export_elapsed < 5.0
        assert import_elapsed < 10.0
        assert imported.imported_count == 1000
        assert exported.metadata["estimated_peak_bytes"] <= exported.metadata["memory_budget_bytes"]
        assert imported.estimated_peak_bytes <= imported.memory_budget_bytes
    finally:
        event_bus._subscribers = subscribers
        source_db.close()
        target_db.close()


def test_perf_3_qr_1kb():
    service = KeyExchangeService()
    payload = service.create_encrypted_entry_payload(os.urandom(1024))

    started = time.perf_counter()
    bundle = service.generate_qr_codes(payload, chunk_size=512, render_svg=False)
    elapsed = time.perf_counter() - started

    assert elapsed < 0.1
    assert bundle.chunks

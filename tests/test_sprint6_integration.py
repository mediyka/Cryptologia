import json
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from core.audit import AuditLogger
from core.clipboard.clipboard_service import ClipboardService
from core.clipboard.platform_adapter import InMemoryClipboardAdapter
from core.events import EventBus
from core.import_export import ExportOptions, ImportOptions, KeyExchangeService, ShareOptions, SharingService, VaultExporter, VaultImporter
from core.key_manager import KeyManager
from core.vault.entry_manager import EntryManager
from database.db import DatabaseHelper


def _vault(tmp_path, name):
    db = DatabaseHelper(str(tmp_path / f"{name}.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")
    return db, key_manager, EntryManager(db, key_manager)


def _create_entry(entry_manager, title, tag):
    return entry_manager.create_entry(
        {
            "title": title,
            "username": f"{tag}@example.com",
            "password": f"{tag}-secret",
            "url": f"https://{tag}.example",
            "notes": f"{tag} notes",
            "category": "Integration",
            "tags": [tag],
        }
    )


def _audit_events(db):
    rows = db.fetchall("SELECT event_type, entry_data, details FROM audit_log ORDER BY sequence_number")
    events = []
    for event_type, entry_data, details in rows:
        if entry_data is None:
            continue
        entry_bytes = entry_data if isinstance(entry_data, bytes) else str(entry_data).encode("utf-8")
        entry = json.loads(entry_bytes.decode("utf-8"))
        events.append((event_type, entry.get("source"), json.loads(details or "{}")))
    return events


class _UnlockedState:
    is_locked = False


def test_int_1_query_export(tmp_path):
    source_db, _, source_entries = _vault(tmp_path, "int-vault-source")
    target_db, _, target_entries = _vault(tmp_path, "int-vault-target")
    _create_entry(source_entries, "Alpha Portal", "alpha")
    _create_entry(source_entries, "Beta Portal", "beta")

    try:
        exported = VaultExporter(source_entries).export_by_query(
            'title:"Alpha"',
            ExportOptions(
                format="encrypted_json",
                encryption_password="query-passphrase",
                master_password_confirmed=True,
            ),
        )
        result = VaultImporter(target_entries).import_from_bytes(
            exported.content,
            ImportOptions(mode="merge", encryption_password="query-passphrase"),
        )
        imported_titles = {entry["title"] for entry in target_entries.get_all_entries(include_decrypted_password=True)}

        assert result.imported_count == 1
        assert imported_titles == {"Alpha Portal"}
    finally:
        source_db.close()
        target_db.close()


def test_int_2_audit_events(tmp_path):
    db, key_manager, entry_manager = _vault(tmp_path, "int-audit")
    entry_id = _create_entry(entry_manager, "Audit Portal", "audit")
    bus = EventBus()
    logger = AuditLogger(db, key_manager=key_manager, bus=bus)

    try:
        exported = VaultExporter(entry_manager, bus=bus).export(
            ExportOptions(
                format="encrypted_json",
                encryption_password="audit-passphrase",
                master_password_confirmed=True,
            )
        )
        VaultImporter(entry_manager, bus=bus).import_from_bytes(
            exported.content,
            ImportOptions(mode="dry-run", encryption_password="audit-passphrase"),
        )
        SharingService(entry_manager, bus=bus).share_entry(
            entry_id,
            ShareOptions(method="password", recipient_info="recipient@example.com", password="share-passphrase"),
        )
        logger.flush_async()
        events = _audit_events(db)

        assert any(event_type == "VaultExportCreated" and source == "import_export" for event_type, source, _ in events)
        assert any(event_type == "VaultImportCompleted" and source == "import_export" for event_type, source, _ in events)
        assert any(
            event_type == "EntryShareCreated"
            and source == "sharing"
            and details.get("encryption_method") == "password"
            for event_type, source, details in events
        )
    finally:
        logger.shutdown()
        db.close()


def test_int_3_clipboard_qr(tmp_path):
    db, _, entry_manager = _vault(tmp_path, "int-clipboard")
    entry_id = _create_entry(entry_manager, "Clipboard Portal", "clip")
    bus = EventBus()
    clipboard = ClipboardService(
        platform_adapter=InMemoryClipboardAdapter(),
        event_system=bus,
        config={"clipboard_timeout": 5},
        state=_UnlockedState(),
        register_exit_handler=False,
    )

    try:
        sharing = SharingService(entry_manager, bus=bus)
        package = sharing.share_entry(
            entry_id,
            ShareOptions(method="password", recipient_info="recipient@example.com", password="share-passphrase"),
        )
        share_link = sharing.build_share_link(package.shared_id, "https://share.example", package.expires_at)

        assert sharing.copy_share_link_to_clipboard(clipboard, share_link, shared_id=package.shared_id) is True
        assert clipboard.platform.get_clipboard_content() == share_link
        assert clipboard.get_clipboard_status().active is True

        key_exchange = KeyExchangeService(bus=bus)
        payload = key_exchange.create_share_link_payload(share_link)
        bundle = key_exchange.generate_qr_codes(payload, chunk_size=256, render_svg=False)
        clipboard.copy_text("\n".join(chunk.encoded_text for chunk in bundle.chunks), source_entry_id=package.shared_id)
        decoded = key_exchange.decode_qr_chunks_from_clipboard(clipboard)

        assert decoded["type"] == "share_link"
        assert decoded["url"] == share_link
    finally:
        clipboard.shutdown()
        db.close()


def test_int_4_future_link(tmp_path):
    db, _, entry_manager = _vault(tmp_path, "int-future")
    entry_id = _create_entry(entry_manager, "Future Portal", "future")

    try:
        sharing = SharingService(entry_manager)
        package = sharing.share_entry(
            entry_id,
            ShareOptions(method="password", recipient_info="recipient@example.com", password="share-passphrase"),
        )
        share_link = sharing.build_share_link(package.shared_id, "https://sync.example", package.expires_at)
        qr_payload = KeyExchangeService().create_share_link_payload(share_link)

        assert share_link.startswith("https://sync.example/share/")
        assert package.shared_id in share_link
        assert qr_payload["type"] == "share_link"
        assert qr_payload["url_sha256"]
    finally:
        db.close()

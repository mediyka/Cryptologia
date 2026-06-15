import base64
import json
import os
import random
import sys
import inspect
import time
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.audit import AuditLogger, AuditLogExporter, AuditLogImportVerifier, AuditLogSigner, AuditLogVerifier
from core.audit.log_formatters import AuditLogFormatter
from core.audit.log_exporter import EXPORT_AAD, EXPORT_KEY_PURPOSE
from core.events import EventBus
from core.key_manager import KeyManager
from core.vault.entry_manager import EntryManager
from database.db import DatabaseHelper
from gui.widgets.audit_log_viewer import AuditLogViewer


def test_cry_2_audit_key(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-key.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    encryption_key = key_manager.storage.get_key()
    audit_key = key_manager.derive_audit_signing_key()
    repeat_audit_key = key_manager.derive_key("audit-signing", 32)

    assert audit_key == repeat_audit_key
    assert audit_key != encryption_key

    signer = AuditLogSigner(key_manager=key_manager)
    assert signer.algorithm in {"Ed25519", "HMAC-SHA256"}
    assert signer._seed_cache.get_key() == audit_key

    db.close()


def test_cry_3_signed_entry(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-entry.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    signer = AuditLogSigner(key_manager=key_manager)
    logger = AuditLogger(db, signer=signer, bus=EventBus())
    sequence = logger.log_event(
        event_type="EntryCreated",
        severity="INFO",
        source="vault",
        entry_id="entry-cry-3",
        details={"title": "Example", "password": "must-not-log"},
    )

    row = db.fetchone(
        """
        SELECT sequence_number, previous_hash, entry_data, entry_hash, signature
        FROM audit_log
        WHERE sequence_number = ?
        """,
        (sequence,),
    )

    assert row is not None
    sequence_number, previous_hash, entry_data, entry_hash, signature = row
    entry_bytes = entry_data if isinstance(entry_data, bytes) else str(entry_data).encode("utf-8")
    entry = json.loads(entry_bytes.decode("utf-8"))

    assert sequence_number == sequence
    assert entry["sequence_number"] == sequence
    assert entry["previous_hash"] == previous_hash
    assert entry["details"]["password"] == "[REDACTED]"
    assert entry["signature_algorithm"] == signer.algorithm
    assert entry_hash
    assert signature

    verification = AuditLogVerifier(db, signer).verify_integrity()
    assert verification["verified"] is True
    assert verification["valid_entries"] == 1

    db.close()


def test_log_1_events():
    catalog = AuditLogger.EVENT_CATALOG

    expected_events = {
        "LoginSucceeded": "auth",
        "LoginFailed": "auth",
        "PasswordChanged": "auth",
        "EntryCreated": "vault",
        "EntryRead": "vault",
        "EntryUpdated": "vault",
        "EntryDeleted": "vault",
        "ClipboardCopied": "clipboard",
        "ClipboardCleared": "clipboard",
        "ClipboardAutoCleared": "clipboard",
        "ApplicationStarted": "system",
        "ApplicationShutdown": "system",
        "VaultLocked": "system",
        "SuspiciousActivity": "security",
        "FailedAuthAttempt": "auth",
        "ConfigChanged": "config",
        "SettingChanged": "config",
    }

    for event_name, source in expected_events.items():
        assert event_name in catalog
        assert catalog[event_name][1] == source


def test_log_2_structure(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-structure.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    logger = AuditLogger(db, key_manager=key_manager, bus=EventBus())
    sequence = logger.log_event(
        event_type="LoginFailed",
        severity="WARN",
        source="auth",
        user_id="default_user",
        details={"reason": "bad_password"},
    )

    row = db.fetchone("SELECT entry_data FROM audit_log WHERE sequence_number = ?", (sequence,))
    entry_data = row[0]
    entry_bytes = entry_data if isinstance(entry_data, bytes) else str(entry_data).encode("utf-8")
    entry = json.loads(entry_bytes.decode("utf-8"))

    for key in ("timestamp", "event_type", "severity", "user_id", "source", "details", "entry_id"):
        assert key in entry

    assert entry["timestamp"].endswith("+00:00")
    assert entry["event_type"] == "LoginFailed"
    assert entry["severity"] == "WARN"
    assert entry["user_id"] == "default_user"
    assert entry["source"] == "auth"
    assert entry["details"] == {"reason": "bad_password"}
    assert entry["entry_id"] is None

    db.close()


def test_log_3_redaction(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-redaction.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    logger = AuditLogger(db, key_manager=key_manager, bus=EventBus())
    sequence = logger.log_event(
        event_type="EntryCreated",
        source="vault",
        details={
            "password": "plain-password",
            "encryption_key": "raw-key",
            "profile": {"totp_secret": "totp-plain"},
        },
    )

    row = db.fetchone("SELECT entry_data, details FROM audit_log WHERE sequence_number = ?", (sequence,))
    entry_data, details_json = row
    entry_bytes = entry_data if isinstance(entry_data, bytes) else str(entry_data).encode("utf-8")
    entry_text = entry_bytes.decode("utf-8")
    details = json.loads(details_json)

    assert "plain-password" not in entry_text
    assert "raw-key" not in entry_text
    assert "totp-plain" not in entry_text
    assert details["password"] == "[REDACTED]"
    assert details["encryption_key"] == "[REDACTED]"
    assert details["profile"]["totp_secret"] == "[REDACTED]"

    db.close()


def test_db_1_schema(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-schema.db"))

    columns = {
        row[1]: row[2]
        for row in db.fetchall("PRAGMA table_info(audit_log)")
    }
    key_columns = {
        row[1]: row[2]
        for row in db.fetchall("PRAGMA table_info(audit_keys)")
    }

    for column in ("sequence_number", "previous_hash", "entry_data", "signature", "event_type"):
        assert column in columns
    assert columns["entry_data"].upper() == "BLOB"
    assert columns["signature"].upper() == "TEXT"
    assert "public_key" in key_columns

    db.close()


def test_db_3_indexes(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-indexes.db"))

    indexes = {
        row[1]
        for row in db.fetchall("PRAGMA index_list(audit_log)")
    }

    assert "idx_audit_timestamp" in indexes
    assert "idx_audit_event_type" in indexes
    assert "idx_audit_sequence" in indexes

    db.close()


def test_db_4_rotation(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-rotation.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    logger = AuditLogger(db, key_manager=key_manager, bus=EventBus())
    db.set_audit_rotation_policy(max_entries=2, max_age_days=365, auto_archive=True)

    for index in range(4):
        logger.log_event("EntryCreated", source="vault", details={"index": index})

    archived = db.rotate_audit_logs()
    active_count = db.fetchone("SELECT COUNT(*) FROM audit_log")[0]
    archive_count = db.fetchone("SELECT COUNT(*) FROM audit_log_archive")[0]

    assert archived == 2
    assert active_count == 2
    assert archive_count == 2

    db.close()


def test_ver_1_startup(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-startup-verify.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    signer = AuditLogSigner(key_manager=key_manager)
    logger = AuditLogger(db, signer=signer, bus=EventBus())
    sequence = logger.log_event("EntryCreated", source="vault", details={"title": "Original"})

    db.unsafe_audit_execute("UPDATE audit_log SET entry_hash = ? WHERE sequence_number = ?", ("bad-hash", sequence))

    result = AuditLogVerifier(db, signer, bus=EventBus()).verify_on_startup()

    assert result["verified"] is False
    assert result["invalid_entries"][0]["sequence"] == sequence

    db.close()


def test_ver_2_periodic(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-periodic-verify.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    signer = AuditLogSigner(key_manager=key_manager)
    logger = AuditLogger(db, signer=signer, bus=EventBus())
    for index in range(5):
        logger.log_event("EntryCreated", source="vault", details={"index": index})

    verifier = AuditLogVerifier(db, signer, bus=EventBus())
    result = verifier.verify_periodic(sample_size=2)

    assert result["verified"] is True
    assert result["total_entries"] == 2
    assert verifier.get_status()["verified"] is True

    db.close()


def test_ver_3_manual(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-manual-verify.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    signer = AuditLogSigner(key_manager=key_manager)
    logger = AuditLogger(db, signer=signer, bus=EventBus())
    logger.log_event("EntryCreated", source="vault", details={"title": "Report"})

    report_path = tmp_path / "verification-report.json"
    report = AuditLogVerifier(db, signer, bus=EventBus()).verify_manual(export_path=str(report_path))
    exported = json.loads(report_path.read_text(encoding="utf-8"))

    assert report["report_type"] == "audit-integrity-verification"
    assert report["verified"] is True
    assert exported["verified"] is True
    assert exported["valid_entries"] == 1

    db.close()


def test_ver_4_tamper_event(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-tamper-event.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    bus = EventBus()
    events = []
    bus.subscribe("TamperDetected", lambda event: events.append(event.data))

    signer = AuditLogSigner(key_manager=key_manager)
    logger = AuditLogger(db, signer=signer, bus=bus)
    sequence = logger.log_event("EntryCreated", source="vault", details={"title": "Tamper"})

    db.unsafe_audit_execute("UPDATE audit_log SET signature = ? WHERE sequence_number = ?", ("00", sequence))
    result = AuditLogVerifier(db, signer, bus=bus).verify_integrity()
    security_count = db.fetchone("SELECT COUNT(*) FROM audit_security_events")[0]

    assert result["verified"] is False
    assert events
    assert events[-1]["reason"] == "audit_integrity_failed"
    assert security_count == 1

    db.close()


def test_gui_1_viewer():
    source = inspect.getsource(AuditLogViewer)

    assert AuditLogViewer.PAGE_SIZE == 50
    assert "ttk.Treeview" in source
    assert "sort_by" in source
    assert "event_type_var" in source
    assert "severity_var" in source
    assert "date_from_var" in source
    assert "date_to_var" in source
    assert "user_var" in source
    assert "search_var" in source
    assert "prev_page" in source
    assert "next_page" in source


def test_gui_2_details():
    source = inspect.getsource(AuditLogViewer)

    assert "details_text" in source
    assert "json.dumps" in source
    assert "verification_var" in source
    assert "Подпись:" in source
    assert "chain_var" in source
    assert "Цепочка:" in source
    assert "verify_integrity" in source


def test_gui_3_dashboard():
    source = inspect.getsource(AuditLogViewer)

    assert "stats_var" in source
    assert "size_var" in source
    assert "integrity_var" in source
    assert "failed_logins" in source
    assert "suspicious" in source
    assert "graph_canvas" in source
    assert "graph_period_var" in source
    assert "_draw_frequency_graph" in source


def test_gui_4_highlight():
    source = inspect.getsource(AuditLogViewer)

    assert "on_entry_select" in source
    assert "highlight_selected_entry" in source
    assert "entry_id" in source


def test_exp_1_formats(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-export-formats.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    logger = AuditLogger(db, key_manager=key_manager, bus=EventBus())
    logger.log_event("EntryCreated", source="vault", entry_id="entry-export", details={"title": "Export"})
    exporter = AuditLogExporter(db, key_manager=key_manager, audit_logger=logger)

    json_path = tmp_path / "audit.json"
    csv_path = tmp_path / "audit.csv"
    pdf_path = tmp_path / "audit.pdf"

    exporter.export(str(json_path), "json", encrypt=False, confirm_password=lambda: True)
    exporter.export(str(csv_path), "csv", encrypt=False, confirm_password=lambda: True)
    exporter.export(str(pdf_path), "pdf", encrypt=False, confirm_password=lambda: True)

    signed_json = json.loads(json_path.read_text(encoding="utf-8"))
    csv_text = csv_path.read_text(encoding="utf-8-sig")
    pdf_bytes = pdf_path.read_bytes()

    assert signed_json["format"] == "cryptosafe-audit-signed-json-v1"
    assert signed_json["entries"][0]["signature"]
    assert "sequence_number" in csv_text
    assert "EntryCreated" in csv_text
    assert pdf_bytes.startswith(b"%PDF-1.4")

    db.close()


def test_exp_2_signed_json(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-export-json.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    logger = AuditLogger(db, key_manager=key_manager, bus=EventBus())
    logger.log_event("LoginFailed", severity="WARN", source="auth", details={"reason": "bad_password"})

    export_path = tmp_path / "signed.json"
    AuditLogExporter(db, key_manager=key_manager, audit_logger=logger).export(
        str(export_path),
        "json",
        exporter="default_user",
        start_date="2000-01-01T00:00:00+00:00",
        end_date="2999-01-01T00:00:00+00:00",
        encrypt=False,
        confirm_password=lambda: True,
    )
    exported = json.loads(export_path.read_text(encoding="utf-8"))

    assert exported["metadata"]["exported_at"]
    assert exported["metadata"]["exporter"] == "default_user"
    assert exported["metadata"]["range"]["start"] == "2000-01-01T00:00:00+00:00"
    assert "public_key" in exported
    assert exported["entries"][0]["entry_hash"]
    assert exported["entries"][0]["signature"]

    db.close()


def test_exp_3_security(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-export-secure.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    logger = AuditLogger(db, key_manager=key_manager, bus=EventBus())
    logger.log_event("EntryCreated", source="vault", details={"title": "Secure export"})
    exporter = AuditLogExporter(db, key_manager=key_manager, audit_logger=logger)

    denied_path = tmp_path / "denied.json.enc"
    try:
        exporter.export(str(denied_path), "json", encrypt=True, confirm_password=lambda: False)
        assert False, "export without password confirmation must fail"
    except PermissionError:
        pass

    export_path = tmp_path / "audit.json.enc"
    result = exporter.export(str(export_path), "json", encrypt=True, confirm_password=lambda: True)
    envelope = json.loads(export_path.read_text(encoding="utf-8"))
    nonce = base64.b64decode(envelope["nonce"])
    ciphertext = base64.b64decode(envelope["ciphertext"])
    plaintext = AESGCM(key_manager.derive_key(EXPORT_KEY_PURPOSE, 32)).decrypt(nonce, ciphertext, EXPORT_AAD)
    exported = json.loads(plaintext.decode("utf-8"))
    export_event_count = db.fetchone("SELECT COUNT(*) FROM audit_log WHERE event_type = 'AuditExportCreated'")[0]

    assert result["encrypted"] is True
    assert envelope["algorithm"] == "AES-256-GCM"
    assert exported["format"] == "cryptosafe-audit-signed-json-v1"
    assert export_event_count == 1

    db.close()


def test_exp_4_range(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-export-range.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    logger = AuditLogger(db, key_manager=key_manager, bus=EventBus())
    first = logger.log_event("EntryCreated", source="vault", details={"title": "First"})
    second = logger.log_event("EntryUpdated", source="vault", details={"title": "Second"})
    db.unsafe_audit_execute("UPDATE audit_log SET timestamp = ? WHERE sequence_number = ?", ("2024-01-01T00:00:00+00:00", first))
    db.unsafe_audit_execute("UPDATE audit_log SET timestamp = ? WHERE sequence_number = ?", ("2024-02-01T00:00:00+00:00", second))

    export_path = tmp_path / "range.json"
    AuditLogExporter(db, key_manager=key_manager, audit_logger=logger).export(
        str(export_path),
        "json",
        start_date="2024-02-01T00:00:00+00:00",
        end_date="2024-02-28T23:59:59+00:00",
        encrypt=False,
        confirm_password=lambda: True,
    )
    exported = json.loads(export_path.read_text(encoding="utf-8"))

    assert exported["metadata"]["entry_count"] == 1
    assert exported["entries"][0]["sequence_number"] == second

    db.close()


def test_exp_4_schedule(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-export-schedule.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    logger = AuditLogger(db, key_manager=key_manager, bus=EventBus())
    logger.log_event("EntryCreated", source="vault", details={"title": "Scheduled"})
    exporter = AuditLogExporter(db, key_manager=key_manager, audit_logger=logger)

    schedule_id = exporter.create_schedule(
        name="daily",
        output_dir=str(tmp_path),
        export_format="json",
        frequency="daily",
        retention_days=1,
    )
    db.execute(
        "UPDATE audit_export_schedule SET next_run_at = ? WHERE id = ?",
        ("2000-01-01T00:00:00+00:00", schedule_id),
    )

    old_export = tmp_path / "audit-old.json.enc"
    old_export.write_text("old", encoding="utf-8")
    old_timestamp = (datetime.now(timezone.utc) - timedelta(days=3)).timestamp()
    os.utime(old_export, (old_timestamp, old_timestamp))

    results = exporter.run_due_schedules(confirm_password=lambda: True)
    next_run_at = db.fetchone("SELECT next_run_at FROM audit_export_schedule WHERE id = ?", (schedule_id,))[0]

    assert len(results) == 1
    assert results[0]["encrypted"] is True
    assert not old_export.exists()
    assert next_run_at > "2000-01-01T00:00:00+00:00"

    db.close()


def test_perf_1_logging(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-perf-log.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    logger = AuditLogger(db, key_manager=key_manager, bus=EventBus())
    first = logger.log_event("EntryCreated", source="vault", details={"index": 1})
    second = logger.log_event("EntryCreated", source="vault", details={"index": 2})

    assert second == first + 1
    assert logger._fallback_sequence == second
    assert logger._fallback_last_hash

    db.close()


def test_perf_2_streaming():
    source = inspect.getsource(AuditLogVerifier)

    assert "_iter_rows" in source
    assert "iter_rows" in source
    assert "fetchmany" not in source or "batch_size" in source


def test_perf_3_indexes(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-perf-indexes.db"))
    indexes = {row[1] for row in db.fetchall("PRAGMA index_list(audit_log)")}

    assert "idx_audit_timestamp" in indexes
    assert "idx_audit_event_type" in indexes
    assert "idx_audit_event_timestamp" in indexes
    assert "idx_audit_entry_id" in indexes

    db.close()


def test_perf_4_lazy_viewer():
    source = inspect.getsource(AuditLogViewer)

    assert '"entry_data": None' in source
    assert "search_text" in source
    assert "_load_entry_data" in source
    assert "SELECT entry_data FROM audit_log WHERE sequence_number = ?" in source


def test_perf_5_async(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-perf-async.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    logger = AuditLogger(db, key_manager=key_manager, bus=EventBus())
    assert logger.log_event_async("EntryCreated", source="vault", details={"mode": "async"}) is True
    assert logger.flush_async()
    count = db.fetchone("SELECT COUNT(*) FROM audit_log WHERE event_type = 'EntryCreated'")[0]

    assert count == 1
    logger.shutdown()
    db.close()


def test_test_1_integrity(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-test-1.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    signer = AuditLogSigner(key_manager=key_manager)
    logger = AuditLogger(db, signer=signer, bus=EventBus())
    for index in range(1000):
        logger.log_event("EntryCreated", source="vault", details={"index": index})

    db.unsafe_audit_execute("UPDATE audit_log SET entry_hash = ? WHERE sequence_number = ?", ("tampered", 500))
    result = AuditLogVerifier(db, signer, bus=EventBus()).verify_integrity()

    assert result["verified"] is False
    assert {"sequence": 500, "reason": "hash mismatch"} in result["invalid_entries"]

    db.close()


def test_test_1_chain_delete_detected(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-test-1-chain.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    signer = AuditLogSigner(key_manager=key_manager)
    logger = AuditLogger(db, signer=signer, bus=EventBus())
    first = logger.log_event("EntryCreated", source="vault", details={"index": 1})
    middle = logger.log_event("EntryUpdated", source="vault", details={"index": 2})
    logger.log_event("EntryDeleted", source="vault", details={"index": 3})

    db.unsafe_audit_execute("DELETE FROM audit_log WHERE sequence_number = ?", (middle,))
    result = AuditLogVerifier(db, signer, bus=EventBus()).verify_integrity()

    assert result["verified"] is False
    assert result["chain_breaks"]
    assert result["chain_breaks"][0]["sequence"] == first + 2

    db.close()


def test_test_5_audit_log_is_append_only(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-test-5-append-only.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    logger = AuditLogger(db, key_manager=key_manager, bus=EventBus())
    sequence = logger.log_event("EntryCreated", source="vault", details={"title": "Immutable"})

    with pytest.raises(PermissionError, match="append-only"):
        db.execute("UPDATE audit_log SET event_type = ? WHERE sequence_number = ?", ("Tampered", sequence))

    with pytest.raises(PermissionError, match="append-only"):
        db.execute("DELETE FROM audit_log WHERE sequence_number = ?", (sequence,))

    result = AuditLogVerifier(db, logger.signer, bus=EventBus()).verify_integrity()
    assert result["verified"] is True

    db.close()


def test_test_2_performance(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-test-2.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    signer = AuditLogSigner(key_manager=key_manager)
    logger = AuditLogger(db, signer=signer, bus=EventBus())

    rng = random.Random(20260519)
    event_types = ["EntryCreated", "EntryUpdated", "EntryDeleted", "UserLoginSuccess", "ClipboardCopied"]
    sources = ["vault", "auth", "clipboard", "settings", "security"]
    severities = ["INFO", "INFO", "INFO", "WARN", "ERROR"]
    payloads = [
        {
            "event_type": rng.choice(event_types),
            "severity": rng.choice(severities),
            "source": rng.choice(sources),
            "details": {
                "index": index,
                "entry_id": f"entry-{rng.randrange(1, 500)}",
                "operation_id": f"op-{rng.getrandbits(48):012x}",
                "payload_size": rng.randrange(8, 256),
                "flagged": rng.random() < 0.05,
            },
        }
        for index in range(10000)
    ]

    start = time.perf_counter()
    for payload in payloads:
        logger.log_event(
            payload["event_type"],
            severity=payload["severity"],
            source=payload["source"],
            details=payload["details"],
        )
    logging_time = time.perf_counter() - start
    avg_logging_ms = logging_time / len(payloads) * 1000

    start = time.perf_counter()
    result = AuditLogVerifier(db, signer, bus=EventBus()).verify_periodic(sample_size=1000)
    verification_time = time.perf_counter() - start

    print(
        "\nSprint 5 TEST-2 performance: "
        f"events={len(payloads)}, "
        f"logging_total={logging_time:.3f}s, "
        f"logging_avg={avg_logging_ms:.3f}ms, "
        f"verify_1000={verification_time:.3f}s"
    )

    assert logging_time / len(payloads) < 0.010
    assert verification_time < 1.0
    assert result["verified"] is True
    assert result["total_entries"] == 1000

    db.close()


def test_test_3_export_import(tmp_path):
    source_db = DatabaseHelper(str(tmp_path / "audit-test-3-source.db"))
    key_manager = KeyManager(source_db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    signer = AuditLogSigner(key_manager=key_manager)
    logger = AuditLogger(source_db, signer=signer, bus=EventBus())
    for index in range(10):
        logger.log_event("EntryCreated", source="vault", details={"index": index})

    export_path = tmp_path / "signed-audit.json"
    AuditLogExporter(source_db, key_manager=key_manager, audit_logger=logger).export(
        str(export_path),
        "json",
        encrypt=False,
        confirm_password=lambda: True,
    )

    imported_db = DatabaseHelper(str(tmp_path / "audit-test-3-imported.db"))
    importer = AuditLogImportVerifier(imported_db)
    independent_result = importer.verify_signed_json(export_path)
    import_result = importer.import_signed_json(export_path)
    imported_result = AuditLogVerifier(imported_db, signer, bus=EventBus()).verify_integrity()

    assert independent_result["verified"] is True
    assert import_result["imported"] == 10
    assert imported_result["verified"] is True
    assert imported_result["valid_entries"] == 10

    source_db.close()
    imported_db.close()


def test_test_4_recovery(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-test-4.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    logger = AuditLogger(db, key_manager=key_manager, bus=EventBus())
    logger.log_event("EntryCreated", source="vault", details={"title": "Recoverable"})
    recovery = db.recover_to(str(tmp_path / "audit-test-4-recovered.db"))

    recovered_db = DatabaseHelper(recovery["recovered_db_path"])
    with recovered_db.audit_read_access():
        recovered_count = recovered_db.fetchone("SELECT COUNT(*) FROM audit_log")[0]

    assert recovery["source_ok"] is True
    assert recovery["copied_audit_entries"] == 1
    assert recovered_count == 1

    db.close()
    recovered_db.close()

    corrupt_path = tmp_path / "corrupt.db"
    corrupt_path.write_bytes(b"not a sqlite database")
    corrupt_recovery = DatabaseHelper.recover_corrupt_database(
        str(corrupt_path),
        str(tmp_path / "clean-recovered.db"),
    )

    assert corrupt_recovery["source_ok"] is False
    assert os.path.exists(corrupt_recovery["quarantine_path"])
    assert os.path.exists(corrupt_recovery["recovered_db_path"])


def test_test_5_security(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-test-5.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    signer = AuditLogSigner(key_manager=key_manager)
    logger = AuditLogger(db, signer=signer, bus=EventBus())
    logger.log_security_attempt("sql_injection", {"input": "'; DROP TABLE audit_log; --"})
    logger.log_security_attempt("privilege_escalation", {"role": "admin"})
    sequence = logger.log_security_attempt("tampering", {"target": "audit_log"})

    db.unsafe_audit_execute("UPDATE audit_log SET signature = ? WHERE sequence_number = ?", ("00", sequence))
    result = AuditLogVerifier(db, signer, bus=EventBus()).verify_integrity()
    logged_attempts = db.fetchone(
        """
        SELECT COUNT(*)
        FROM audit_log
        WHERE event_type IN ('SQLInjectionAttempt', 'PrivilegeEscalationAttempt', 'AuditTamperAttempt')
        """
    )[0]

    assert logged_attempts == 3
    assert result["verified"] is False
    assert result["invalid_entries"][-1]["reason"] == "invalid signature"

    db.close()


def test_int_1_event_bus(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-int-1.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    bus = EventBus()
    logger = AuditLogger(db, key_manager=key_manager, bus=bus)
    bus.publish("PanicModeActivated", {"reason": "hotkey"})
    bus.publish("TOTPViewed", {"entry_id": "entry-totp", "totp_secret": "raw-secret"})
    logger.flush_async()

    rows = db.fetchall(
        "SELECT event_type, entry_data FROM audit_log WHERE event_type IN ('PanicModeActivated', 'TOTPViewed')"
    )
    text = "\n".join(row[1].decode("utf-8") if isinstance(row[1], bytes) else str(row[1]) for row in rows)

    assert {row[0] for row in rows} == {"PanicModeActivated", "TOTPViewed"}
    assert "raw-secret" not in text

    logger.shutdown()
    db.close()


def test_int_2_vault_events(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-int-2.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    bus = EventBus()
    logger = AuditLogger(db, key_manager=key_manager, bus=bus)
    manager = EntryManager(db, key_manager)

    entry_id = manager.create_entry({"title": "Work Email", "username": "ivan", "password": "Secret123!"})
    manager.update_entry(entry_id, {"notes": "updated"})
    manager.search_entries("Work Email")
    manager.delete_entry(entry_id, soft_delete=True)
    logger.flush_async()

    rows = db.fetchall(
        """
        SELECT event_type, entry_id, details
        FROM audit_log
        WHERE event_type IN ('EntryCreated', 'EntryRead', 'EntryUpdated', 'EntryDeleted', 'VaultSearch')
        """
    )
    event_types = {row[0] for row in rows}
    details_text = "\n".join(row[2] or "" for row in rows)

    assert {"EntryCreated", "EntryRead", "EntryUpdated", "EntryDeleted", "VaultSearch"}.issubset(event_types)
    assert any(row[1] == entry_id for row in rows if row[0].startswith("Entry"))
    assert "Work Email" not in details_text
    assert "query_hash" in details_text

    logger.shutdown()
    db.close()


def test_int_3_clipboard_events(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-int-3.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    bus = EventBus()
    logger = AuditLogger(db, key_manager=key_manager, bus=bus)
    bus.publish(
        "ClipboardCopied",
        {
            "data_type": "password",
            "source_entry_id": "entry-clip",
            "clipboard_content": "plain-password",
            "timeout": 30,
        },
    )
    bus.publish("ClipboardMonitorError", {"reason": "poll_failed", "message": "backend failed"})
    logger.flush_async()

    rows = db.fetchall(
        "SELECT event_type, entry_id, entry_data FROM audit_log WHERE event_type LIKE 'Clipboard%'"
    )
    text = "\n".join(row[2].decode("utf-8") if isinstance(row[2], bytes) else str(row[2]) for row in rows)

    assert {"ClipboardCopied", "ClipboardMonitorError"}.issubset({row[0] for row in rows})
    assert any(row[1] == "entry-clip" for row in rows)
    assert "plain-password" not in text

    logger.shutdown()
    db.close()


def test_int_4_future_events(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-int-4.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    bus = EventBus()
    logger = AuditLogger(db, key_manager=key_manager, bus=bus)
    logger.log_event("AuditImportCompleted", severity="WARN", source="audit", details={"imported": 2})
    logger.log_event("AuditExportCreated", severity="WARN", source="audit", details={"format": "json"})
    logger.log_event("PanicModeActivated", severity="CRITICAL", source="security", details={"reason": "manual"})
    logger.log_event("TOTPCopied", severity="INFO", source="totp", entry_id="entry-totp", details={"entry_id": "entry-totp"})

    event_types = {
        row[0]
        for row in db.fetchall(
            """
            SELECT event_type
            FROM audit_log
            WHERE event_type IN ('AuditImportCompleted', 'AuditExportCreated', 'PanicModeActivated', 'TOTPCopied')
            """
        )
    }

    assert event_types == {"AuditImportCompleted", "AuditExportCreated", "PanicModeActivated", "TOTPCopied"}

    logger.shutdown()
    db.close()


def test_comp_1_cef_format(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-comp-1.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    logger = AuditLogger(db, key_manager=key_manager, bus=EventBus())
    sequence = logger.log_event("EntryCreated", source="vault", entry_id="entry-cef", details={"title": "CEF"})
    row = db.fetchone(
        """
        SELECT sequence_number, previous_hash, entry_data, entry_hash, event_type,
               timestamp, entry_id, details, signature, public_key
        FROM audit_log
        WHERE sequence_number = ?
        """,
        (sequence,),
    )
    record = {
        "sequence_number": row[0],
        "previous_hash": row[1],
        "entry_data": row[2],
        "entry_hash": row[3],
        "event_type": row[4],
        "timestamp": row[5],
        "entry_id": row[6],
        "details": row[7],
        "signature": row[8],
        "public_key": row[9],
    }
    entry = json.loads(row[2].decode("utf-8") if isinstance(row[2], bytes) else row[2])
    cef_text = AuditLogFormatter.to_cef([record])

    assert entry["cef"].startswith("CEF:0|CryptoSafe|Manager|5|EntryCreated|vault|3|")
    assert "cs1=entry-cef" in entry["cef"]
    assert cef_text.startswith("CEF:0|CryptoSafe|Manager|5|EntryCreated|vault|3|")

    logger.shutdown()
    db.close()


def test_comp_2_timezone(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-comp-2.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    logger = AuditLogger(db, key_manager=key_manager, bus=EventBus())
    sequence = logger.log_event("LoginSucceeded", source="auth", details={})
    entry_data = db.fetchone("SELECT entry_data FROM audit_log WHERE sequence_number = ?", (sequence,))[0]
    entry = json.loads(entry_data.decode("utf-8") if isinstance(entry_data, bytes) else entry_data)
    parsed = datetime.fromisoformat(entry["timestamp"])

    assert parsed.tzinfo is not None
    assert parsed.utcoffset() == timezone.utc.utcoffset(parsed)

    logger.shutdown()
    db.close()


def test_comp_3_retention_policy(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-comp-3.db"))

    db.set_audit_rotation_policy(max_entries=123, max_age_days=45, auto_archive=False)
    policy = db.get_audit_rotation_policy()

    assert policy == {"max_entries": 123, "max_age_days": 45, "auto_archive": False}

    db.close()


def test_comp_4_timeline(tmp_path):
    db = DatabaseHelper(str(tmp_path / "audit-comp-4.db"))
    key_manager = KeyManager(db)
    assert key_manager.setup_new_vault("Str0ng!P@ssw0rd123")

    logger = AuditLogger(db, key_manager=key_manager, bus=EventBus())
    first = logger.log_event("EntryCreated", source="vault", details={"index": 1})
    second = logger.log_event("EntryUpdated", source="vault", details={"index": 2})
    third = logger.log_event("EntryDeleted", source="vault", details={"index": 3})
    timeline = db.get_audit_timeline()

    assert [row[0] for row in timeline[-3:]] == [first, second, third]
    assert [row[2] for row in timeline[-3:]] == ["EntryCreated", "EntryUpdated", "EntryDeleted"]

    logger.shutdown()
    db.close()

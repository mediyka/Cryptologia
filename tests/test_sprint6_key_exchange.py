import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from core.import_export import KeyExchangeService, QRCodeValidationError
from database.db import DatabaseHelper


@pytest.fixture
def key_exchange_db(tmp_path):
    db = DatabaseHelper(str(tmp_path / "key-exchange.db"))
    yield db
    db.close()


def test_qr_3_key_pairs():
    service = KeyExchangeService()
    rsa_pair = service.generate_rsa_key_pair()
    ecc_pair = service.generate_ecc_key_pair()

    assert rsa_pair.algorithm == "RSA-2048"
    assert ecc_pair.algorithm == "ECC-P-256"
    assert b"BEGIN PRIVATE KEY" in rsa_pair.private_key_pem
    assert b"BEGIN PUBLIC KEY" in ecc_pair.public_key_pem
    assert rsa_pair.fingerprint != ecc_pair.fingerprint


def test_qr_3_contact_lifecycle(key_exchange_db):
    service = KeyExchangeService(key_exchange_db)
    old_pair = service.generate_rsa_key_pair()
    new_pair = service.generate_ecc_key_pair()

    contact_id = service.store_contact_key(
        key_exchange_db,
        "Alice",
        old_pair.public_key_pem,
        identifier="alice@example.com",
    )
    assert service.verify_contact_fingerprint(contact_id, old_pair.fingerprint) is True

    rotated_id = service.rotate_contact_key(contact_id, new_pair.public_key_pem)
    contacts = service.list_contacts(include_revoked=True)
    active_key = service.get_active_public_key(rotated_id)

    assert any(contact["id"] == contact_id and contact["status"] == "revoked" for contact in contacts)
    assert any(contact["id"] == rotated_id and contact["rotated_from"] == contact_id for contact in contacts)
    assert active_key == new_pair.public_key_pem


def test_qr_1_public_key_roundtrip(key_exchange_db):
    service = KeyExchangeService(key_exchange_db)
    pair = service.generate_rsa_key_pair()
    payload = service.create_public_key_payload(
        pair.public_key_pem,
        contact_name="Alice",
        identifier="alice@example.com",
    )
    bundle = service.generate_qr_codes(payload, chunk_size=128, render_svg=False)
    decoded = service.decode_qr_chunks([chunk.encoded_text for chunk in bundle.chunks])
    contact_id = service.import_public_key_payload(decoded, verified=True)
    contacts = service.list_contacts()

    assert decoded["fingerprint"] == pair.fingerprint
    assert len(bundle.chunks) > 1
    assert contacts[-1]["id"] == contact_id
    assert contacts[-1]["verified"] is True


def test_qr_1_entry_chunking():
    service = KeyExchangeService()
    content = b"x" * 2048
    payload = service.create_encrypted_entry_payload(content)
    bundle = service.generate_qr_codes(payload, chunk_size=256, render_svg=False)
    decoded = service.decode_qr_chunks([chunk.encoded_text for chunk in bundle.chunks])

    assert decoded["type"] == "encrypted_entry"
    assert decoded["data_sha256"] == payload["data_sha256"]
    assert len(bundle.chunks) >= 1


def test_qr_2_bad_chunk():
    service = KeyExchangeService()
    payload = service.create_share_link_payload("https://example.invalid/share/abc")
    bundle = service.generate_qr_codes(payload, render_svg=False)
    chunk = json.loads(bundle.chunks[0].encoded_text)
    chunk["data"] = chunk["data"][:-4] + "AAAA"

    with pytest.raises(QRCodeValidationError):
        service.decode_qr_chunks([json.dumps(chunk)])


def test_qr_4_ttl_replay():
    service = KeyExchangeService()
    with pytest.raises(ValueError):
        service.create_share_link_payload("https://example.invalid/share/abc", ttl_seconds=3600)

    payload = service.create_share_link_payload("https://example.invalid/share/abc")
    bundle = service.generate_qr_codes(payload, render_svg=False)
    chunks = [chunk.encoded_text for chunk in bundle.chunks]

    service.decode_qr_chunks(chunks)
    with pytest.raises(QRCodeValidationError):
        service.decode_qr_chunks(chunks)

"""
Тесты базы данных.
"""
import pytest
import tempfile
from pathlib import Path
from src.database.db import Database
from src.database.models import VaultEntry


@pytest.fixture
def temp_db():
    """Фикстура для временной БД."""
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = Path(f.name)
    
    # Подменяем путь к БД
    from src.core.config import config
    original_path = config.DB_PATH
    config.DB_PATH = db_path
    
    db = Database()
    yield db
    
    # Очистка
    db_path.unlink()
    config.DB_PATH = original_path


def test_add_entry(temp_db):
    """Тест добавления записи."""
    entry = VaultEntry(
        title="Test",
        username="user",
        encrypted_password=b"encrypted"
    )
    
    entry_id = temp_db.add_entry(entry)
    assert entry_id > 0


def test_get_entries(temp_db):
    """Тест получения записей."""
    entries = temp_db.get_all_entries()
    assert isinstance(entries, list)

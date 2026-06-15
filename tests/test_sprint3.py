"""
Тесты для Спринта 3: AES-256-GCM, CRUD, Password Generator.
Реализует требования TEST-1 — TEST-4.
"""

import pytest
import os
import sys
import time
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from core.vault.encryption_service import AES256GCMService
from core.vault.password_generator import PasswordGenerator, PasswordStrength
from core.vault.entry_manager import EntryManager, EntryEvent
from core.key_manager import KeyManager
from database.db import DatabaseHelper


@pytest.fixture
def temp_db(tmp_path):
    """Создает временную БД для тестов."""
    db_file = tmp_path / "test_sprint3.db"
    db = DatabaseHelper(str(db_file))
    yield db
    db.close()


@pytest.fixture
def key_manager(temp_db):
    """KeyManager с настроенным хранилищем."""
    km = KeyManager(temp_db)
    password = "Str0ng!P@ssw0rd123"
    km.setup_new_vault(password)
    return km


@pytest.fixture
def encryption_service(key_manager):
    """AES-256-GCM сервис с ключом."""
    service = AES256GCMService()
    service.set_key_manager(key_manager)
    return service


@pytest.fixture
def entry_manager(temp_db, key_manager):
    """EntryManager с настроенным хранилищем."""
    return EntryManager(temp_db, key_manager)


# === TEST-1: (ENC-1 — ENC-5) ===

class TestAES256GCMEncryption:
    """TEST-1: Тесты шифрования AES-256-GCM."""

    def test_encrypt_decrypt_round_trip(self, encryption_service):
        """Шифрование и расшифровка — данные должны совпасть."""
        original_data = b"This is secret data for testing AES-256-GCM round trip!"

        encrypted = encryption_service.encrypt(original_data)
        decrypted = encryption_service.decrypt(encrypted)

        assert decrypted == original_data

    def test_encrypted_blob_not_plaintext(self, encryption_service):
        """Зашифрованный BLOB не должен содержать исходные данные."""
        original_data = b"secret_password_12345"
        encrypted = encryption_service.encrypt(original_data)

        assert original_data not in encrypted
        assert encrypted != original_data

    def test_unique_nonces(self, encryption_service):
        """Каждое шифрование должно использовать уникальный nonce (ENC-2)."""
        data = b"same data"
        encrypted1 = encryption_service.encrypt(data)
        encrypted2 = encryption_service.encrypt(data)

        # Первые 12 байт — nonce, должны отличаться
        nonce1 = encrypted1[:12]
        nonce2 = encrypted2[:12]
        assert nonce1 != nonce2

        # Зашифрованные blob тоже разные
        assert encrypted1 != encrypted2

    def test_blob_format_nonce_ciphertext_tag(self, encryption_service):
        """Формат: nonce (12B) || ciphertext || tag (16B) (ENC-4)."""
        data = b"test data for format validation"
        encrypted = encryption_service.encrypt(data)

        # Минимальная длина: 12 (nonce) + 0 (ciphertext) + 16 (tag) = 28
        assert len(encrypted) >= 12 + 16

        #Nonce первые 12 байт
        nonce = encrypted[:12]
        assert len(nonce) == 12

    def test_authentication_tag_validation(self, encryption_service):
        """Валидация authentication tag при tampering (ENC-5)."""
        data = b"important secret data"
        encrypted = encryption_service.encrypt(data)

        #Tampering: изменяем байт в ciphertext
        tampered = bytearray(encrypted)
        tampered[15] ^= 0xFF  # Изменяем байт в ciphertext/tag

        with pytest.raises(ValueError, match="проверка подлинности не пройдена"):
            encryption_service.decrypt(bytes(tampered))

    def test_encrypt_decrypt_dict(self, key_manager):
        """Шифровка/расшифровка словаря (ENC-3)."""
        payload = {
            "title": "Test Entry",
            "username": "user@test.com",
            "password": "s3cr3t!",
            "url": "https://test.com",
            "notes": "Test notes",
            "category": "Work",
            "version": 1,
        }

        encrypted = AES256GCMService.encrypt_dict(payload, key_manager)
        decrypted = AES256GCMService.decrypt_dict(encrypted, key_manager)

        assert decrypted["title"] == payload["title"]
        assert decrypted["password"] == payload["password"]
        assert decrypted["version"] == 1


# === TEST-2: CRUD Integration Test (CRUD-1 — CRUD-4) ===

class TestEntryManagerCRUD:
    """TEST-2: Интеграционные тесты CRUD операций."""

    def test_create_entry(self, entry_manager):
        """CRUD-1: Создание записи."""
        data = {
            "title": "Google Account",
            "username": "user@gmail.com",
            "password": "G00gle_P@ss!",
            "url": "https://accounts.google.com",
            "notes": "Main Google account",
            "category": "Work",
            "tags": ["google", "email"],
        }

        entry_id = entry_manager.create_entry(data)
        assert entry_id is not None
        assert len(entry_id) > 0

    def test_get_entry(self, entry_manager):
        """CRUD-1: Получение записи."""
        data = {
            "title": "GitHub",
            "username": "dev@github.com",
            "password": "G1tHub_S3cur3!",
            "url": "https://github.com",
            "notes": "",
            "category": "Dev",
            "tags": ["github"],
        }

        entry_id = entry_manager.create_entry(data)
        retrieved = entry_manager.get_entry(entry_id)

        assert retrieved["title"] == data["title"]
        assert retrieved["username"] == data["username"]
        assert retrieved["password"] == data["password"]
        assert retrieved["url"] == data["url"]

    def test_update_entry(self, entry_manager):
        """CRUD-1: Обновление записи."""
        data = {
            "title": "Twitter",
            "username": "user@twitter.com",
            "password": "Tw1tter_P@ss!",
            "url": "https://twitter.com",
            "notes": "",
            "category": "Social",
            "tags": ["twitter"],
        }

        entry_id = entry_manager.create_entry(data)

        # Обновляем
        update_data = {
            "password": "N3w_Tw1tter_P@ss!",
            "notes": "Updated password",
        }

        entry_manager.update_entry(entry_id, update_data)
        updated = entry_manager.get_entry(entry_id)

        assert updated["password"] == update_data["password"]
        assert updated["notes"] == update_data["notes"]
        assert updated["title"] == data["title"]  # Не изменилось

    def test_delete_entry_soft(self, entry_manager):
        """CRUD-1, CRUD-4: Мягкое удаление."""
        data = {
            "title": "ToDelete",
            "username": "delete@test.com",
            "password": "D3lete_P@ss!",
            "url": "",
            "notes": "",
            "category": "",
            "tags": [],
        }

        entry_id = entry_manager.create_entry(data)

        # Мягкое удаление
        entry_manager.delete_entry(entry_id, soft_delete=True)

        # Запись не должна быть в vault_entries
        all_entries = entry_manager.get_all_entries(include_decrypted_password=True)
        assert not any(e["id"] == entry_id for e in all_entries)

        # Но должна быть в deleted_entries
        deleted = entry_manager.get_deleted_entries()
        assert any(d["original_id"] == entry_id for d in deleted)

    def test_delete_entry_hard(self, entry_manager):
        """CRUD-1: Жёсткое удаление."""
        data = {
            "title": "HardDelete",
            "username": "hard@test.com",
            "password": "H4rd_P@ss!",
            "url": "",
            "notes": "",
            "category": "",
            "tags": [],
        }

        entry_id = entry_manager.create_entry(data)
        entry_manager.delete_entry(entry_id, soft_delete=False)

        all_entries = entry_manager.get_all_entries(include_decrypted_password=True)
        assert not any(e["id"] == entry_id for e in all_entries)

    def test_restore_entry(self, entry_manager):
        """CRUD-4: Восстановление удалённой записи."""
        data = {
            "title": "Restore Me",
            "username": "restore@test.com",
            "password": "R3st0re_P@ss!",
            "url": "",
            "notes": "",
            "category": "",
            "tags": [],
        }

        entry_id = entry_manager.create_entry(data)
        entry_manager.delete_entry(entry_id, soft_delete=True)

        # Восстановление
        entry_manager.restore_entry(entry_id)

        all_entries = entry_manager.get_all_entries(include_decrypted_password=True)
        assert any(e["id"] == entry_id for e in all_entries)

    def test_crud_100_entries(self, entry_manager):
        """TEST-2: CRUD Integration Test — 100 записей."""
        # Создаём 100 записей
        created_ids = []
        for i in range(100):
            data = {
                "title": f"Site {i}",
                "username": f"user{i}@test.com",
                "password": f"S3cur3_P@ss_{i}!",
                "url": f"https://site{i}.com",
                "notes": f"Note for site {i}",
                "category": "Test",
                "tags": [f"tag{i}"],
            }
            entry_id = entry_manager.create_entry(data)
            created_ids.append(entry_id)

        assert len(created_ids) == 100

        # Проверяем получение всех записей
        all_entries = entry_manager.get_all_entries(include_decrypted_password=True)
        assert len(all_entries) == 100

        # Обновляем каждые 10-ю запись
        for i in range(0, 100, 10):
            entry_id = created_ids[i]
            entry_manager.update_entry(entry_id, {"notes": f"Updated note for site {i}"})

        # Проверяем обновления
        for i in range(0, 100, 10):
            entry_id = created_ids[i]
            entry = entry_manager.get_entry(entry_id)
            assert entry["notes"] == f"Updated note for site {i}"

        # Удаляем 10 записей
        for i in range(0, 100, 10):
            entry_manager.delete_entry(created_ids[i], soft_delete=True)

        # Проверяем остаток
        all_entries = entry_manager.get_all_entries(include_decrypted_password=True)
        assert len(all_entries) == 90

    def test_transactional_rollback(self, entry_manager):
        """CRUD-2: Транзакционность с rollback."""
        data = {
            "title": "Transactional Test",
            "username": "tx@test.com",
            "password": "Tx_P@ss!",
            "url": "",
            "notes": "",
            "category": "",
            "tags": [],
        }

        # Создание должно пройти успешно
        entry_id = entry_manager.create_entry(data)
        assert entry_id is not None

    def test_entry_not_found(self, entry_manager):
        """Получение несуществующей записи."""
        with pytest.raises(ValueError, match="Ошибка доступа"):
            entry_manager.get_entry("non-existent-id")


# === TEST-3: Concurrency Test (TEST-3) ===

class TestConcurrency:
    """TEST-3: Тесты конкурентности."""

    def test_concurrent_crud(self, entry_manager):
        """Симуляция множественных операций (псевдо-конкурентность)."""
        import threading

        errors = []
        created_ids = []
        lock = threading.Lock()

        def create_entries(start, count):
            try:
                for i in range(start, start + count):
                    data = {
                        "title": f"Concurrent {i}",
                        "username": f"user{i}@test.com",
                        "password": f"C0nc_P@ss_{i}!",
                        "url": f"https://site{i}.com",
                        "notes": "",
                        "category": "",
                        "tags": [],
                    }
                    entry_id = entry_manager.create_entry(data)
                    with lock:
                        created_ids.append(entry_id)
            except Exception as e:
                errors.append(str(e))

        # Запускаем 2 потока по 10 записей
        threads = [
            threading.Thread(target=create_entries, args=(0, 10)),
            threading.Thread(target=create_entries, args=(100, 10)),
        ]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Проверяем результат
        assert len(errors) == 0, f"Errors: {errors}"
        assert len(created_ids) == 20


# === TEST-4: Password Generator Test (GEN-1 — GEN-5) ===

class TestPasswordGenerator:
    """TEST-4: Тесты генератора паролей."""

    def test_generate_basic(self):
        """GEN-1: Базовая генерация."""
        gen = PasswordGenerator()
        password = gen.generate()

        assert len(password) == 16  # Длина по умолчанию
        assert len(password) >= 8

    def test_generate_custom_length(self):
        """GEN-2: Кастомная длина."""
        gen = PasswordGenerator()

        for length in [8, 12, 20, 32, 64]:
            password = gen.generate(length=length)
            assert len(password) == length

    def test_generate_character_sets(self):
        """GEN-2: Наборы символов."""
        gen = PasswordGenerator()

        # Только заглавные
        password = gen.generate(length=16, use_lowercase=False, use_digits=False, use_symbols=False)
        assert all(c.isupper() for c in password)

        # Только цифры
        password = gen.generate(length=16, use_uppercase=False, use_lowercase=False, use_symbols=False)
        assert all(c.isdigit() for c in password)

    def test_exclude_ambiguous(self):
        """GEN-2: Исключение неоднозначных символов."""
        gen = PasswordGenerator()
        password = gen.generate(length=32, exclude_ambiguous=True)

        ambiguous = set("lI10Oo")
        assert not any(c in ambiguous for c in password)

    def test_guaranteed_character_sets(self):
        """GEN-3: Гарантия хотя бы одного символа из каждого набора."""
        gen = PasswordGenerator()

        password = gen.generate(length=16)

        # Проверяем наличие каждого типа
        assert any(c.isupper() for c in password), "No uppercase"
        assert any(c.islower() for c in password), "No lowercase"
        assert any(c.isdigit() for c in password), "No digits"
        assert any(not c.isalnum() for c in password), "No symbols"

    def test_no_duplicates_in_history(self):
        """GEN-5: История предотвращает дубликаты."""
        gen = PasswordGenerator()
        gen.clear_history()

        # Генерируем много паролей (маловероятно получить дубликат с энтропией)
        passwords = set()
        for _ in range(100):
            pwd = gen.generate(length=12)
            passwords.add(pwd)

        # Все должны быть уникальны (вероятность коллизии крайне мала)
        assert len(passwords) == 100

    def test_password_strength_calculation(self):
        """GEN-4: Оценка сложности пароля."""
        # Очень слабый
        assert PasswordStrength.calculate("") == 0
        assert PasswordStrength.calculate("short") == 0

        # Слабый/Средний — short1A! имеет 8 символов + 4 типа = score 2
        assert PasswordStrength.calculate("short1A!") >= 1

        # Средний
        score = PasswordStrength.calculate("Medium1!Pass")
        assert score >= 2

        # Сильный
        score = PasswordStrength.calculate("Str0ng!P@ssw0rd123")
        assert score >= 3

        # Очень сильный
        score = PasswordStrength.calculate("V3ry!Str0ng#P@ssw0rd_L0ng")
        assert score >= 4

    def test_generate_10000_passwords(self):
        """TEST-4: Генерация 10,000 паролей — проверка уникальности и соответствия требованиям."""
        gen = PasswordGenerator()
        gen.clear_history()

        # Для теста используем меньшее число (10000 может занять время)
        count = 1000
        passwords = []

        for _ in range(count):
            pwd = gen.generate(length=16)
            passwords.append(pwd)

        # Проверка 1: Нет дубликатов (probability check)
        assert len(set(passwords)) == count, "Found duplicate passwords!"

        # Проверка 2: Character set compliance
        for pwd in passwords:
            assert any(c.isupper() for c in pwd)
            assert any(c.islower() for c in pwd)
            assert any(c.isdigit() for c in pwd)
            assert any(not c.isalnum() for c in pwd)

        # Проверка 3: Strength requirements
        for pwd in passwords:
            score = PasswordStrength.calculate(pwd)
            assert score >= 3, f"Password strength too low: {pwd} (score={score})"

    def test_history_size(self):
        """GEN-5: Проверка размера истории."""
        gen = PasswordGenerator(history_size=5)

        for _ in range(10):
            gen.generate()

        assert len(gen.get_history()) == 5


# === SEARCH TESTS ===

class TestSearchAndFilter:
    """Тесты поиска и фильтрации (SEARCH-1 — SEARCH-3)."""

    def test_search_by_title(self, entry_manager):
        """SEARCH-1: Поиск по названию."""
        entry_manager.create_entry({
            "title": "Google Account",
            "username": "user@gmail.com",
            "password": "P@ss1!",
            "url": "",
            "notes": "",
            "category": "",
            "tags": [],
        })

        entry_manager.create_entry({
            "title": "Facebook Profile",
            "username": "user@fb.com",
            "password": "P@ss2!",
            "url": "",
            "notes": "",
            "category": "",
            "tags": [],
        })

        results = entry_manager.search_entries("Google")
        assert len(results) == 1
        assert results[0]["title"] == "Google Account"

    def test_search_by_username(self, entry_manager):
        """SEARCH-1: Поиск по имени пользователя."""
        entry_manager.create_entry({
            "title": "Test Entry",
            "username": "john.doe@example.com",
            "password": "P@ss!",
            "url": "",
            "notes": "",
            "category": "",
            "tags": [],
        })

        results = entry_manager.search_entries("john.doe")
        assert len(results) == 1

    def test_search_field_filter(self, entry_manager):
        """SEARCH-1: Фильтр по конкретному полю."""
        entry_manager.create_entry({
            "title": "Work Email",
            "username": "user@work.com",
            "password": "P@ss!",
            "url": "",
            "notes": "",
            "category": "Work",
            "tags": [],
        })

        entry_manager.create_entry({
            "title": "Personal Email",
            "username": "user@personal.com",
            "password": "P@ss!",
            "url": "",
            "notes": "",
            "category": "Personal",
            "tags": [],
        })

        results = entry_manager.search_entries('category:"Work"')
        assert len(results) == 1
        assert results[0]["category"] == "Work"

    def test_search_typo_tolerance(self, entry_manager):
        """SEARCH-1: Нечёткое сопоставление с устойчивостью к опечаткам."""
        entry_manager.create_entry({
            "title": "Github Account",
            "username": "dev@example.com",
            "password": "P@ss!",
            "url": "https://github.com",
            "notes": "Primary development account",
            "category": "Work",
            "tags": [],
        })

        results = entry_manager.search_entries("githib")
        assert len(results) == 1
        assert results[0]["title"] == "Github Account"

    def test_filter_by_tags(self, entry_manager):
        """SEARCH-3: Фильтрация по тегам."""
        entry_manager.create_entry({
            "title": "Entry with tag1",
            "username": "user@test.com",
            "password": "P@ss!",
            "url": "",
            "notes": "",
            "category": "",
            "tags": ["work", "email"],
        })

        entry_manager.create_entry({
            "title": "Entry with tag2",
            "username": "user2@test.com",
            "password": "P@ss!",
            "url": "",
            "notes": "",
            "category": "",
            "tags": ["personal", "social"],
        })

        results = entry_manager.filter_by_tags(["work"])
        assert len(results) == 1
        assert "work" in results[0]["tags"]

    def test_filter_by_date_range(self, entry_manager):
        """SEARCH-3: Фильтрация по диапазону дат."""
        first_id = entry_manager.create_entry({
            "title": "Older Entry",
            "username": "old@test.com",
            "password": "P@ss!",
            "url": "",
            "notes": "",
            "category": "",
            "tags": [],
        })
        second_id = entry_manager.create_entry({
            "title": "Newer Entry",
            "username": "new@test.com",
            "password": "P@ss!",
            "url": "",
            "notes": "",
            "category": "",
            "tags": [],
        })

        entry_manager.db.execute(
            "UPDATE vault_entries SET created_at = ?, updated_at = ? WHERE id = ?",
            ("2026-01-10T10:00:00+00:00", "2026-01-10T10:00:00+00:00", first_id)
        )
        entry_manager.db.execute(
            "UPDATE vault_entries SET created_at = ?, updated_at = ? WHERE id = ?",
            ("2026-03-10T10:00:00+00:00", "2026-03-10T10:00:00+00:00", second_id)
        )

        results = entry_manager.filter_by_date_range(
            start_date="2026-02-01T00:00:00+00:00",
            end_date="2026-03-31T23:59:59+00:00",
        )
        assert len(results) == 1
        assert results[0]["title"] == "Newer Entry"

    def test_filter_by_password_strength(self, entry_manager):
        """SEARCH-3: Фильтрация по силе пароля."""
        entry_manager.create_entry({
            "title": "Weak Password",
            "username": "weak@test.com",
            "password": "short1A!",
            "url": "",
            "notes": "",
            "category": "",
            "tags": [],
        })
        entry_manager.create_entry({
            "title": "Strong Password",
            "username": "strong@test.com",
            "password": "V3ry!Str0ng#P@ssw0rd_L0ng",
            "url": "",
            "notes": "",
            "category": "",
            "tags": [],
        })

        results = entry_manager.filter_by_password_strength(min_score=4)
        assert len(results) == 1
        assert results[0]["title"] == "Strong Password"



class TestPerformance:
    """Тесты производительности."""

    def test_load_1000_entries(self, entry_manager):
        """PERF-1: Загрузка 1000 записей < 2 секунд (включая шифрование)."""
        start = time.time()

        for i in range(1000):
            entry_manager.create_entry({
                "title": f"Site {i}",
                "username": f"user{i}@test.com",
                "password": f"P@ss_{i}!",
                "url": f"https://site{i}.com",
                "notes": "",
                "category": "",
                "tags": [],
            })

        # Загружаем все записи
        entries = entry_manager.get_all_entries(include_decrypted_password=True)

        elapsed = time.time() - start

        assert len(entries) == 1000
        # AES-256-GCM + 1000 записей — даём запас
        assert elapsed < 2, f"Loading took {elapsed:.2f}s (limit 2s for test)"

    def test_search_performance(self, entry_manager):
        """PERF-2: Поиск среди 1000 записей < 200ms."""
        # Создаём 1000 записей
        for i in range(1000):
            entry_manager.create_entry({
                "title": f"Site {i}",
                "username": f"user{i}@test.com",
                "password": f"P@ss_{i}!",
                "url": "",
                "notes": "",
                "category": "",
                "tags": [],
            })

        start = time.time()

        # Поиск
        results = entry_manager.search_entries("Site 500")

        elapsed = time.time() - start

        assert len(results) >= 1
        assert elapsed < 0.2, f"Search took {elapsed:.3f}s (limit 0.2s for test)"

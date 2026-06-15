# CryptoSafeManager — Sprint Implementation Map

Этот файл показывает, где в проекте реализованы требования Sprint 1–8. Он нужен для защиты и быстрой навигации по коду.

## Sprint 1 — Foundation, Architecture, DB, GUI shell

**Цель:** модульная основа, SQLite, config, event system, GUI shell.

**Главные файлы:**

- `src/core/config.py` — централизованные настройки, путь к БД, security/clipboard/UI параметры.
- `src/core/events.py` — event bus для связи модулей без жесткой зависимости.
- `src/core/state_manager.py` — состояние сессии, lock/unlock, пользовательская активность.
- `src/core/crypto/abstract.py` — интерфейс сервиса шифрования.
- `src/core/crypto/placeholder.py` — Sprint 1 placeholder-сервис.
- `src/database/db.py` — SQLite schema, миграции, индексы, transactions, backup/recovery.
- `src/gui/main_window.py` — главное окно приложения.
- `src/gui/setup_wizard.py` — первый запуск и создание vault.
- `src/gui/settings_dialog.py` — настройки.
- `src/gui/widgets/password_entry.py`, `secure_table.py`, `audit_log_viewer.py` — переиспользуемые widgets.
- `tests/test_core.py`, `tests/test_integration.py` — базовые проверки.

## Sprint 2 — Master Password, Key Derivation, Session Security

**Цель:** мастер-пароль, Argon2id, PBKDF2-HMAC-SHA256, key cache, session management.

**Главные файлы:**

- `src/core/key_manager.py` — создание vault, unlock/lock, key derivation, смена мастер-пароля.
- `src/core/crypto/key_derivation.py` — Argon2id для auth hash и PBKDF2-HMAC-SHA256 для encryption key.
- `src/core/crypto/authentication.py` — strength validation, failed attempts, backoff, session timers.
- `src/core/crypto/key_storage.py` — secure in-memory cache и очистка ключей.
- `src/gui/dialogs/login_dialog.py` — вход по мастер-паролю.
- `src/gui/dialogs/change_password_dialog.py` — смена мастер-пароля.

**Что хранится:** мастер-пароль не хранится. В `key_store` лежат `auth_hash` и `enc_salt`; encryption key выводится на лету и хранится только в памяти во время разблокированной сессии.

## Sprint 3 — Vault CRUD, AES-256-GCM, Password Generator

**Цель:** реальные зашифрованные записи, CRUD, генератор паролей, поиск и фильтры.

**Главные файлы:**

- `src/core/vault/encryption_service.py` — AES-256-GCM, уникальный nonce, format `nonce || ciphertext || tag`.
- `src/core/vault/entry_manager.py` — create/read/update/delete/search/filter/restore.
- `src/core/vault/password_generator.py` — генератор через `secrets` и оценка сложности.
- `src/gui/dialogs/entry_dialog.py` — создание/редактирование записи.
- `src/gui/widgets/secure_table.py` — таблица vault entries с masked password и reveal.
- `src/gui/widgets/search_widget.py` — поиск и фильтры.
- `tests/test_sprint3.py` — AES-GCM и CRUD тесты.

## Sprint 4 — Secure Clipboard

**Цель:** secure clipboard, auto-clear, monitor, platform adapters, UI feedback.

**Главные файлы:**

- `src/core/clipboard/clipboard_service.py` — copy/clear, timer, observers, panic handling.
- `src/core/clipboard/platform_adapter.py` — Windows/macOS/Linux/fallback adapters.
- `src/core/clipboard/clipboard_monitor.py` — мониторинг изменений и suspicious activity.
- `src/gui/main_window.py` — кнопки copy username/password, статус буфера, preview.
- `tests/test_sprint4_*.py` — функциональные, security, resilience, performance проверки.

## Sprint 5 — Tamper-Evident Audit Log

**Цель:** audit log с подписью, hash chain, verification, export/reporting.

**Главные файлы:**

- `src/core/audit/audit_logger.py` — запись событий и управление audit flow.
- `src/core/audit/log_signer.py` — Ed25519/HMAC signatures и key separation.
- `src/core/audit/log_verifier.py` — проверка signature и hash chain.
- `src/core/audit/log_formatters.py` — JSON/CSV/PDF/CEF formatting.
- `src/core/audit/log_exporter.py`, `log_importer.py` — export/import audit logs.
- `src/gui/widgets/audit_log_viewer.py` — просмотр, фильтры, детали, verification status.
- `tests/test_sprint5_audit.py` — tamper detection, export, performance.

## Sprint 6 — Import/Export, Sharing, QR/Key Exchange

**Цель:** encrypted JSON/CSV/Bitwarden/LastPass, import validation, sharing, QR, key exchange.

**Главные файлы:**

- `src/core/import_export/exporter.py` — export vault data.
- `src/core/import_export/importer.py` — import, validation, dry-run, conflict handling.
- `src/core/import_export/sharing_service.py` — encrypted share packages.
- `src/core/import_export/key_exchange.py` — RSA/ECC key exchange, QR payloads, chunking, TTL/replay protection.
- `src/core/import_export/formats/` — native JSON, CSV, password-manager compatibility.
- `src/gui/dialogs/export_dialog.py`, `import_dialog.py`, `sharing_dialog.py`, `qr_dialog.py` — UI flows.
- `tests/test_sprint6_*.py` — database, export/import, sharing, formats, security, validation.

## Sprint 7 — Hardening, Auto-Lock, Tray, Panic Mode

**Цель:** side-channel protection, secure memory, activity monitor, panic mode, tray, profiles.

**Главные файлы:**

- `src/core/security/side_channel_protection.py` — constant-time comparison и defensive helpers.
- `src/core/security/memory_guard.py` — locked memory/zeroing/canary best-effort.
- `src/core/security/activity_monitor.py` — user activity и auto-lock.
- `src/core/security/panic_mode.py` — emergency lock/clear/stealth flow.
- `src/core/security/platform_security.py` — platform capabilities.
- `src/core/security/security_validator.py` — security profile validation.
- `src/gui/tray_manager.py` — system tray with fallback backend.
- `src/gui/ux.py` — shortcuts, theme, friendly errors.
- `tests/test_sprint7_security_framework.py` — Sprint 7 checks.

## Sprint 8 — Final Integration, Tests, Packaging, Documentation

**Цель:** единое приложение, тесты, coverage, PyInstaller, docs, cleanup.

**Главные файлы:**

- `run.py`, `main.py` — запуск приложения.
- `build.py` — PyInstaller build and ZIP packaging.
- `requirements.txt`, `requirements-win.txt`, `requirements-optional.txt` — зависимости.
- `INSTALL_WINDOWS.bat`, `RUN_WINDOWS.bat` — быстрый Windows запуск.
- `README.md` — overview, setup, tests, packaging.
- `docs/user_guide.md` — user guide.
- `docs/technical.md` — technical summary.
- `docs/sprint_implementation_map.md` — этот файл.
- `tests/report/summary.md` — тестовый отчет.

## Security notes for presentation

- Master password is never stored in plaintext.
- `key_store.auth_hash` stores Argon2id verification hash.
- `key_store.enc_salt` stores PBKDF2 salt.
- Vault encryption key is derived only after unlock and cached only in memory.
- Each vault entry is encrypted separately with AES-256-GCM and a unique 12-byte nonce.
- Audit log is tamper-evident via sequence numbers, previous hashes, entry hashes and signatures.
- Clipboard protection is best-effort because system clipboards are shared by design; the app mitigates exposure with auto-clear, warnings and panic/lock cleanup.

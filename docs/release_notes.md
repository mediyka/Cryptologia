# CryptoSafeManager — Final Release Notes

## Что было улучшено в финальной версии

- Новый интерфейс главного окна: hero header, security dashboard/sidebar, карточная рабочая область, обновленная toolbar-панель и более аккуратная таблица vault entries.
- Тёмная тема используется как современный default, при этом прежняя настройка темы сохраняется.
- Таблица получила более понятные колонки с иконками, увеличенную высоту строк, подсветку active clipboard entry и более читабельные действия.
- Добавлены `requirements-win.txt`, `requirements-optional.txt`, `INSTALL_WINDOWS.bat`, `RUN_WINDOWS.bat` для более понятного запуска на Windows.
- Из main requirements убраны heavy optional QR-scanning зависимости `opencv-python` и `pyzbar`; они перенесены в `requirements-optional.txt`.
- Усилена смена мастер-пароля: key rotation теперь прерывается, если не удалось перешифровать хотя бы одну запись. Это защищает от частичной потери vault data.
- AES-256-GCM теперь требует строго 32-byte key и не делает небезопасные pad/truncate операции.
- Проект очищен от IDE/cache мусора перед упаковкой.

## Проверки после правок

```text
PYTHONPATH=src python -m py_compile $(find src -name '*.py')
PYTHONPATH=src python -c 'import main; from gui.main_window import MainWindow; print("ok")'
PYTHONPATH=src pytest tests/test_core.py tests/test_sprint3.py -q
PYTHONPATH=src pytest tests/test_sprint7_security_framework.py -q
```

Локальные результаты в среде сборки:

```text
58 passed — core + Sprint 3
50 passed — Sprint 7 security framework
263 tests collected
```

Полный Sprint 8 отчет проекта остается в `tests/report/summary.md`.

## Windows Argon2 install fix

- `requirements.txt` and `requirements-win.txt` no longer force Argon2 during the basic Windows install.
- `KeyDerivationService` now uses Argon2id automatically when `argon2-cffi` is available.
- If `argon2-cffi` is unavailable, the app starts with a marked PBKDF2 authentication-hash fallback instead of crashing.
- `INSTALL_FULL_SECURITY_WINDOWS.bat` is provided for full Argon2id mode on Python 3.12/3.11.

# Test Report

Последний полный прогон, предоставленный разработчиком:

```text
Command: py -m pytest tests/ --cov=src
Result: 263 passed
Duration: 60.64 seconds
Coverage with Sprint 8 policy: 82.50%
```

Для финального Sprint 8 coverage считается по стабильному слою приложения (`src/core` и `src/database`).
Tkinter GUI исключен из автоматического coverage в `.coveragerc`, потому что требует интерактивной
среды и проверяется smoke/manual сценариями.

Финальную HTML-версию отчета нужно сгенерировать командой:

```bash
py -m pytest tests/ --cov=src --cov-report=term --cov-report=html:tests/report/html
```

Текущий критерий Sprint 8 выполнен: итоговый coverage по `.coveragerc` выше 80%.

Дополнительный артефакт для защиты Sprint 8: `docs/user_feedback.md`.
В нем нужно зафиксировать реальные отзывы 5 пользователей, краткое резюме фидбека и таблицу исправлений с указанием файлов/проверок.

Примечание: на Windows после завершения pytest может появиться `PermissionError` при удалении
`pytest-current` во временной папке. Это cleanup-сообщение pytest, тестовый прогон при этом завершается
с кодом `0`.

# Profile Admin

Локальная и серверная панель для пакетного управления профилями Vision с прокси IPRoyal, проверкой Scamalytics и заметками `email:code`.

## Быстрый старт

```powershell
.\admin_panel\start.ps1
```

Панель откроется на `http://127.0.0.1:8765/`. Проверка состояния сервера:

```powershell
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8765/healthz
```

## Документация

- [Handoff для следующего чата](docs/PROJECT_HANDOFF.md) — актуальные функции, решения, ограничения и следующие шаги.
- [Архитектура](docs/ARCHITECTURE.md) — модули, данные, статусы и потоки интеграций.
- [Панель](admin_panel/README.md) — импорт, управление профилями и локальная конфигурация.
- [Развертывание на VPS](deploy/README.md) — Docker и приватный доступ через Tailscale.

## Проверка проекта

```powershell
$py = 'C:\Users\Alex\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
& $py -m py_compile admin_panel\app.py admin_panel\core.py admin_panel\integrations.py admin_panel\jobs.py
node --check admin_panel\static\app.js
& $py -m unittest discover -s tests
```

На момент последнего handoff проходят `45` тестов.

## Секреты

Локальные `.env.local`, `.new-api.env.local`, `.octo.env.local`, внешние IPRoyal `.env`, серверный `.env.server`, SQLite и содержимое `outputs/` исключены из проекта. Не вставляйте их в документацию, коммиты или новый чат.


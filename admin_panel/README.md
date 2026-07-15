# Profile Admin Panel

Локальная панель для пакетного импорта email и создания профилей Vision с прокси IPRoyal и проверкой Scamalytics.

Полный контекст проекта:

- [`../docs/PROJECT_HANDOFF.md`](../docs/PROJECT_HANDOFF.md)
- [`../docs/ARCHITECTURE.md`](../docs/ARCHITECTURE.md)

Запуск: `admin_panel\start.ps1`. Панель открывается на `http://127.0.0.1:8765/`.

Форматы импорта:

```text
email@icloud.com
email@icloud.com:code
email@icloud.com:code,mz
newTry[16] email@icloud.com:code,mz
```

База данных хранится в `admin_panel/data/profiles.sqlite3`. Существующие строки из `outputs/vision_notes.txt` импортируются один раз, если база пуста.

Vision-профили используют имя `newTry[N] Country`. Проверка статусов читает наличие профиля и назначенный прокси без раскрытия пароля. Синхронизация отправляет измененные имена и заметки `email:code`, затем обновляет состояние.

Редактор изменяет имя, email, код, страну и ОС до создания. Созданные профили после локальных изменений получают `pending_sync`. Есть одиночные и массовые действия, удаление из Vision, локальная корзина, восстановление, TOTP и смена прокси.

Прокси принимается только при fraud score ниже `25`. После score выполняется короткая проверка доступности и неизменности выходного IP. После пяти неподходящих кандидатов операция останавливается.

В таблице полный прокси не показывается. Кнопка копирования получает credentials с паролем из Vision только по явному нажатию.

Локальные Vision credentials загружаются из ignored-файла `.env.local`, Scamalytics из `.new-api.env.local`, а IPRoyal по умолчанию из `C:\Users\Alex\Documents\proxy\.env`. Сервер использует `.env.server`. Значения не возвращаются списочными API.

Значение `code` намеренно записывается в Vision notes. Workspace и backups являются чувствительными. Non-loopback binding отклоняется без `ADMIN_USER` и `ADMIN_PASSWORD`.

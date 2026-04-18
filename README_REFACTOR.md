# Refactored structure for the diploma verification service

## Что изменилось

Старый `main.py` разделён на:
- `app/routes/*` — Flask routes / blueprints
- `app/services/*` — бизнес-логика
- `app/repositories/*` — SQL и доступ к данным
- `app/db.py` — подключение к БД и миграции SQLite
- `scripts/generate_keys.py` — генерация ключей
- `scripts/university_admin.py` — консольная админка
- `run.py` — новая точка входа

## Как запускать

1. Положите рядом ваши существующие папки:
   - `database/`
   - `templates/`
   - `keys/` (если есть)
   - `suspicious_reports.log` (если нужен)

2. Установите зависимости:
   ```bash
   pip install -r requirements.txt
   ```

3. Запустите:
   ```bash
   python run.py
   ```

## Что осталось совместимым

- URL сохранены
- JSON-ответы сохранены максимально близко к старым
- текущие шаблоны `dashboard.html`, `index.html`, `student.html`, `university.html` можно использовать без изменений

## Что исправлено по пути

- убран дублирующийся `@app.route('/api/generate_qr', methods=['POST'])`
- генерация RSA-ключей вынесена в общий сервис
- `generate_student_secrets()` больше не падает из-за несуществующей переменной `university_code`

## Что стоит сделать следующим шагом

- добавить тесты
- вынести SQL в единый слой репозиториев полностью
- перевести suspicious reports из файла в таблицу БД
- убрать приватные ключи из папки проекта в безопасное хранилище
- перевести SQLite на PostgreSQL для production

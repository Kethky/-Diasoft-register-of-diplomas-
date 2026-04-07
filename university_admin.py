"""
Утилита для управления ВУЗами и просмотра логов безопасности
Консольное приложение с меню:
1. Добавить вуз
2. Удалить вуз
3. Просмотреть список вузов
4. Просмотреть логи безопасности
5. Просмотреть логи проверок дипломов
6. Выход
"""

import sqlite3
import bcrypt
import secrets
import string
import re
import os
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "database", "diploma_platform.db")
SUSPICIOUS_REPORTS_LOG = os.path.join(os.path.dirname(__file__), "suspicious_reports.log")

# ---------- Вспомогательные функции ----------
def show_suspicious_reports(limit: int = 50):
    """Показывает сообщения из suspicious_reports.log"""
    if not os.path.exists(SUSPICIOUS_REPORTS_LOG):
        print("\nФайл suspicious_reports.log не найден.")
        return

    with open(SUSPICIOUS_REPORTS_LOG, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    if not lines:
        print("\nФайл suspicious_reports.log пуст.")
        return

    print("\n" + "=" * 90)
    print("ПОДОЗРИТЕЛЬНЫЕ СООБЩЕНИЯ ИЗ suspicious_reports.log")
    print("=" * 90)

    for idx, line in enumerate(lines[-limit:], start=1):
        print(f"{idx}. {line}")

    print("=" * 90)

def transliterate(text: str) -> str:
    """Простая транслитерация кириллицы в латиницу"""
    cyrillic = 'абвгдеёжзийклмнопрстуфхцчшщъыьэюя'
    latin = [
        'a', 'b', 'v', 'g', 'd', 'e', 'e', 'zh', 'z', 'i', 'y', 'k', 'l', 'm',
        'n', 'o', 'p', 'r', 's', 't', 'u', 'f', 'kh', 'ts', 'ch', 'sh', 'shch',
        '', 'y', '', 'e', 'yu', 'ya'
    ]
    trans_dict = {ord(c): l for c, l in zip(cyrillic + cyrillic.upper(),
                                            latin + [x.upper() for x in latin])}
    return text.translate(trans_dict).replace(' ', '_').lower()


def generate_login_from_name(university_name: str, existing_logins: set) -> str:
    """Генерирует логин из названия вуза: берёт первое слово до пробела"""
    first_word = university_name.split()[0] if university_name.split() else university_name
    base = transliterate(first_word)
    base = re.sub(r'[^a-z0-9]', '', base)
    if not base:
        base = "university"
    login = base
    counter = 1
    while login in existing_logins:
        login = f"{base}{counter}"
        counter += 1
    return login


def generate_password() -> str:
    """Генерирует криптостойкий пароль длиной 12-16 символов"""
    length = secrets.randbelow(5) + 12
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special = "!@#$%^&*"
    password_chars = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(special),
    ]
    all_chars = lowercase + uppercase + digits + special
    for _ in range(length - 4):
        password_chars.append(secrets.choice(all_chars))
    secrets.SystemRandom().shuffle(password_chars)
    return ''.join(password_chars)


def hash_password(password: str) -> str:
    """Хеширует пароль с помощью bcrypt"""
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed.decode('utf-8')


def get_next_university_code(conn) -> int:
    """Возвращает следующий свободный university_code (начинается с 1)"""
    cursor = conn.cursor()
    cursor.execute("SELECT MAX(university_code) FROM universities")
    max_code = cursor.fetchone()[0]
    return 1 if max_code is None else max_code + 1


def list_universities(conn):
    """Выводит список всех вузов (код, название, логин)"""
    cursor = conn.cursor()
    cursor.execute("SELECT university_code, name, login FROM universities ORDER BY university_code")
    rows = cursor.fetchall()
    if not rows:
        print("\nСписок вузов пуст.")
        return
    print("\n" + "=" * 70)
    print(f"{'Код':<6} {'Название':<40} {'Логин':<20}")
    print("=" * 70)
    for code, name, login in rows:
        name_short = (name[:37] + '...') if len(name) > 40 else name
        print(f"{code:<6} {name_short:<40} {login:<20}")
    print("=" * 70)


def view_security_logs(conn):
    """Просмотр логов безопасности (security_logs)"""
    cursor = conn.cursor()
    cursor.execute('''
        SELECT id, ip, endpoint, user_agent, timestamp
        FROM security_logs
        ORDER BY timestamp DESC
        LIMIT 50
    ''')
    rows = cursor.fetchall()
    if not rows:
        print("\nЛоги безопасности пусты.")
        return
    print("\n" + "=" * 100)
    print(f"{'ID':<5} {'IP':<16} {'Endpoint':<35} {'User-Agent':<30} {'Время':<20}")
    print("=" * 100)
    for row in rows:
        id, ip, endpoint, ua, ts = row
        ua_short = (ua[:27] + '...') if len(ua) > 30 else ua
        print(f"{id:<5} {ip:<16} {endpoint:<35} {ua_short:<30} {ts:<20}")
    print("=" * 100)


def view_verification_logs(conn):
    """Просмотр логов проверок дипломов (verification_logs)"""
    cursor = conn.cursor()
    # Проверяем, существует ли таблица verification_logs
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='verification_logs'")
    if not cursor.fetchone():
        print("\nТаблица verification_logs не найдена. Сначала добавьте логирование в main.py.")
        return

    cursor.execute('''
        SELECT id, diploma_number, verification_type, ip, user_agent, result, timestamp
        FROM verification_logs
        ORDER BY timestamp DESC
        LIMIT 50
    ''')
    rows = cursor.fetchall()
    if not rows:
        print("\nЛоги проверок дипломов пусты.")
        return
    print("\n" + "=" * 120)
    print(f"{'ID':<5} {'Диплом':<15} {'Тип':<12} {'IP':<16} {'User-Agent':<25} {'Результат':<15} {'Время':<20}")
    print("=" * 120)
    for row in rows:
        id, diploma_num, v_type, ip, ua, result, ts = row
        ua_short = (ua[:22] + '...') if len(ua) > 25 else ua
        diploma_short = (diploma_num[:12] + '...') if len(diploma_num) > 15 else diploma_num
        print(f"{id:<5} {diploma_short:<15} {v_type:<12} {ip:<16} {ua_short:<25} {result:<15} {ts:<20}")
    print("=" * 120)


# ---------- Основные операции ----------
def add_university():
    """Добавляет новый вуз с генерацией кода, логина и пароля"""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    name = input("\nВведите полное название ВУЗа: ").strip()
    if not name:
        print("Название не может быть пустым.")
        conn.close()
        return

    cursor.execute("SELECT id FROM universities WHERE name = ?", (name,))
    if cursor.fetchone():
        print(f"ВУЗ с названием '{name}' уже существует.")
        conn.close()
        return

    cursor.execute("SELECT login FROM universities")
    existing_logins = {row[0] for row in cursor.fetchall()}

    university_code = get_next_university_code(conn)
    login = generate_login_from_name(name, existing_logins)
    plain_password = generate_password()
    password_hash = hash_password(plain_password)

    try:
        cursor.execute('''
            INSERT INTO universities (university_code, name, login, password_hash)
            VALUES (?, ?, ?, ?)
        ''', (university_code, name, login, password_hash))
        conn.commit()
        print(f"\nВУЗ успешно добавлен!")
        print(f"   Код вуза: {university_code}")
        print(f"   Логин: {login}")
        print(f"   Пароль (сохраните!): {plain_password}")
        print("   (пароль больше не будет показан)\n")
    except sqlite3.IntegrityError as e:
        print(f"Ошибка при добавлении: {e}")
    finally:
        conn.close()


def delete_university():
    """Удаляет вуз по его коду (каскадно удалятся и дипломы)"""
    conn = sqlite3.connect(DB_PATH)
    list_universities(conn)
    try:
        code = int(input("\nВведите код вуза для удаления: ").strip())
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM universities WHERE university_code = ?", (code,))
        row = cursor.fetchone()
        if not row:
            print(f"Вуз с кодом {code} не найден.")
            conn.close()
            return
        name = row[0]
        confirm = input(
            f"Вы действительно хотите удалить вуз '{name}' (код {code})? Все его дипломы также будут удалены. (Y/N): ").strip().lower()
        if confirm == 'y':
            cursor.execute("DELETE FROM universities WHERE university_code = ?", (code,))
            conn.commit()
            print(f"Вуз '{name}' удалён.")
        else:
            print("Удаление отменено.")
    except ValueError:
        print("Ошибка: код должен быть числом.")
    finally:
        conn.close()


def show_universities():
    """Показывает список вузов"""
    conn = sqlite3.connect(DB_PATH)
    list_universities(conn)
    conn.close()


def show_security_logs():
    """Показывает логи безопасности"""
    conn = sqlite3.connect(DB_PATH)
    view_security_logs(conn)
    conn.close()


def show_verification_logs():
    """Показывает логи проверок дипломов"""
    conn = sqlite3.connect(DB_PATH)
    view_verification_logs(conn)
    conn.close()

def generate_student_secrets():
    """Создаёт коды доступа для дипломов, у которых ещё нет student_secret_hash"""
    if not os.path.exists(DB_PATH):
        print(f"\nФайл базы данных не найден: {DB_PATH}")
        print("Сначала создайте базу или проверьте путь.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id, diploma_number
        FROM diplomas
        WHERE student_secret_hash IS NULL OR student_secret_hash = ''
    """)
    rows = cursor.fetchall()

    if not rows:
        print("\nВсе дипломы уже имеют коды доступа.")
        conn.close()
        return

    for diploma_id, diploma_number in rows:
        secret = secrets.token_urlsafe(12)
        secret_hash = hash_password(secret)
        cursor.execute(
            "UPDATE diplomas SET student_secret_hash = ? WHERE id = ?",
            (secret_hash, diploma_id)
        )
        print(f"{university_code} - {diploma_number}: {secret}")

    conn.commit()
    conn.close()
    print("\nКоды доступа успешно созданы.")

def reset_student_secret():
    """Перевыпускает код доступа для одного диплома"""
    if not os.path.exists(DB_PATH):
        print(f"\nФайл базы данных не найден: {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        university_code = input("\nВведите код ВУЗа: ").strip()
        diploma_number = input("Введите номер диплома: ").strip()

        if not university_code or not diploma_number:
            print("Код ВУЗа и номер диплома обязательны.")
            conn.close()
            return

        try:
            university_code = int(university_code)
        except ValueError:
            print("Код ВУЗа должен быть числом.")
            conn.close()
            return

        cursor.execute("""
            SELECT id, full_name
            FROM diplomas
            WHERE university_code = ? AND diploma_number = ?
        """, (university_code, diploma_number))
        row = cursor.fetchone()

        if not row:
            print("Диплом не найден.")
            conn.close()
            return

        diploma_id, full_name = row

        new_secret = secrets.token_urlsafe(12)
        new_secret_hash = hash_password(new_secret)

        cursor.execute("""
            UPDATE diplomas
            SET student_secret_hash = ?
            WHERE id = ?
        """, (new_secret_hash, diploma_id))

        conn.commit()

        print("\nКод доступа успешно перевыпущен.")
        print(f"Студент: {full_name}")
        print(f"Номер диплома: {diploma_number}")
        print(f"Новый код доступа: {new_secret}")
        print("Сохраните его сразу: повторно старый код показать нельзя.")

    except Exception as e:
        print(f"Ошибка при перевыпуске кода: {e}")
    finally:
        conn.close()
# ---------- Главное меню ----------
def main():
    # Проверка существования таблиц
    show_suspicious_reports()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='universities'")
    if not cursor.fetchone():
        print("Таблицы не найдены. Запустите сначала CREATEBD.py для создания базы данных.")
        conn.close()
        return
    conn.close()

    while True:
        print("\n" + "=" * 40)
        print("УПРАВЛЕНИЕ ВУЗАМИ И ПРОСМОТР ЛОГОВ")
        print("=" * 40)
        print("1. Добавить вуз")
        print("2. Удалить вуз")
        print("3. Список вузов")
        print("4. Логи безопасности (security_logs)")
        print("5. Логи проверок дипломов (verification_logs)")
        print("6. Создание кода для входа студентам.")
        print("7. Пересоздание кода для входа студентам.")
        print("8. Выход")
        choice = input("\nВыберите действие (1-8): ").strip()

        if choice == '1':
            add_university()
        elif choice == '2':
            delete_university()
        elif choice == '3':
            show_universities()
        elif choice == '4':
            show_security_logs()
        elif choice == '5':
            show_verification_logs()
        elif choice == '6':
            generate_student_secrets()
        elif choice == '7':
            reset_student_secret()
        elif choice == '8':
            print("Выход из программы.")
            break
        else:
            print("Неверный ввод. Попробуйте снова.")


if __name__ == "__main__":
    main()

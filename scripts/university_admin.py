from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from app.services.admin_service import (
    add_university,
    delete_university,
    generate_student_secrets,
    get_security_logs,
    get_universities,
    get_verification_logs,
    reset_student_secret,
    show_suspicious_reports,
)


def print_universities():
    rows = get_universities()
    if not rows:
        print("\nСписок вузов пуст.")
        return

    print("\n" + "=" * 70)
    print(f"{'Код':<6} {'Название':<40} {'Логин':<20}")
    print("=" * 70)
    for row in rows:
        name = row["name"]
        name_short = (name[:37] + "...") if len(name) > 40 else name
        print(f"{row['university_code']:<6} {name_short:<40} {row['login']:<20}")
    print("=" * 70)


def print_security_logs():
    rows = get_security_logs()
    if not rows:
        print("\nЛоги безопасности пусты.")
        return

    print("\n" + "=" * 100)
    print(f"{'ID':<5} {'IP':<16} {'Endpoint':<35} {'User-Agent':<30} {'Время':<20}")
    print("=" * 100)
    for row in rows:
        ua = row["user_agent"] or ""
        ua_short = (ua[:27] + "...") if len(ua) > 30 else ua
        print(f"{row['id']:<5} {row['ip']:<16} {row['endpoint']:<35} {ua_short:<30} {row['timestamp']:<20}")
    print("=" * 100)


def print_verification_logs():
    rows = get_verification_logs()
    if not rows:
        print("\nЛоги проверок дипломов пусты.")
        return

    print("\n" + "=" * 120)
    print(f"{'ID':<5} {'Диплом':<15} {'Тип':<12} {'IP':<16} {'User-Agent':<25} {'Результат':<15} {'Время':<20}")
    print("=" * 120)
    for row in rows:
        ua = row["user_agent"] or ""
        diploma_num = row["diploma_number"] or ""
        ua_short = (ua[:22] + "...") if len(ua) > 25 else ua
        diploma_short = (diploma_num[:12] + "...") if len(diploma_num) > 15 else diploma_num
        print(
            f"{row['id']:<5} {diploma_short:<15} {row['verification_type']:<12} "
            f"{row['ip']:<16} {ua_short:<25} {row['result']:<15} {row['timestamp']:<20}"
        )
    print("=" * 120)


def print_suspicious_reports():
    rows = show_suspicious_reports()
    if not rows:
        print("\nФайл suspicious_reports.log пуст или не найден.")
        return

    print("\n" + "=" * 90)
    print("ПОДОЗРИТЕЛЬНЫЕ СООБЩЕНИЯ ИЗ suspicious_reports.log")
    print("=" * 90)
    for index, line in enumerate(rows, start=1):
        print(f"{index}. {line}")
    print("=" * 90)


def main():
    app = create_app()
    with app.app_context():
        print_suspicious_reports()

        while True:
            print("\n" + "=" * 44)
            print("УПРАВЛЕНИЕ ВУЗАМИ И ПРОСМОТР ЛОГОВ")
            print("=" * 44)
            print("1. Добавить вуз")
            print("2. Удалить вуз")
            print("3. Список вузов")
            print("4. Логи безопасности (security_logs)")
            print("5. Логи проверок дипломов (verification_logs)")
            print("6. Создать коды для входа студентам")
            print("7. Пересоздать код для одного студента")
            print("8. Выход")
            choice = input("\nВыберите действие (1-8): ").strip()

            if choice == "1":
                name = input("\nВведите полное название ВУЗа: ").strip()
                try:
                    result = add_university(name)
                    print("\nВУЗ успешно добавлен!")
                    print(f"   Код вуза: {result['university_code']}")
                    print(f"   Логин: {result['login']}")
                    print(f"   Пароль (сохраните!): {result['password']}")
                    print("   (пароль больше не будет показан)\n")
                except Exception as error:
                    print(f"Ошибка при добавлении: {error}")

            elif choice == "2":
                print_universities()
                try:
                    code = int(input("\nВведите код вуза для удаления: ").strip())
                    university = delete_university(code)
                    if not university:
                        print(f"Вуз с кодом {code} не найден.")
                        continue
                    print(f"Вуз '{university['name']}' удалён.")
                except ValueError:
                    print("Ошибка: код должен быть числом.")

            elif choice == "3":
                print_universities()

            elif choice == "4":
                print_security_logs()

            elif choice == "5":
                print_verification_logs()

            elif choice == "6":
                secrets_list = generate_student_secrets()
                if not secrets_list:
                    print("\nВсе дипломы уже имеют коды доступа.")
                    continue

                print("\nКоды доступа успешно созданы:")
                for item in secrets_list:
                    print(
                        f"{item['university_code']} - {item['diploma_number']}: {item['student_secret']}"
                    )

            elif choice == "7":
                try:
                    university_code = int(input("\nВведите код ВУЗа: ").strip())
                    diploma_number = input("Введите номер диплома: ").strip()
                    result = reset_student_secret(university_code, diploma_number)
                    if not result:
                        print("Диплом не найден.")
                        continue

                    print("\nКод доступа успешно перевыпущен.")
                    print(f"Студент: {result['full_name']}")
                    print(f"Номер диплома: {result['diploma_number']}")
                    print(f"Новый код доступа: {result['student_secret']}")
                except ValueError:
                    print("Код ВУЗа должен быть числом.")
                except Exception as error:
                    print(f"Ошибка при перевыпуске кода: {error}")

            elif choice == "8":
                print("Выход из программы.")
                break

            else:
                print("Неверный ввод. Попробуйте снова.")


if __name__ == "__main__":
    main()

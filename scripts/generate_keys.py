from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from app import create_app
from app.services.crypto_service import generate_keys_for_all_universities


def main():
    app = create_app()
    with app.app_context():
        created_for = generate_keys_for_all_universities()
        if not created_for:
            print("❌ В базе нет ни одного ВУЗа. Сначала добавьте ВУЗ.")
            return

        for code in created_for:
            print(f"✅ Ключи для ВУЗа {code} созданы или уже существуют.")
        print("🎉 Генерация ключей завершена.")


if __name__ == "__main__":
    main()

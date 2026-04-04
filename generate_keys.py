import sqlite3
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

DB_PATH = "database/diploma_platform.db"


def generate_keys_for_university(university_code):
    """Генерирует RSA ключи для указанного ВУЗа"""
    keys_dir = f"keys/university_{university_code}"
    os.makedirs(keys_dir, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    with open(f"{keys_dir}/private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    public_key = private_key.public_key()
    with open(f"{keys_dir}/public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"✅ Ключи для ВУЗа {university_code} созданы в {keys_dir}")


def main():
    if not os.path.exists(DB_PATH):
        print("❌ База данных не найдена. Сначала запустите main.py или CREATEBD.py")
        return
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT university_code FROM universities")
    rows = cursor.fetchall()
    conn.close()
    if not rows:
        print("❌ В базе нет ни одного ВУЗа. Сначала добавьте ВУЗ через ADDVUZ.py или интерфейс.")
        return
    for (code,) in rows:
        generate_keys_for_university(code)
    print("🎉 Генерация ключей завершена.")


if __name__ == "__main__":
    main()
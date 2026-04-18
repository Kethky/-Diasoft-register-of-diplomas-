import sqlite3
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database", "diploma_platform.db")

print("Путь к БД:", DB_PATH)
print("Файл существует:", os.path.exists(DB_PATH))

conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()

cur.execute("SELECT COUNT(*) FROM diplomas;")
print("Дипломов:", cur.fetchone()[0])

cur.execute("SELECT COUNT(*) FROM universities;")
print("ВУЗов:", cur.fetchone()[0])

cur.execute("""
SELECT COUNT(*)
FROM diplomas d
LEFT JOIN universities u ON d.university_code = u.university_code
WHERE u.university_code IS NULL;
""")
print("Дипломов без связанного ВУЗа:", cur.fetchone()[0])

conn.close()
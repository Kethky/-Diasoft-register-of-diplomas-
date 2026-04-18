import sqlite3

from flask import current_app


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(current_app.config["DB_PATH"])
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def create_security_tables() -> None:
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS blocked_ips (
            ip TEXT PRIMARY KEY,
            reason TEXT,
            blocked_until TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS security_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            endpoint TEXT,
            user_agent TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS verification_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            diploma_id INTEGER,
            university_code INTEGER,
            diploma_number TEXT,
            verification_type TEXT,
            token TEXT,
            ip TEXT,
            user_agent TEXT,
            result TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS hr_verification_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            verification_mode TEXT,
            input_source TEXT,
            university_code INTEGER,
            university_name TEXT,
            diploma_number TEXT,
            requested_full_name TEXT,
            matched_full_name TEXT,
            requested_graduation_year INTEGER,
            matched_graduation_year INTEGER,
            requested_specialty TEXT,
            matched_specialty TEXT,
            status TEXT,
            trust_level TEXT,
            trust_label TEXT,
            signature_valid INTEGER,
            fields_match_status TEXT,
            details_json TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    conn.commit()
    conn.close()


def update_db_schema() -> None:
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("PRAGMA table_info(diplomas)")
    columns = {col[1] for col in cursor.fetchall()}

    migrations = [
        ("active_token", "ALTER TABLE diplomas ADD COLUMN active_token TEXT"),
        ("hash_combined", "ALTER TABLE diplomas ADD COLUMN hash_combined TEXT"),
        ("digital_signature", "ALTER TABLE diplomas ADD COLUMN digital_signature TEXT"),
        (
            "signature_created_at",
            "ALTER TABLE diplomas ADD COLUMN signature_created_at TIMESTAMP",
        ),
        (
            "student_secret_hash",
            "ALTER TABLE diplomas ADD COLUMN student_secret_hash TEXT",
        ),
        (
            "active_token_expires_at",
            "ALTER TABLE diplomas ADD COLUMN active_token_expires_at TIMESTAMP",
        ),
    ]

    for column_name, sql in migrations:
        if column_name not in columns:
            cursor.execute(sql)
            conn.commit()

    conn.close()

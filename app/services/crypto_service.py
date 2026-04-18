import base64
import hashlib
import os
import secrets
from pathlib import Path

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from flask import current_app

from app.repositories.university_repository import get_all_university_codes


def _keys_dir(university_code: int) -> Path:
    return Path(current_app.config["KEYS_DIR"]) / f"university_{university_code}"


def generate_keys_for_university(university_code: int) -> bool:
    keys_dir = _keys_dir(university_code)
    keys_dir.mkdir(parents=True, exist_ok=True)

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend(),
    )

    private_path = keys_dir / "private_key.pem"
    public_path = keys_dir / "public_key.pem"

    with private_path.open("wb") as file_obj:
        file_obj.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    public_key = private_key.public_key()
    with public_path.open("wb") as file_obj:
        file_obj.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    return True


def ensure_university_keys(university_code: int) -> bool:
    keys_dir = _keys_dir(university_code)
    private_path = keys_dir / "private_key.pem"
    public_path = keys_dir / "public_key.pem"

    if private_path.exists() and public_path.exists():
        return True

    return generate_keys_for_university(university_code)


def generate_keys_for_all_universities():
    created_for = []
    for code in get_all_university_codes():
        ensure_university_keys(code)
        created_for.append(code)
    return created_for


def calculate_diploma_hash(
    university_code: int,
    diploma_number: str,
    full_name: str,
    graduation_year: int,
    specialty: str,
    salt: str | None = None,
) -> tuple[str, str]:
    if salt is None:
        salt = secrets.token_hex(32)

    raw_data = (
        f"{university_code}|{diploma_number}|{full_name}|{graduation_year}|{specialty}|{salt}"
    )
    hash_combined = hashlib.sha256(raw_data.encode()).hexdigest()
    return hash_combined, salt


def _build_signature_string(diploma_data: dict) -> str:
    return (
        f"{diploma_data['university_code']}|"
        f"{diploma_data['diploma_number']}|"
        f"{diploma_data['full_name']}|"
        f"{diploma_data['graduation_year']}|"
        f"{diploma_data['specialty']}"
    )


def sign_diploma(university_code: int, diploma_data: dict) -> str:
    ensure_university_keys(university_code)
    sign_string = _build_signature_string(diploma_data)
    private_path = _keys_dir(university_code) / "private_key.pem"

    with private_path.open("rb") as file_obj:
        private_key = load_pem_private_key(file_obj.read(), password=None)

    signature = private_key.sign(
        sign_string.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

    return base64.b64encode(signature).decode()


def verify_diploma_signature(university_code: int, diploma_data: dict, signature_b64: str) -> bool:
    sign_string = _build_signature_string(diploma_data)
    public_path = _keys_dir(university_code) / "public_key.pem"

    if not public_path.exists():
        return False

    with public_path.open("rb") as file_obj:
        public_key = load_pem_public_key(file_obj.read())

    try:
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            sign_string.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except Exception:
        return False

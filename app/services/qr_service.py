import base64
import hashlib
import hmac
import io
import os
import tempfile
import time
from urllib.parse import parse_qs, urlencode, urlparse

import cv2
import qrcode
from itsdangerous import BadSignature
from flask import current_app

from app.repositories.diploma_repository import (
    get_active_token,
    get_active_token_by_params,
    set_active_token,
)
from app.services.security_service import get_serializer



def generate_qr_base64(url: str) -> str:
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=10,
        border=4,
    )
    qr.add_data(url)
    qr.make(fit=True)

    img = qr.make_image(fill_color='black', back_color='white').convert('RGB')
    buffered = io.BytesIO()
    img.save(buffered, format='PNG')

    return base64.b64encode(buffered.getvalue()).decode('utf-8')



def _qr_signing_key() -> bytes:
    secret = current_app.config['SECRET_KEY']
    salt = current_app.config.get('QR_SIGNING_SALT', 'diploma-qr-signature')
    return f'{secret}:{salt}'.encode('utf-8')



def sign_qr_payload(payload: dict) -> str:
    normalized = urlencode(sorted((str(k), str(v)) for k, v in payload.items() if v is not None))
    return hmac.new(_qr_signing_key(), normalized.encode('utf-8'), hashlib.sha256).hexdigest()



def verify_qr_payload(payload: dict, signature: str | None) -> bool:
    if not signature:
        return False
    expected = sign_qr_payload(payload)
    return hmac.compare_digest(expected, signature)



def build_temp_token(diploma_id: int, university_code, diploma_number: str, expiry_seconds: int):
    expiry_timestamp = int(time.time()) + expiry_seconds
    token = get_serializer().dumps(
        {
            'diploma_id': diploma_id,
            'university_code': university_code,
            'diploma_number': diploma_number,
            'expiry': expiry_timestamp,
        }
    )
    set_active_token(diploma_id, token, expiry_timestamp)
    signature = sign_qr_payload({'token': token})
    return token, expiry_timestamp, signature



def validate_temp_token(temp_token: str):
    token_data = get_serializer().loads(temp_token)
    expiry = token_data.get('expiry')
    diploma_id = token_data.get('diploma_id')
    university_code = token_data.get('university_code')
    diploma_number = token_data.get('diploma_number')

    if expiry is None:
        return {'ok': False, 'status_code': 400, 'payload': {'valid': False, 'expired': False, 'message': 'Некорректный токен'}}

    if time.time() > expiry:
        return {'ok': False, 'status_code': 410, 'payload': {'valid': False, 'expired': True, 'message': 'Срок действия ссылки истёк'}}

    active_token = get_active_token(diploma_id, university_code, diploma_number)
    if not active_token or active_token != temp_token:
        return {'ok': False, 'status_code': 410, 'payload': {'valid': False, 'expired': True, 'message': 'QR-код был отозван'}}

    return {
        'ok': True,
        'diploma_id': diploma_id,
        'university_code': university_code,
        'diploma_number': diploma_number,
        'expiry': expiry,
    }



def decode_qr_upload(file_storage):
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix='.png', delete=False) as tmp_file:
            file_storage.save(tmp_file.name)
            temp_path = tmp_file.name

        image = cv2.imread(temp_path)
        if image is None:
            return {'success': False, 'status_code': 400, 'message': 'Не удалось открыть изображение'}

        detector = cv2.QRCodeDetector()
        qr_data, points, _ = detector.detectAndDecode(image)

        if not qr_data:
            return {
                'success': False,
                'status_code': 400,
                'message': 'QR-код не найден или не удалось декодировать',
            }

        parsed = urlparse(qr_data)
        params = parse_qs(parsed.query)

        token = params.get('token', [None])[0]
        uni_code = params.get('uni_code', [None])[0]
        dip_num = params.get('dip_num', [None])[0]
        signature = params.get('sig', [None])[0]

        if token:
            if not verify_qr_payload({'token': token}, signature):
                return {'success': False, 'status_code': 400, 'message': 'Подпись QR-кода недействительна'}
            try:
                token_data = get_serializer().loads(token)
                expiry = token_data.get('expiry')
                diploma_id = token_data.get('diploma_id')
                university_code = token_data.get('university_code')
                diploma_number = token_data.get('diploma_number')

                if not university_code or not diploma_number:
                    return {'success': False, 'status_code': 400, 'message': 'Некорректный токен QR-кода'}

                if expiry and time.time() > expiry:
                    return {'success': False, 'status_code': 410, 'message': 'Срок действия ссылки истёк'}

                if diploma_id is not None:
                    active_token = get_active_token(diploma_id, university_code, diploma_number)
                else:
                    active_token = get_active_token_by_params(university_code, diploma_number)

                if not active_token:
                    return {'success': False, 'status_code': 404, 'message': 'Диплом по QR-коду не найден'}

                if active_token != token:
                    return {'success': False, 'status_code': 410, 'message': 'QR-код был отозван'}

                return {
                    'success': True,
                    'status_code': 200,
                    'university_code': str(university_code),
                    'diploma_number': str(diploma_number),
                    'temp_token': token,
                    'diploma_id': diploma_id,
                }
            except BadSignature:
                return {'success': False, 'status_code': 400, 'message': 'Недействительная ссылка'}

        if uni_code and dip_num:
            payload = {'uni_code': uni_code, 'dip_num': dip_num}
            if not verify_qr_payload(payload, signature):
                return {'success': False, 'status_code': 400, 'message': 'Подпись QR-кода недействительна'}
            return {
                'success': True,
                'status_code': 200,
                'university_code': str(uni_code),
                'diploma_number': str(dip_num),
            }

        return {'success': False, 'status_code': 400, 'message': 'QR-код не содержит данных о дипломе'}

    finally:
        if temp_path and os.path.exists(temp_path):
            os.remove(temp_path)

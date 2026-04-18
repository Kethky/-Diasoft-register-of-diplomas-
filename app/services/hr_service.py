import io
import os
import re
import secrets
from datetime import datetime
from typing import Any

import fitz
import pandas as pd
import pytesseract
from PIL import Image, ImageOps
from flask import current_app, session
from reportlab.lib.pagesizes import A4
from reportlab.lib.utils import simpleSplit
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas

from app.repositories.diploma_repository import (
    get_hr_diploma,
    get_hr_diploma_by_number,
    get_hr_diploma_by_university_name,
)
from app.repositories.hr_repository import (
    get_hr_history_item,
    insert_hr_history,
    list_hr_history,
)
from app.services.crypto_service import verify_diploma_signature


def get_hr_session_id() -> str:
    if not session.get("hr_session_id"):
        session["hr_session_id"] = secrets.token_urlsafe(16)
        session.modified = True
    return session["hr_session_id"]


def normalize_text(value: Any) -> str:
    return " ".join(str(value or "").strip().lower().split())


def _bool_label(value):
    if value is True:
        return "yes"
    if value is False:
        return "no"
    return "unknown"


def _build_indicators(status: str, signature_valid, field_matches: dict, mode: str):
    indicators = []

    if signature_valid is True:
        indicators.append({"key": "signature", "state": "success", "label": "Проверено по подписи вуза"})
    elif signature_valid is False:
        indicators.append({"key": "signature", "state": "warn", "label": "Подпись вуза не подтверждена"})
    else:
        indicators.append({"key": "signature", "state": "neutral", "label": "Подпись отсутствует"})

    provided = [k for k, v in field_matches.items() if v is not None]
    mismatches = [k for k, v in field_matches.items() if v is False]
    if provided and not mismatches:
        label = "Совпали все поля" if mode == "extended" else "Совпали все заполненные поля"
        indicators.append({"key": "fields", "state": "success", "label": label})
    elif mismatches:
        indicators.append({"key": "fields", "state": "warn", "label": "Есть расхождения"})
    else:
        indicators.append({"key": "fields", "state": "neutral", "label": "Сверка полей не выполнена"})

    if status == "valid":
        indicators.append({"key": "registry", "state": "success", "label": "Запись найдена в реестре"})
    elif status == "invalid":
        indicators.append({"key": "registry", "state": "warn", "label": "Диплом аннулирован"})
    elif status == "not_found":
        indicators.append({"key": "registry", "state": "warn", "label": "Запись не найдена в реестре"})
    else:
        indicators.append({"key": "registry", "state": "neutral", "label": "Требуется дополнительная проверка"})

    return indicators


def _trust_level(status: str, signature_valid, field_matches: dict):
    mismatches = any(v is False for v in field_matches.values())
    any_matches_checked = any(v is not None for v in field_matches.values())

    if status == "valid" and signature_valid is True and not mismatches and any_matches_checked:
        return "high", "Высокий уровень доверия"
    if status == "valid" and not mismatches:
        return "medium", "Средний уровень доверия"
    if status in {"invalid", "not_found", "discrepancy"} or mismatches:
        return "low", "Низкий уровень доверия"
    return "medium", "Требуется ручная проверка"


def verify_hr_diploma(
    university_code,
    diploma_number: str,
    full_name: str = "",
    graduation_year=None,
    specialty: str = "",
    verification_mode: str = "quick",
    input_source: str = "manual",
    save_history: bool = True,
):
    session_id = get_hr_session_id()
    diploma_number = str(diploma_number or "").strip()
    full_name = str(full_name or "").strip()
    specialty = str(specialty or "").strip()

    requested_year = None
    if graduation_year not in (None, ""):
        try:
            requested_year = int(graduation_year)
        except (TypeError, ValueError):
            requested_year = None

    result = {
        "verification_mode": verification_mode,
        "input_source": input_source,
        "verified_at": datetime.now().isoformat(timespec="seconds"),
        "university_code": university_code,
        "diploma_number": diploma_number,
        "requested": {
            "full_name": full_name,
            "graduation_year": requested_year,
            "specialty": specialty,
        },
    }

    row = None
    try:
        university_code_str = str(university_code or "").strip()
        if university_code_str and university_code_str.isdigit():
            row = get_hr_diploma(int(university_code_str), diploma_number)
        elif university_code_str:
            row = get_hr_diploma_by_university_name(university_code_str, diploma_number, full_name)
        else:
            row = get_hr_diploma_by_number(diploma_number, full_name)
    except Exception as exc:
        result.update(
            {
                "status": "error",
                "message": f"Ошибка проверки: {exc}",
                "trust_level": "low",
                "trust_label": "Ошибка проверки",
                "field_matches": {"full_name": None, "graduation_year": None, "specialty": None},
                "indicators": _build_indicators("error", None, {"full_name": None, "graduation_year": None, "specialty": None}, verification_mode),
            }
        )
        return result

    if not row:
        field_matches = {"full_name": None, "graduation_year": None, "specialty": None}
        trust_level, trust_label = _trust_level("not_found", None, field_matches)
        result.update(
            {
                "status": "not_found",
                "message": "Сведений не найдено",
                "university_name": None,
                "registry_found": False,
                "signature_valid": None,
                "field_matches": field_matches,
                "fields_match_status": "not_checked",
                "trust_level": trust_level,
                "trust_label": trust_label,
                "indicators": _build_indicators("not_found", None, field_matches, verification_mode),
                "matched": {},
            }
        )
        if save_history:
            history_id = insert_hr_history(
                session_id=session_id,
                verification_mode=verification_mode,
                input_source=input_source,
                university_code=university_code,
                university_name=None,
                diploma_number=diploma_number,
                requested_full_name=full_name,
                matched_full_name=None,
                requested_graduation_year=requested_year,
                matched_graduation_year=None,
                requested_specialty=specialty,
                matched_specialty=None,
                status=result["status"],
                trust_level=trust_level,
                trust_label=trust_label,
                signature_valid=None,
                fields_match_status="not_checked",
                details=result,
            )
            result["history_id"] = history_id
        return result

    field_matches = {
        "full_name": None,
        "graduation_year": None,
        "specialty": None,
    }

    if full_name:
        field_matches["full_name"] = normalize_text(full_name) == normalize_text(row.get("full_name"))
    if requested_year is not None:
        field_matches["graduation_year"] = requested_year == row.get("graduation_year")
    if specialty:
        field_matches["specialty"] = normalize_text(specialty) == normalize_text(row.get("specialty"))

    mismatches = [key for key, value in field_matches.items() if value is False]
    any_checked = any(value is not None for value in field_matches.values())
    if mismatches:
        fields_match_status = "mismatch"
    elif any_checked:
        fields_match_status = "all_match"
    else:
        fields_match_status = "not_checked"

    signature_valid = None
    if row.get("digital_signature"):
        diploma_data = {
            "university_code": row.get("university_code"),
            "diploma_number": row.get("diploma_number"),
            "full_name": row.get("full_name"),
            "graduation_year": row.get("graduation_year"),
            "specialty": row.get("specialty"),
        }
        signature_valid = verify_diploma_signature(row.get("university_code"), diploma_data, row.get("digital_signature"))

    if row.get("status") != 1:
        status = "invalid"
        message = "Диплом аннулирован"
    elif mismatches:
        status = "discrepancy"
        message = "Есть расхождения в переданных полях"
    else:
        status = "valid"
        message = "Подлинность подтверждена"

    trust_level, trust_label = _trust_level(status, signature_valid, field_matches)
    indicators = _build_indicators(status, signature_valid, field_matches, verification_mode)

    result.update(
        {
            "status": status,
            "message": message,
            "registry_found": True,
            "university_name": row.get("university_name"),
            "matched": {
                "full_name": row.get("full_name"),
                "graduation_year": row.get("graduation_year"),
                "specialty": row.get("specialty"),
            },
            "signature_valid": signature_valid,
            "signature_label": (
                "Проверено по подписи вуза"
                if signature_valid is True
                else "Подпись вуза не подтверждена"
                if signature_valid is False
                else "Подпись отсутствует"
            ),
            "field_matches": field_matches,
            "fields_match_status": fields_match_status,
            "trust_level": trust_level,
            "trust_label": trust_label,
            "indicators": indicators,
        }
    )

    if save_history:
        history_id = insert_hr_history(
            session_id=session_id,
            verification_mode=verification_mode,
            input_source=input_source,
            university_code=university_code,
            university_name=row.get("university_name"),
            diploma_number=diploma_number,
            requested_full_name=full_name,
            matched_full_name=row.get("full_name"),
            requested_graduation_year=requested_year,
            matched_graduation_year=row.get("graduation_year"),
            requested_specialty=specialty,
            matched_specialty=row.get("specialty"),
            status=status,
            trust_level=trust_level,
            trust_label=trust_label,
            signature_valid=signature_valid,
            fields_match_status=fields_match_status,
            details=result,
        )
        result["history_id"] = history_id

    return result


COLUMN_ALIASES = {
    "university_code": {"university_code", "код_вуза", "код вуза", "код", "uni_code"},
    "diploma_number": {"diploma_number", "номер_диплома", "номер диплома", "диплом", "diploma"},
    "full_name": {"full_name", "фио", "фио студента", "student_name", "name"},
    "graduation_year": {"graduation_year", "год выпуска", "year", "год"},
    "specialty": {"specialty", "специальность", "направление", "qualification"},
}


def _normalize_column_name(name: str) -> str:
    return normalize_text(name).replace("_", " ")




def _sample_non_empty(series, limit: int = 10):
    values = []
    for value in series.tolist():
        if pd.isna(value):
            continue
        text = str(value).strip()
        if not text:
            continue
        values.append(text)
        if len(values) >= limit:
            break
    return values


def _looks_like_university_code(values: list[str]) -> bool:
    if not values:
        return False
    good = sum(1 for value in values if re.fullmatch(r"\d{1,10}", value))
    return good >= max(1, len(values) // 2)


def _looks_like_diploma_number(values: list[str]) -> bool:
    if not values:
        return False
    good = 0
    for value in values:
        if any(pattern.search(value) for pattern in DIPLOMA_NUMBER_PATTERNS):
            good += 1
    return good >= max(1, len(values) // 2)


def _looks_like_full_name(values: list[str]) -> bool:
    if not values:
        return False
    good = 0
    for value in values:
        parts = [p for p in re.split(r"\s+", value) if p]
        if 2 <= len(parts) <= 4 and all(re.search(r"[A-Za-zА-Яа-яЁё]", p) for p in parts):
            good += 1
    return good >= max(1, len(values) // 2)


def _looks_like_year(values: list[str]) -> bool:
    if not values:
        return False
    good = sum(1 for value in values if re.fullmatch(r"(19|20)\d{2}", value))
    return good >= max(1, len(values) // 2)


def _guess_column_map(df):
    guessed = {}
    columns = list(df.columns)
    samples = {col: _sample_non_empty(df[col]) for col in columns}

    for col in columns:
        vals = samples[col]
        if _looks_like_diploma_number(vals) and 'diploma_number' not in guessed:
            guessed['diploma_number'] = col
    for col in columns:
        vals = samples[col]
        if col == guessed.get('diploma_number'):
            continue
        if _looks_like_university_code(vals) and 'university_code' not in guessed:
            guessed['university_code'] = col
    for col in columns:
        vals = samples[col]
        if col in guessed.values():
            continue
        if _looks_like_full_name(vals) and 'full_name' not in guessed:
            guessed['full_name'] = col
    for col in columns:
        vals = samples[col]
        if col in guessed.values():
            continue
        if _looks_like_year(vals) and 'graduation_year' not in guessed:
            guessed['graduation_year'] = col

    for col in columns:
        if col in guessed.values():
            continue
        if 'specialty' not in guessed:
            guessed['specialty'] = col

    return guessed


def parse_batch_verification_file(file_storage):
    filename = (file_storage.filename or "").lower()
    content = file_storage.read()
    if not content:
        raise ValueError("Файл пустой")

    if filename.endswith(".csv"):
        last_error = None
        for encoding in ["utf-8", "utf-8-sig", "cp1251", "windows-1251", "latin1"]:
            for sep in [",", ";", "\t", "|"]:
                try:
                    df = pd.read_csv(io.BytesIO(content), encoding=encoding, sep=sep)
                    if len(df.columns) >= 2:
                        break
                except Exception as exc:
                    last_error = exc
                    df = None
            if df is not None and len(df.columns) >= 2:
                break
        if df is None:
            raise ValueError(f"Не удалось прочитать CSV: {last_error}")
    elif filename.endswith(".xlsx") or filename.endswith(".xls"):
        df = pd.read_excel(io.BytesIO(content))
    else:
        raise ValueError("Поддерживаются только CSV/XLSX/XLS")

    if df is None or df.empty:
        raise ValueError("Файл не содержит данных")

    column_map = {}
    normalized_columns = {_normalize_column_name(col): col for col in df.columns}
    for target, aliases in COLUMN_ALIASES.items():
        for alias in aliases:
            if alias in normalized_columns:
                column_map[target] = normalized_columns[alias]
                break

    guessed_map = _guess_column_map(df)
    for key, value in guessed_map.items():
        column_map.setdefault(key, value)

    if "diploma_number" not in column_map:
        raise ValueError("Не удалось определить колонку с номером диплома")

    rows = []
    for _, record in df.iterrows():
        university_code = record.get(column_map.get("university_code")) if column_map.get("university_code") is not None else None
        diploma_number = record.get(column_map.get("diploma_number"))
        if pd.isna(diploma_number):
            continue

        row = {
            "university_code": "" if pd.isna(university_code) or university_code is None else str(university_code).strip(),
            "diploma_number": str(diploma_number).strip(),
            "full_name": "",
            "graduation_year": None,
            "specialty": "",
        }
        if column_map.get("full_name") is not None and pd.notna(record.get(column_map["full_name"])):
            row["full_name"] = str(record.get(column_map["full_name"])).strip()
        if column_map.get("graduation_year") is not None and pd.notna(record.get(column_map["graduation_year"])):
            row["graduation_year"] = record.get(column_map["graduation_year"])
        if column_map.get("specialty") is not None and pd.notna(record.get(column_map["specialty"])):
            row["specialty"] = str(record.get(column_map["specialty"])).strip()
        rows.append(row)

    return rows


def get_status_label(status: str) -> str:
    return {
        "valid": "Действителен",
        "invalid": "Аннулирован",
        "discrepancy": "Есть расхождения",
        "not_found": "Сведений не найдено",
        "error": "Ошибка проверки",
    }.get(status, status or "—")


def verify_batch_rows(rows: list[dict], verification_mode: str = "quick"):
    results = []
    valid_count = invalid_count = discrepancy_count = not_found_count = 0
    for item in rows:
        result = verify_hr_diploma(
            university_code=item.get("university_code"),
            diploma_number=item.get("diploma_number", ""),
            full_name=item.get("full_name", ""),
            graduation_year=item.get("graduation_year"),
            specialty=item.get("specialty", ""),
            verification_mode=verification_mode,
            input_source="batch",
            save_history=True,
        )
        result["status_label"] = get_status_label(result.get("status"))
        result["comment"] = ", ".join(ind.get("label") for ind in (result.get("indicators") or []))
        results.append(result)
        if result["status"] == "valid":
            valid_count += 1
        elif result["status"] == "invalid":
            invalid_count += 1
        elif result["status"] == "discrepancy":
            discrepancy_count += 1
        elif result["status"] == "not_found":
            not_found_count += 1

    return {
        "results": results,
        "total": len(results),
        "valid_count": valid_count,
        "invalid_count": invalid_count,
        "discrepancy_count": discrepancy_count,
        "not_found_count": not_found_count,
        "verified_at": datetime.now().isoformat(timespec="seconds"),
    }


NAME_RE = re.compile(r"\b[А-ЯЁA-Z][А-ЯЁA-Zа-яёa-z-]+(?:\s+[А-ЯЁA-Z][А-ЯЁA-Zа-яёa-z-]+){1,3}\b")
YEAR_RE = re.compile(r"\b(19\d{2}|20\d{2})\b")
DIPLOMA_NUMBER_PATTERNS = [
    re.compile(r"(?:номер\s+диплома|диплом\s*№|номер\s*№|№)\s*[:\-]?\s*([A-ZА-Я0-9\-/]{4,})", re.IGNORECASE),
    re.compile(r"\b([A-ZА-Я]{1,4}[\-/ ]?\d{4,12})\b"),
]
SPECIALTY_PATTERNS = [
    re.compile(r"(?:специальность|направление подготовки|qualification)\s*[:\-]?\s*([^\n]{5,100})", re.IGNORECASE),
]
UNIVERSITY_CODE_PATTERNS = [
    re.compile(r"(?:код\s+вуза|university\s+code)\s*[:\-]?\s*(\d{1,10})", re.IGNORECASE),
]
UNIVERSITY_LINE_RE = re.compile(r"(университет|институт|академ|колледж|college|university|school)", re.IGNORECASE)


def extract_text_from_pdf(file_bytes: bytes) -> str:
    document = fitz.open(stream=file_bytes, filetype="pdf")
    pages = []
    for page in document[:5]:
        pages.append(page.get_text("text"))
    document.close()
    return "\n".join(pages)


def extract_text_from_image(file_bytes: bytes) -> str:
    image = Image.open(io.BytesIO(file_bytes)).convert("L")
    image = ImageOps.autocontrast(image)
    image = image.point(lambda p: 255 if p > 170 else 0)
    lang = os.getenv("OCR_LANG", "eng")
    return pytesseract.image_to_string(image, lang=lang, config="--psm 6")


def extract_requisites_from_text(text: str) -> dict:
    cleaned = re.sub(r"[\r\t]+", " ", text or "")
    cleaned = re.sub(r" +", " ", cleaned)
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]

    diploma_number = None
    for pattern in DIPLOMA_NUMBER_PATTERNS:
        match = pattern.search(cleaned)
        if match:
            diploma_number = match.group(1).strip()
            break

    years = YEAR_RE.findall(cleaned)
    graduation_year = int(years[0]) if years else None

    full_name = None
    explicit_name = re.search(r"(?:ФИО|FIO|на имя|выдан[а-я\s]*)\s*[:\-]?\s*([А-ЯЁA-Z][^\n]{5,100})", text or "", re.IGNORECASE)
    if explicit_name:
        candidate = explicit_name.group(1).strip()
        if 1 < len(candidate.split()) <= 4:
            full_name = candidate
    if not full_name:
        for line in lines:
            match = NAME_RE.search(line)
            if match:
                full_name = match.group(0).strip()
                break

    specialty = None
    for pattern in SPECIALTY_PATTERNS:
        match = pattern.search(text or "")
        if match:
            specialty = match.group(1).strip(" .")
            break

    university_name = None
    for line in lines:
        if UNIVERSITY_LINE_RE.search(line):
            university_name = line[:120]
            break

    university_code = None
    for pattern in UNIVERSITY_CODE_PATTERNS:
        match = pattern.search(cleaned)
        if match:
            university_code = match.group(1).strip()
            break

    preview = cleaned[:1000]
    return {
        "university_code": university_code,
        "university_name": university_name,
        "diploma_number": diploma_number,
        "full_name": full_name,
        "graduation_year": graduation_year,
        "specialty": specialty,
        "preview_text": preview,
    }


def extract_requisites_from_upload(file_storage):
    filename = (file_storage.filename or "").lower()
    content = file_storage.read()
    if not content:
        raise ValueError("Файл пустой")

    if filename.endswith(".pdf"):
        text = extract_text_from_pdf(content)
        source_type = "pdf"
    elif filename.endswith((".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".webp")):
        text = extract_text_from_image(content)
        source_type = "scan"
    else:
        raise ValueError("Поддерживаются PDF и изображения дипломов")

    extracted = extract_requisites_from_text(text)
    extracted["source_type"] = source_type
    extracted["source_filename"] = file_storage.filename
    extracted["text_found"] = bool((text or "").strip())
    return extracted


_registered_font_name = None


def _get_pdf_font_name():
    global _registered_font_name
    if _registered_font_name:
        return _registered_font_name

    candidates = [
        os.path.join(current_app.root_path, "static", "fonts", "DejaVuSans.ttf"),
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/dejavu/DejaVuSans.ttf",
        r"C:\Windows\Fonts\arial.ttf",
        r"C:\Windows\Fonts\DejaVuSans.ttf",
    ]
    for path in candidates:
        if os.path.exists(path):
            pdfmetrics.registerFont(TTFont("AppUnicode", path))
            _registered_font_name = "AppUnicode"
            return _registered_font_name
    _registered_font_name = "Helvetica"
    return _registered_font_name


def build_result_pdf(result: dict) -> io.BytesIO:
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4
    font_name = _get_pdf_font_name()
    pdf.setTitle("Результат проверки диплома")

    y = height - 40

    def write_line(text: str, size: int = 11, bold: bool = False):
        nonlocal y
        text = str(text)
        pdf.setFont(font_name, size)
        max_width = width - 80
        lines = simpleSplit(text, font_name, size, max_width)
        for line in lines:
            if y < 50:
                pdf.showPage()
                pdf.setFont(font_name, size)
                y = height - 40
            pdf.drawString(40, y, line)
            y -= size + 4

    write_line("Результат проверки диплома", 16)
    y -= 4
    write_line(f"Дата проверки: {result.get('verified_at', '')}")
    write_line(f"Режим: {'Быстрая проверка' if result.get('verification_mode') == 'quick' else 'Расширенная проверка'}")
    write_line(f"Статус: {result.get('message', result.get('status', ''))}")
    write_line(f"Индекс доверия: {result.get('trust_label', '')}")
    y -= 4
    write_line(f"ВУЗ: {result.get('university_name') or result.get('university_code') or '—'}")
    write_line(f"Номер диплома: {result.get('diploma_number') or '—'}")

    requested = result.get("requested", {})
    matched = result.get("matched", {})
    write_line(f"ФИО (введено): {requested.get('full_name') or '—'}")
    write_line(f"ФИО (реестр): {matched.get('full_name') or '—'}")
    write_line(f"Год (введено): {requested.get('graduation_year') or '—'}")
    write_line(f"Год (реестр): {matched.get('graduation_year') or '—'}")
    write_line(f"Специальность (введено): {requested.get('specialty') or '—'}")
    write_line(f"Специальность (реестр): {matched.get('specialty') or '—'}")
    y -= 4
    write_line(f"Подпись вуза: {result.get('signature_label', '—')}")
    write_line("Индикаторы:")
    for indicator in result.get("indicators", []):
        write_line(f"• {indicator.get('label', '')}")

    pdf.showPage()
    pdf.save()
    buffer.seek(0)
    return buffer


def get_hr_history(filters: dict):
    return list_hr_history(
        session_id=get_hr_session_id(),
        university_code=filters.get("university_code"),
        status=filters.get("status", ""),
        date_from=filters.get("date_from", ""),
        date_to=filters.get("date_to", ""),
        limit=int(filters.get("limit", 100) or 100),
    )


def get_hr_history_for_pdf(history_id: int):
    return get_hr_history_item(get_hr_session_id(), history_id)

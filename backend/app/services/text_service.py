import os, re
from difflib import SequenceMatcher
from pathlib import Path

from pypdf import PdfReader


class InvalidWrittenWorkError(ValueError):
    pass


MAX_PDF_PAGES = int(os.getenv("MAX_PDF_PAGES", "100"))
MAX_TEXT_CHARS = int(os.getenv("MAX_TEXT_CHARS", "2000000"))


def normalize_text(value: str) -> str:
    return re.sub(r"\s+", " ", value.replace("\ufeff", " ")).strip()


def extract_written_content(path: Path, media_type: str) -> tuple[str, int]:
    try:
        if media_type == "pdf":
            reader = PdfReader(str(path))
            if len(reader.pages) > MAX_PDF_PAGES:
                raise InvalidWrittenWorkError("PDF vượt quá số trang cho phép")
            chunks = []
            total_chars = 0
            for page in reader.pages:
                chunk = page.extract_text() or ""
                total_chars += len(chunk)
                if total_chars > MAX_TEXT_CHARS:
                    raise InvalidWrittenWorkError("Nội dung văn bản vượt quá giới hạn cho phép")
                chunks.append(chunk)
            text = "\n".join(chunks)
            page_count = len(reader.pages)
        else:
            text = path.read_text(encoding="utf-8")
            if len(text) > MAX_TEXT_CHARS:
                raise InvalidWrittenWorkError("Nội dung văn bản vượt quá giới hạn cho phép")
            page_count = 1
    except Exception as exc:
        raise InvalidWrittenWorkError("Không thể đọc nội dung tác phẩm viết") from exc
    normalized = normalize_text(text)
    if not normalized:
        raise InvalidWrittenWorkError("Tác phẩm không có văn bản có thể đọc được")
    return normalized, page_count


def text_similarity(text_a: str, text_b: str) -> float:
    if not text_a or not text_b:
        return 0.0
    return round(SequenceMatcher(None, text_a, text_b).ratio() * 100, 2)

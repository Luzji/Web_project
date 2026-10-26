import hashlib, os
from pathlib import Path
from PIL import Image, UnidentifiedImageError
import imagehash

MAX_IMAGE_PIXELS = int(os.getenv("MAX_IMAGE_PIXELS", "25000000"))

class InvalidImageError(ValueError):
    pass

def validate_image(path: Path) -> None:
    try:
        with Image.open(path) as image:
            if image.width * image.height > MAX_IMAGE_PIXELS:
                raise InvalidImageError("Ảnh vượt quá giới hạn độ phân giải cho phép")
            image.verify()
    except InvalidImageError:
        raise
    except (UnidentifiedImageError, OSError) as exc:
        raise InvalidImageError("File không phải ảnh hợp lệ") from exc

def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()

def phash_file(path: Path) -> str:
    try:
        with Image.open(path) as image:
            if image.width * image.height > MAX_IMAGE_PIXELS:
                raise InvalidImageError("Ảnh vượt quá giới hạn độ phân giải cho phép")
            return str(imagehash.phash(image.convert("RGB")))
    except InvalidImageError:
        raise
    except (UnidentifiedImageError, OSError) as exc:
        raise InvalidImageError("Không thể đọc ảnh") from exc

def similarity_percent(phash_a: str, phash_b: str) -> float:
    hash_a = imagehash.hex_to_hash(phash_a); hash_b = imagehash.hex_to_hash(phash_b)
    return max(0.0, round((1 - (hash_a - hash_b) / len(hash_a)) * 100, 2))

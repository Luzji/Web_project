import json, logging, os, uuid
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, RedirectResponse
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from ..db import get_db
from ..models import Artwork, User
from ..schemas import ArtworkOut, VerifyResult, WorkDetailOut
from ..services.auth_service import decode_token
from ..services.blockchain_service import find_registration_tx, get_transaction_proof, register_on_chain, verify_on_chain
from ..services.image_service import InvalidImageError, phash_file, sha256_file, similarity_percent, validate_image
from ..services.rate_limit import VERIFY_LIMITER
from ..services.text_service import InvalidWrittenWorkError, extract_written_content, text_similarity
from ..services.storage_service import cloud_enabled, is_remote, media_url, upload_file

oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/token")
optional_oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/token", auto_error=False)
logger = logging.getLogger(__name__)
router = APIRouter(tags=["artworks"])
UPLOAD_DIR = Path(os.getenv("UPLOAD_DIR", "./uploads")); UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp"}
WRITTEN_TYPES = {"text/plain", "text/markdown", "text/x-markdown", "application/pdf", "application/octet-stream"}
MAX_BYTES = int(float(os.getenv("MAX_UPLOAD_MB", "10")) * 1024 * 1024)


def current_user(token: str = Depends(oauth2), db: Session = Depends(get_db)) -> User:
    try:
        user_id = int(decode_token(token))
    except (JWTError, ValueError, KeyError):
        raise HTTPException(401, "Token không hợp lệ")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(401, "Không tìm thấy người dùng")
    return user


def optional_current_user(token: str | None = Depends(optional_oauth2), db: Session = Depends(get_db)) -> User | None:
    """Resolve a bearer token for public endpoints without requiring one."""
    if token is None:
        return None
    try:
        user_id = int(decode_token(token))
    except (JWTError, ValueError, KeyError):
        raise HTTPException(401, "Token không hợp lệ")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(401, "Không tìm thấy người dùng")
    return user


def detect_media_type(file: UploadFile, requested: str) -> str:
    if requested in {"image", "written"}:
        return requested
    suffix = Path(file.filename or "").suffix.lower()
    return "written" if suffix in {".txt", ".md", ".markdown", ".pdf"} else "image"


def parse_artwork(row: Artwork, *, viewer: User | None = None) -> ArtworkOut:
    media_type = getattr(row, "media_type", "image") or "image"
    visibility = getattr(row, "visibility", None) or "public"
    license_name = getattr(row, "license", None) or "All rights reserved"
    show_preview = bool(getattr(row, "show_public_preview", False)) and visibility == "public"
    return ArtworkOut(
        id=row.id, title=row.title, description=row.description, tags=json.loads(row.tags or "[]"),
        sha256=row.sha256, phash=row.phash, originality=row.originality, status=row.status,
        tx_hash=row.tx_hash, image_url=media_url(row.file_path) if media_type == "image" and visibility == "public" else None,
        download_url=f"/api/artworks/{row.id}/download" if bool(getattr(row, "allow_download", False)) and visibility == "public" else None,
        author_email=row.owner.email if row.show_contact_email else None,
        author_wallet=row.owner.wallet_address, media_type=media_type,
        work_type=getattr(row, "work_type", None), language=getattr(row, "language", None),
        word_count=getattr(row, "word_count", None), page_count=getattr(row, "page_count", None),
        preview_text=row.preview_text if show_preview else None, license=license_name,
        visibility=visibility, show_public_preview=show_preview,
        allow_download=bool(getattr(row, "allow_download", False)) and visibility == "public",
        created_at=row.created_at, is_owner=bool(viewer and row.owner_id == viewer.id),
    )


async def save_upload(file: UploadFile, prefix: str, media_type: str) -> Path:
    suffix = Path(file.filename or "").suffix.lower()
    allowed = IMAGE_TYPES if media_type == "image" else WRITTEN_TYPES
    if file.content_type not in allowed and not (media_type == "written" and suffix in {".txt", ".md", ".markdown", ".pdf"}):
        raise HTTPException(415, "Định dạng file chưa được hỗ trợ")
    target = UPLOAD_DIR / f"{prefix}_{uuid.uuid4().hex}{suffix}"
    total = 0
    try:
        with target.open("wb") as output:
            while chunk := await file.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_BYTES:
                    raise HTTPException(413, f"File vượt quá {MAX_BYTES // 1024 // 1024} MB")
                output.write(chunk)
        if media_type == "image":
            validate_image(target)
        return target
    except HTTPException:
        target.unlink(missing_ok=True); raise
    except InvalidImageError as exc:
        target.unlink(missing_ok=True); raise HTTPException(415, str(exc)) from exc
    except Exception:
        target.unlink(missing_ok=True); raise


def _safe_verify_on_chain(file_hash: str) -> bool:
    try:
        return verify_on_chain(file_hash)
    except Exception:
        logger.exception("Không thể verify artwork %s trên blockchain", file_hash)
        return False


def _safe_find_registration_tx(file_hash: str) -> str | None:
    try:
        return find_registration_tx(file_hash)
    except Exception:
        logger.exception("Không thể truy hồi tx_hash của artwork %s", file_hash)
        return None


def _safe_transaction_proof(tx_hash: str | None) -> dict[str, int | None] | None:
    try:
        return get_transaction_proof(tx_hash) if tx_hash else None
    except Exception:
        logger.exception("Không thể đọc bằng chứng transaction %s", tx_hash)
        return None


@router.get("/artworks", response_model=list[ArtworkOut])
def list_artworks(viewer: User | None = Depends(optional_current_user), db: Session = Depends(get_db)):
    rows = db.scalars(select(Artwork).where(Artwork.visibility == "public").order_by(Artwork.created_at.desc())).all()
    return [parse_artwork(x, viewer=viewer) for x in rows]


@router.get("/media/{filename:path}")
def serve_media(filename: str, viewer: User | None = Depends(optional_current_user), db: Session = Depends(get_db)):
    """Serve previews only after applying the artwork visibility policy."""
    if not filename or Path(filename).name != filename:
        raise HTTPException(404, "Không tìm thấy file tác phẩm")
    row = db.scalar(select(Artwork).where(Artwork.file_path.endswith(f"/{filename}")))
    if not row or (row.visibility != "public" and not (viewer and viewer.id == row.owner_id)):
        raise HTTPException(404, "Không tìm thấy file tác phẩm")
    if is_remote(row.file_path):
        if row.visibility != "public":
            raise HTTPException(404, "Không tìm thấy file tác phẩm")
        return RedirectResponse(row.file_path)
    path = Path(row.file_path).resolve()
    root = UPLOAD_DIR.resolve()
    try:
        path.relative_to(root)
    except ValueError:
        raise HTTPException(404, "Không tìm thấy file tác phẩm")
    if not path.is_file():
        raise HTTPException(404, "Không tìm thấy file tác phẩm")
    return FileResponse(path, media_type="application/octet-stream")


@router.get("/artworks/{artwork_id}", response_model=WorkDetailOut)
def get_artwork_detail(artwork_id: int, viewer: User | None = Depends(optional_current_user), db: Session = Depends(get_db)):
    row = db.get(Artwork, artwork_id)
    if not row or (row.visibility != "public" and not (viewer and viewer.id == row.owner_id)):
        raise HTTPException(404, "Không tìm thấy tác phẩm")
    media_type = getattr(row, "media_type", "image") or "image"
    return WorkDetailOut(
        id=row.id, title=row.title, description=row.description or "", tags=json.loads(row.tags or "[]"),
        kind=media_type, owner_address=row.owner.wallet_address, created_at=row.created_at, status=row.status,
        sha256=row.sha256, phash=row.phash, tx_hash=row.tx_hash,
        contract_address=os.getenv("CONTRACT_ADDRESS"),
        image_url=media_url(row.file_path) if media_type == "image" and row.visibility == "public" else None,
        work_type=getattr(row, "work_type", None), originality=row.originality,
        is_owner=bool(viewer and viewer.id == row.owner_id),
    )


@router.get("/artworks/{artwork_id}/download")
def download_artwork(artwork_id: int, db: Session = Depends(get_db)):
    row = db.get(Artwork, artwork_id)
    if not row or row.visibility != "public" or not row.allow_download:
        raise HTTPException(404, "Tác phẩm không cho phép tải xuống")
    if is_remote(row.file_path):
        return RedirectResponse(row.file_path)
    path = Path(row.file_path)
    if not path.is_file():
        raise HTTPException(404, "Không tìm thấy file tác phẩm")
    return FileResponse(path, filename=path.name, media_type="application/octet-stream")


@router.post("/artworks/register", response_model=ArtworkOut, status_code=201)
async def register_artwork(
    file: UploadFile = File(...), title: str = Form("Untitled"), description: str = Form(""), tags: str = Form("[]"),
    media_type: str = Form("auto"), work_type: str = Form(""), language: str = Form(""), license: str = Form("All rights reserved"),
    visibility: str = Form("public"), show_public_preview: bool = Form(False), allow_download: bool = Form(False),
    show_contact_email: bool = Form(False), user: User = Depends(current_user), db: Session = Depends(get_db),
):
    if not user.wallet_address or not user.wallet_verified_at:
        raise HTTPException(403, "Hãy xác thực ví MetaMask trước khi đăng ký")
    media_type = detect_media_type(file, media_type)
    if visibility not in {"public", "private"}:
        raise HTTPException(422, "visibility phải là public hoặc private")
    if media_type == "written" and visibility == "private":
        show_public_preview = False; allow_download = False
    target = await save_upload(file, "work", media_type)
    try:
        sha = sha256_file(target)
        if db.scalar(select(Artwork).where(Artwork.sha256 == sha)):
            raise HTTPException(409, "File trùng SHA-256 với tác phẩm đã đăng ký")
        phash, content_text, page_count, word_count = "", "", None, None
        nearest, best = None, 0.0
        if media_type == "image":
            phash = phash_file(target)
            candidates = db.scalars(select(Artwork).where(Artwork.media_type == "image")).all()
            for row in candidates:
                if row.phash:
                    score = similarity_percent(phash, row.phash)
                    if score > best: best, nearest = score, row
        else:
            try:
                content_text, page_count = extract_written_content(target, "pdf" if target.suffix.lower() == ".pdf" else "text")
            except InvalidWrittenWorkError as exc:
                raise HTTPException(415, str(exc)) from exc
            word_count = len(content_text.split())
            candidates = db.scalars(select(Artwork).where(Artwork.media_type == "written")).all()
            for row in candidates:
                score = text_similarity(content_text, row.content_text)
                if score > best: best, nearest = score, row
        if best >= 85:
            label = "văn bản" if media_type == "written" else "ảnh"
            raise HTTPException(409, {"message": f"{label.capitalize()} quá giống tác phẩm đã đăng ký", "similarity_percent": best, "suspected_artwork_id": nearest.id})
        stored_path = str(target)
        # Cloudinary uploads in this project use public delivery URLs. Keep private
        # works on the protected local path until authenticated/signed delivery is added.
        if cloud_enabled() and visibility == "public":
            try:
                stored_path = await run_in_threadpool(upload_file, target, media_type)
            except Exception as exc:
                logger.exception("Upload Cloudinary that bai")
                raise HTTPException(502, "Không thể lưu file lên kho lưu trữ") from exc
        try:
            tag_list = json.loads(tags)
        except json.JSONDecodeError:
            tag_list = [x.strip() for x in tags.split(",") if x.strip()]
        preview_text = content_text[:400] if media_type == "written" and show_public_preview and visibility == "public" else None
        row = Artwork(
            owner_id=user.id, file_path=stored_path, sha256=sha, phash=phash, title=title, description=description,
            tags=json.dumps(tag_list), originality=round(100 - best), status="pending_chain", show_contact_email=show_contact_email,
            media_type=media_type, work_type=work_type or ("written" if media_type == "written" else "image"), language=language or None,
            word_count=word_count, page_count=page_count, content_text=content_text, preview_text=preview_text,
            license=license, visibility=visibility, show_public_preview=bool(show_public_preview), allow_download=bool(allow_download),
        )
        db.add(row); db.commit(); db.refresh(row)
        if is_remote(stored_path):
            target.unlink(missing_ok=True)
        try:
            row.tx_hash = await run_in_threadpool(register_on_chain, sha, user.wallet_address, row.originality, f"mediaguard://artworks/{row.id}")
            if row.tx_hash:
                row.status = "protected"
            elif await run_in_threadpool(_safe_verify_on_chain, sha):
                row.tx_hash = await run_in_threadpool(_safe_find_registration_tx, sha); row.status = "protected"
            else:
                row.status = "approved_local"
        except Exception:
            logger.exception("Ghi artwork %s lên blockchain thất bại", row.id); row.status = "chain_failed"
        db.commit(); db.refresh(row)
        return parse_artwork(row)
    except HTTPException:
        target.unlink(missing_ok=True); raise


@router.post("/verify", response_model=VerifyResult)
async def verify_artwork(request: Request, file: UploadFile = File(...), viewer: User | None = Depends(optional_current_user), db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    if not VERIFY_LIMITER.allow(f"verify:{client_ip}"):
        raise HTTPException(429, "Quá nhiều lượt verify, vui lòng thử lại sau")
    media_type = detect_media_type(file, "auto")
    target = await save_upload(file, "verify", media_type)
    try:
        sha = sha256_file(target)
        exact = db.scalar(select(Artwork).where(Artwork.sha256 == sha))
        if exact:
            on_chain = await run_in_threadpool(_safe_verify_on_chain, sha)
            proof = await run_in_threadpool(_safe_transaction_proof, exact.tx_hash) if on_chain else None
            can_view = exact.visibility == "public" or bool(viewer and viewer.id == exact.owner_id)
            if not can_view:
                return VerifyResult(
                    sha256=sha, registered=True, similarity_percent=100, on_chain_registered=on_chain,
                    message="File đã tồn tại trong hệ thống nhưng thông tin tác phẩm được bảo vệ theo chế độ riêng tư.", media_type=media_type,
                )
            return VerifyResult(
                sha256=sha, registered=True, artwork_id=exact.id, similarity_percent=100,
                on_chain_registered=on_chain, message="Mã SHA-256 của file khớp hoàn toàn với tác phẩm đã đăng ký. File này giống hệt bản gốc.", media_type=media_type,
                matched_title=exact.title, matched_wallet=exact.owner.wallet_address, matched_created_at=exact.created_at,
                matched_status=exact.status, matched_tx_hash=exact.tx_hash,
                matched_image_url=media_url(exact.file_path) if exact.media_type == "image" and exact.visibility == "public" else None,
                matched_block_number=proof.get("block_number") if proof else None,
                matched_block_timestamp=(datetime.fromtimestamp(proof["block_timestamp"], timezone.utc) if proof and proof.get("block_timestamp") else None),
            )
        nearest, best = None, 0.0
        if media_type == "image":
            phash = phash_file(target)
            for row in db.scalars(select(Artwork).where(Artwork.media_type == "image")).all():
                if row.visibility != "public" and not (viewer and viewer.id == row.owner_id):
                    continue
                if row.phash:
                    score = similarity_percent(phash, row.phash)
                    if score > best: best, nearest = score, row
        else:
            try:
                content_text, _ = extract_written_content(target, "pdf" if target.suffix.lower() == ".pdf" else "text")
            except InvalidWrittenWorkError as exc:
                raise HTTPException(415, str(exc)) from exc
            for row in db.scalars(select(Artwork).where(Artwork.media_type == "written")).all():
                if row.visibility != "public" and not (viewer and viewer.id == row.owner_id):
                    continue
                score = text_similarity(content_text, row.content_text)
                if score > best: best, nearest = score, row
        return VerifyResult(
            sha256=sha, registered=False, suspected_artwork_id=nearest.id if nearest else None,
            suspected_artwork_title=nearest.title if nearest else None,
            # Do not reveal a private work's direct media path through a public verification.
            suspected_artwork_image_url=(media_url(nearest.file_path) if nearest and nearest.media_type == "image" and nearest.visibility == "public" else None),
            suspected_artwork_media_type=nearest.media_type if nearest else None,
            similarity_percent=best, message=f"Không trùng tuyệt đối; giống gần nhất {best:.1f}%" if nearest else "Chưa có dữ liệu đối chiếu", media_type=media_type,
        )
    finally:
        target.unlink(missing_ok=True)


@router.post("/artworks/{artwork_id}/retry-chain", response_model=ArtworkOut)
async def retry_chain(artwork_id: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    row = db.get(Artwork, artwork_id)
    if not row: raise HTTPException(404, "Không tìm thấy artwork")
    if row.owner_id != user.id: raise HTTPException(403, "Không có quyền retry artwork này")
    if row.status not in {"chain_failed", "approved_local", "pending_chain"}: raise HTTPException(409, f"Artwork đang ở trạng thái {row.status}, không cần retry")
    if not user.wallet_address or not user.wallet_verified_at: raise HTTPException(403, "Hãy xác thực ví MetaMask trước")
    try:
        if await run_in_threadpool(verify_on_chain, row.sha256):
            row.tx_hash = await run_in_threadpool(_safe_find_registration_tx, row.sha256); row.status = "protected"; db.commit(); db.refresh(row); return parse_artwork(row)
        row.status = "pending_chain"; db.commit()
        row.tx_hash = await run_in_threadpool(register_on_chain, row.sha256, user.wallet_address, row.originality, f"mediaguard://artworks/{row.id}")
        if row.tx_hash: row.status = "protected"
        elif await run_in_threadpool(_safe_verify_on_chain, row.sha256): row.tx_hash = await run_in_threadpool(_safe_find_registration_tx, row.sha256); row.status = "protected"
        else: row.status = "approved_local"
    except Exception:
        logger.exception("Retry ghi artwork %s lên blockchain thất bại", row.id); row.status = "chain_failed"
    db.commit(); db.refresh(row); return parse_artwork(row)

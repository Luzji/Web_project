import io
from datetime import datetime, timezone
from uuid import uuid4

from fastapi.testclient import TestClient
from eth_account import Account
from eth_account.messages import encode_defunct
from PIL import Image
from sqlalchemy import select

from app.main import app
from app.db import SessionLocal
from app.models import Artwork, User
from app.routers import artworks as artwork_router
from app.services.auth_service import hash_password
from app.services.rate_limit import SlidingWindowLimiter
from app.services.wallet_service import build_message

client = TestClient(app)


def png_bytes(color="red"):
    buffer = io.BytesIO()
    Image.new("RGB", (32, 32), color).save(buffer, format="PNG")
    return buffer.getvalue()


def test_auth_and_verify_endpoint(monkeypatch):
    email = "api-test@example.com"
    response = client.post("/auth/register", json={"email": email, "password": "correct-horse-battery-staple"})
    assert response.status_code in {201, 409}
    token = client.post("/auth/login", json={"email": email, "password": "correct-horse-battery-staple"}).json()["access_token"]
    assert token

    monkeypatch.setattr(artwork_router, "VERIFY_LIMITER", SlidingWindowLimiter(limit=1))
    response = client.post("/verify", files={"file": ("image.png", png_bytes(), "image/png")})
    assert response.status_code == 200
    assert response.json()["registered"] is False
    response = client.post("/verify", files={"file": ("image.png", png_bytes(), "image/png")})
    assert response.status_code == 429


def test_retry_chain_updates_existing_artwork(monkeypatch):
    db = SessionLocal()
    email = f"retry-{uuid4().hex}@example.com"
    password = "correct-horse-battery-staple"
    user = User(email=email, password_hash=hash_password(password), wallet_address="0x0000000000000000000000000000000000000001", wallet_verified_at=datetime.now(timezone.utc))
    db.add(user); db.commit(); db.refresh(user)
    artwork = Artwork(owner_id=user.id, file_path="/tmp/artwork", sha256=uuid4().hex * 2, phash="00" * 8, title="Retry", originality=100, status="chain_failed")
    db.add(artwork); db.commit(); db.refresh(artwork)
    user_id, artwork_id = user.id, artwork.id
    db.close()

    token = client.post("/auth/login", json={"email": email, "password": password}).json()["access_token"]
    monkeypatch.setattr(artwork_router, "verify_on_chain", lambda file_hash: False)
    monkeypatch.setattr(artwork_router, "register_on_chain", lambda *args: "0x" + "ab" * 32)
    response = client.post(f"/artworks/{artwork_id}/retry-chain", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "protected"


def test_list_artworks_marks_only_authenticated_owner():
    db = SessionLocal()
    password = "correct-horse-battery-staple"
    owner = User(email=f"owner-{uuid4().hex}@example.com", password_hash=hash_password(password))
    other = User(email=f"other-{uuid4().hex}@example.com", password_hash=hash_password(password))
    db.add_all([owner, other]); db.commit(); db.refresh(owner); db.refresh(other)
    owned = Artwork(owner_id=owner.id, file_path="/tmp/owned.png", sha256=uuid4().hex * 2, phash="0" * 16, title="Owned", originality=100, status="chain_failed", visibility="public")
    not_owned = Artwork(owner_id=other.id, file_path="/tmp/other.png", sha256=uuid4().hex * 2, phash="1" * 16, title="Other", originality=100, status="pending_chain", visibility="public")
    private = Artwork(owner_id=owner.id, file_path="/tmp/private.png", sha256=uuid4().hex * 2, phash="2" * 16, title="Private", originality=100, status="chain_failed", visibility="private")
    db.add_all([owned, not_owned, private]); db.commit(); db.refresh(owned); db.refresh(not_owned); db.refresh(private)
    owned_id, other_id, private_id, owner_email = owned.id, not_owned.id, private.id, owner.email
    db.close()

    anonymous = client.get("/artworks")
    assert anonymous.status_code == 200, anonymous.text
    anonymous_by_id = {item["id"]: item for item in anonymous.json()}
    assert anonymous_by_id[owned_id]["status"] == "chain_failed"
    assert anonymous_by_id[other_id]["status"] == "pending_chain"
    assert anonymous_by_id[owned_id]["is_owner"] is False
    assert private_id not in anonymous_by_id

    token = client.post("/auth/login", json={"email": owner_email, "password": password}).json()["access_token"]
    authenticated = client.get("/artworks", headers={"Authorization": f"Bearer {token}"})
    assert authenticated.status_code == 200, authenticated.text
    authenticated_by_id = {item["id"]: item for item in authenticated.json()}
    assert authenticated_by_id[owned_id]["is_owner"] is True
    assert authenticated_by_id[other_id]["is_owner"] is False


def test_work_detail_public_and_missing():
    db = SessionLocal()
    owner = User(email=f"detail-{uuid4().hex}@example.com", password_hash=hash_password("correct-horse-battery-staple"), wallet_address="0x0000000000000000000000000000000000000455")
    db.add(owner); db.commit(); db.refresh(owner)
    artwork = Artwork(owner_id=owner.id, file_path="/tmp/detail.png", sha256=uuid4().hex * 2, phash="b" * 16, title="Detail work", description="Detail description", tags='["design"]', originality=98, status="protected", tx_hash="0x" + "ab" * 32, media_type="image", visibility="public")
    db.add(artwork); db.commit(); db.refresh(artwork); artwork_id = artwork.id; db.close()

    response = client.get(f"/artworks/{artwork_id}")
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["id"] == artwork_id
    assert body["kind"] == "image"
    assert body["owner_address"].endswith("0455")
    assert body["is_owner"] is False
    assert client.get("/artworks/99999999").status_code == 404


def test_verify_returns_public_suspected_image_metadata(monkeypatch):
    db = SessionLocal()
    owner = User(email=f"suspect-{uuid4().hex}@example.com", password_hash=hash_password("correct-horse-battery-staple"))
    db.add(owner); db.commit(); db.refresh(owner)
    artwork = Artwork(
        owner_id=owner.id, file_path="/tmp/closest.png", sha256=uuid4().hex * 2,
        phash="a" * 16, title="Closest public image", originality=100, status="approved_local", media_type="image", visibility="public",
    )
    db.add(artwork); db.commit(); db.refresh(artwork)
    artwork_id = artwork.id
    db.close()

    monkeypatch.setattr(artwork_router, "phash_file", lambda _path: "a" * 16)
    response = client.post("/verify", files={"file": ("candidate.png", png_bytes("blue"), "image/png")})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["registered"] is False
    assert body["suspected_artwork_id"] == artwork_id
    assert body["suspected_artwork_title"] == "Closest public image"
    assert body["suspected_artwork_image_url"] == "/api/media/closest.png"
    assert body["suspected_artwork_media_type"] == "image"
    assert body["message"].endswith("100.0%")


def test_verify_exact_private_image_has_no_public_thumbnail(monkeypatch):
    from hashlib import sha256

    data = png_bytes("purple")
    db = SessionLocal()
    owner = User(email=f"private-{uuid4().hex}@example.com", password_hash=hash_password("correct-horse-battery-staple"))
    db.add(owner); db.commit(); db.refresh(owner)
    artwork = Artwork(owner_id=owner.id, file_path="/tmp/private-original.png", sha256=sha256(data).hexdigest(), phash="f" * 16, title="Private original", originality=100, status="approved_local", media_type="image", visibility="private")
    db.add(artwork); db.commit(); db.close()

    monkeypatch.setattr(artwork_router, "verify_on_chain", lambda _hash: False)
    response = client.post("/verify", files={"file": ("private.png", data, "image/png")})
    assert response.status_code == 200, response.text
    assert response.json()["registered"] is True
    assert response.json()["matched_image_url"] is None
    assert response.json().get("matched_title") is None
    assert response.json().get("matched_wallet") is None


def test_private_media_and_similarity_metadata_are_not_public(monkeypatch):
    db = SessionLocal()
    password = "correct-horse-battery-staple"
    owner = User(email=f"private-media-{uuid4().hex}@example.com", password_hash=hash_password(password))
    db.add(owner); db.commit(); db.refresh(owner)
    filename = f"private-{uuid4().hex}.png"
    path = artwork_router.UPLOAD_DIR / filename
    path.write_bytes(png_bytes("black"))
    artwork = Artwork(
        owner_id=owner.id, file_path=str(path), sha256=uuid4().hex * 2,
        phash="c" * 16, title="Secret private work", originality=100,
        status="approved_local", media_type="image", visibility="private",
    )
    db.add(artwork); db.commit(); db.refresh(artwork)
    artwork_id = artwork.id
    db.close()

    assert client.get(f"/media/{filename}").status_code == 404
    monkeypatch.setattr(artwork_router, "phash_file", lambda _path: "c" * 16)
    response = client.post("/verify", files={"file": ("candidate.png", png_bytes("white"), "image/png")})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["suspected_artwork_title"] != "Secret private work"
    assert client.get(f"/artworks/{artwork_id}").status_code == 404


def test_metamask_signature_and_nonce_errors():
    email = f"wallet-{uuid4().hex}@example.com"
    password = "correct-horse-battery-staple"
    register = client.post("/auth/register", json={"email": email, "password": password})
    assert register.status_code == 201, register.text
    token = register.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    nonce_response = client.post("/auth/wallet/nonce", headers=headers)
    assert nonce_response.status_code == 200, nonce_response.text
    nonce_data = nonce_response.json()
    account = Account.create()

    wrong_nonce = "definitely-not-the-issued-nonce"
    wrong_message = build_message(email, wrong_nonce)
    wrong_signature = Account.sign_message(encode_defunct(text=wrong_message), account.key).signature.hex()
    rejected = client.post("/auth/wallet/verify", headers=headers, json={
        "wallet_address": account.address,
        "signature": wrong_signature,
        "nonce": wrong_nonce,
    })
    assert rejected.status_code == 400
    assert "Nonce" in rejected.json()["detail"]

    signature = Account.sign_message(encode_defunct(text=nonce_data["message"]), account.key).signature.hex()
    verified = client.post("/auth/wallet/verify", headers=headers, json={
        "wallet_address": account.address,
        "signature": signature,
        "nonce": nonce_data["nonce"],
    })
    assert verified.status_code == 200, verified.text

    replayed = client.post("/auth/wallet/verify", headers=headers, json={
        "wallet_address": account.address,
        "signature": signature,
        "nonce": nonce_data["nonce"],
    })
    assert replayed.status_code == 400
    assert "Nonce" in replayed.json()["detail"]


def test_register_written_work_with_public_preview(monkeypatch):
    email = f"writer-{uuid4().hex}@example.com"
    password = "correct-horse-battery-staple"
    register = client.post("/auth/register", json={"email": email, "password": password})
    assert register.status_code == 201, register.text
    token = register.json()["access_token"]
    db = SessionLocal()
    user = db.scalar(select(User).where(User.email == email))
    user.wallet_address = "0x" + uuid4().hex + uuid4().hex[:8]
    user.wallet_verified_at = datetime.now(timezone.utc)
    db.commit(); db.close()
    monkeypatch.setattr(artwork_router, "register_on_chain", lambda *args: None)
    monkeypatch.setattr(artwork_router, "verify_on_chain", lambda *args: False)
    content = "Những ngày bên sông Hàn là một bài viết thử nghiệm. " * 12
    response = client.post("/artworks/register", headers={"Authorization": f"Bearer {token}"}, files={"file": ("essay.txt", content.encode(), "text/plain")}, data={
        "title": "Những ngày bên sông Hàn", "media_type": "written", "work_type": "essay", "language": "Vietnamese",
        "show_public_preview": "true", "show_contact_email": "true", "license": "All rights reserved",
    })
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["media_type"] == "written"
    assert body["preview_text"].startswith("Những ngày")
    assert body["author_email"] == email
    assert body["download_url"] is None

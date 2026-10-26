from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import JWTError
from sqlalchemy import select
from sqlalchemy.orm import Session
from web3 import Web3
from ..db import get_db
from ..models import User
from ..schemas import UserRegister, LoginRequest, Token, WalletNonce, WalletVerify
from ..services.auth_service import hash_password, verify_password, create_token, decode_token
from ..services.wallet_service import new_nonce, build_message, expires_at, recover_address
from ..services.rate_limit import AUTH_LIMITER

router = APIRouter(prefix="/auth", tags=["auth"])
oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/token")

def current_user(token: str = Depends(oauth2), db: Session = Depends(get_db)) -> User:
    try: user_id = int(decode_token(token))
    except (JWTError, ValueError, KeyError): raise HTTPException(401, "Token không hợp lệ")
    user = db.get(User, user_id)
    if not user: raise HTTPException(401, "Không tìm thấy người dùng")
    return user

@router.post("/register", response_model=Token, status_code=201)
def register(request: Request, data: UserRegister, db: Session = Depends(get_db)):
    if not AUTH_LIMITER.allow(f"auth:{request.client.host if request.client else 'unknown'}"):
        raise HTTPException(429, "Quá nhiều yêu cầu xác thực, vui lòng thử lại sau")
    if db.scalar(select(User).where(User.email == data.email)):
        raise HTTPException(409, "Email đã tồn tại")
    user = User(email=data.email, password_hash=hash_password(data.password))
    db.add(user); db.commit(); db.refresh(user)
    return Token(access_token=create_token(str(user.id)))

@router.post("/login", response_model=Token)
def login(request: Request, data: LoginRequest, db: Session = Depends(get_db)):
    if not AUTH_LIMITER.allow(f"auth:{request.client.host if request.client else 'unknown'}"):
        raise HTTPException(429, "Quá nhiều yêu cầu xác thực, vui lòng thử lại sau")
    user = db.scalar(select(User).where(User.email == data.email))
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Email hoặc mật khẩu không đúng")
    return Token(access_token=create_token(str(user.id)))

@router.post("/token", response_model=Token)
def oauth_token(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    if not AUTH_LIMITER.allow(f"auth:{request.client.host if request.client else 'unknown'}"):
        raise HTTPException(429, "Quá nhiều yêu cầu xác thực, vui lòng thử lại sau")
    user = db.scalar(select(User).where(User.email == form.username))
    if not user or not verify_password(form.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Email hoặc mật khẩu không đúng", headers={"WWW-Authenticate": "Bearer"})
    return Token(access_token=create_token(str(user.id)))

@router.post("/wallet/nonce", response_model=WalletNonce)
def wallet_nonce(user: User = Depends(current_user), db: Session = Depends(get_db)):
    nonce = new_nonce(); expiry = expires_at()
    user.wallet_nonce, user.wallet_nonce_expires_at = nonce, expiry
    db.commit()
    return WalletNonce(nonce=nonce, message=build_message(user.email, nonce), expires_at=expiry)

@router.post("/wallet/verify", response_model=Token)
def wallet_verify(data: WalletVerify, user: User = Depends(current_user), db: Session = Depends(get_db)):
    if not Web3.is_address(data.wallet_address): raise HTTPException(400, "Địa chỉ ví không hợp lệ")
    if not user.wallet_nonce or data.nonce != user.wallet_nonce: raise HTTPException(400, "Nonce không hợp lệ hoặc đã dùng")
    if not user.wallet_nonce_expires_at or user.wallet_nonce_expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        raise HTTPException(400, "Nonce đã hết hạn")
    try: recovered = recover_address(build_message(user.email, data.nonce), data.signature)
    except Exception as exc: raise HTTPException(400, "Chữ ký không hợp lệ") from exc
    if recovered.lower() != data.wallet_address.lower(): raise HTTPException(400, "Chữ ký không khớp địa chỉ ví")
    checksum_address = Web3.to_checksum_address(data.wallet_address)
    existing = db.scalar(select(User).where(User.wallet_address == checksum_address, User.id != user.id))
    if existing:
        raise HTTPException(409, "Địa chỉ ví đã được liên kết với tài khoản khác")
    user.wallet_address = checksum_address
    user.wallet_verified_at = datetime.now(timezone.utc); user.wallet_nonce = None; user.wallet_nonce_expires_at = None
    db.commit()
    return Token(access_token=create_token(str(user.id)))

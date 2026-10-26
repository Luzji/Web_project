import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from .db import Base, engine, ensure_sqlite_columns
from .routers import auth, artworks

load_dotenv()
jwt_secret = os.getenv("JWT_SECRET", "")
if len(jwt_secret) < 32 or jwt_secret.startswith("REPLACE_ME"):
    raise RuntimeError("JWT_SECRET phải được cấu hình bằng giá trị ngẫu nhiên dài tối thiểu 32 ký tự")
Base.metadata.create_all(bind=engine)
ensure_sqlite_columns()
origins = [x.strip() for x in os.getenv("CORS_ORIGINS", "http://localhost:3000,http://localhost:5173").split(",") if x.strip()]
app = FastAPI(title="MediaGuard API", version="0.2.0", description="Đăng ký bản quyền ảnh bằng SHA-256, pHash và blockchain")
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=["GET", "POST"], allow_headers=["Authorization", "Content-Type"])
app.include_router(auth.router)
app.include_router(artworks.router)

@app.get("/health")
def health(): return {"status": "ok", "service": "mediaguard-api"}

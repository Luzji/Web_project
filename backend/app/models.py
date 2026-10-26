from datetime import datetime, timezone
from sqlalchemy import String, Integer, DateTime, Text, ForeignKey, UniqueConstraint, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .db import Base

def utcnow():
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    wallet_address: Mapped[str | None] = mapped_column(String(42), nullable=True, unique=True, index=True)
    wallet_nonce: Mapped[str | None] = mapped_column(String(128), nullable=True)
    wallet_nonce_expires_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    wallet_verified_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    artworks: Mapped[list["Artwork"]] = relationship(back_populates="owner")

class Artwork(Base):
    __tablename__ = "artworks"
    __table_args__ = (UniqueConstraint("sha256", name="uq_artworks_sha256"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    file_path: Mapped[str] = mapped_column(String(500))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    phash: Mapped[str] = mapped_column(String(64), index=True)
    title: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text, default="")
    tags: Mapped[str] = mapped_column(Text, default="[]")
    originality: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(30), default="pending")
    tx_hash: Mapped[str | None] = mapped_column(String(66), nullable=True)
    show_contact_email: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    media_type: Mapped[str] = mapped_column(String(20), default="image", nullable=False, index=True)
    work_type: Mapped[str | None] = mapped_column(String(30), nullable=True)
    language: Mapped[str | None] = mapped_column(String(30), nullable=True)
    word_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    page_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_text: Mapped[str] = mapped_column(Text, default="", nullable=False)
    preview_text: Mapped[str | None] = mapped_column(Text, nullable=True)
    license: Mapped[str] = mapped_column(String(80), default="All rights reserved", nullable=False)
    visibility: Mapped[str] = mapped_column(String(20), default="public", nullable=False, index=True)
    show_public_preview: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    allow_download: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    owner: Mapped[User] = relationship(back_populates="artworks")

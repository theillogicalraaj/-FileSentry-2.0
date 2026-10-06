from datetime import datetime, timezone
from sqlalchemy import DateTime, Integer, String, Text, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .db import Base


def now_utc():
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc)
    analyses: Mapped[list["Analysis"]] = relationship(back_populates="owner", cascade="all, delete-orphan")

class Analysis(Base):
    __tablename__ = "analyses"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    owner_id: Mapped[int] = mapped_column(ForeignKey("users.id"), index=True)
    original_name: Mapped[str] = mapped_column(String(255))
    stored_name: Mapped[str] = mapped_column(String(255), unique=True)
    size_bytes: Mapped[int] = mapped_column(Integer)
    status: Mapped[str] = mapped_column(String(32), default="completed", index=True)
    claimed_extension: Mapped[str | None] = mapped_column(String(16), nullable=True)
    claimed_mime: Mapped[str | None] = mapped_column(String(128), nullable=True)
    detected_type: Mapped[str] = mapped_column(String(128))
    detected_mime: Mapped[str] = mapped_column(String(128))
    confidence: Mapped[int] = mapped_column(Integer)
    md5: Mapped[str] = mapped_column(String(32))
    sha256: Mapped[str] = mapped_column(String(64), index=True)
    sha512: Mapped[str] = mapped_column(String(128))
    entropy: Mapped[float]
    risk_score: Mapped[int] = mapped_column(Integer, index=True)
    risk_level: Mapped[str] = mapped_column(String(16))
    findings_json: Mapped[str] = mapped_column(Text, default="[]")
    indicators_json: Mapped[str] = mapped_column(Text, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now_utc, index=True)
    owner: Mapped[User] = relationship(back_populates="analyses")

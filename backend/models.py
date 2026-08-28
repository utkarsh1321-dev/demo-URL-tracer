"""
models.py — SQLAlchemy ORM models.
Phase 2: Added user_id UUID to all user-owned tables.
         ip_analysis uniqueness changed to (user_id, ip_address) per-user.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    Column, BigInteger, Integer, String, Float,
    DateTime, Text, ForeignKey, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

from database import Base


# ── Helper: choose correct PK / UUID type based on dialect ────────────────────
# SQLite doesn't support PostgreSQL UUID natively; we use String as fallback.
def _uuid_col(primary_key=False, nullable=False, index=False, fk=None):
    """Return a UUID column compatible with both PostgreSQL and SQLite."""
    if fk:
        return Column(
            String(36),
            ForeignKey(fk),
            nullable=nullable,
            index=index,
        )
    return Column(
        String(36),
        primary_key=primary_key,
        nullable=nullable,
        index=index,
        default=lambda: str(uuid.uuid4()),
    )


class Profile(Base):
    """Mirror of auth.users — auto-populated by DB trigger on signup."""
    __tablename__ = "profiles"

    id           = _uuid_col(primary_key=True)
    email        = Column(String(320), nullable=True)
    display_name = Column(String(100), nullable=True)
    created_at   = Column(DateTime, default=datetime.utcnow)
    updated_at   = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Upload(Base):
    __tablename__ = "uploads"

    id                = Column(BigInteger, primary_key=True, index=True)
    user_id           = _uuid_col(nullable=False, index=True)          # ← Phase 2
    filename          = Column(String(255), nullable=False)
    file_type         = Column(String(10),  nullable=False)            # csv | pcap
    records_processed = Column(Integer, default=0)
    attacks_detected  = Column(Integer, default=0)
    high_risk_ips     = Column(Integer, default=0)
    status            = Column(String(20), default="pending")          # pending | completed | error
    uploaded_at       = Column(DateTime,  default=datetime.utcnow)
    error_message     = Column(Text, nullable=True)

    requests = relationship("Request", back_populates="upload", cascade="all, delete-orphan")


class Request(Base):
    __tablename__ = "requests"

    id             = Column(BigInteger, primary_key=True, index=True)
    upload_id      = Column(BigInteger, ForeignKey("uploads.id", ondelete="CASCADE"), nullable=True)
    timestamp      = Column(DateTime, nullable=True)
    source_ip      = Column(String(45), nullable=False, index=True)
    destination_ip = Column(String(45), nullable=True)
    method         = Column(String(10), nullable=True)
    host           = Column(String(255), nullable=True)
    url            = Column(Text, nullable=True)
    user_agent     = Column(Text, nullable=True)
    status_code    = Column(Integer, nullable=True)
    response_size  = Column(Integer, nullable=True)

    upload     = relationship("Upload", back_populates="requests")
    detections = relationship("Detection", back_populates="request", cascade="all, delete-orphan")


class Detection(Base):
    __tablename__ = "detections"

    id               = Column(BigInteger, primary_key=True, index=True)
    user_id          = _uuid_col(nullable=False, index=True)           # ← Phase 2
    request_id       = Column(BigInteger, ForeignKey("requests.id", ondelete="CASCADE"), nullable=False, index=True)
    attack_type      = Column(String(100), nullable=False, index=True)
    severity         = Column(String(20),  nullable=False)             # LOW | MEDIUM | HIGH | CRITICAL
    confidence       = Column(Float,       nullable=False)
    detection_method = Column(String(20),  nullable=False)             # RULE | ML | HYBRID
    result           = Column(String(30),  nullable=False)             # ATTEMPT | POTENTIAL_SUCCESS
    created_at       = Column(DateTime, default=datetime.utcnow, index=True)

    # Denormalized snapshot for fast dashboard queries
    source_ip  = Column(String(45),  nullable=True)
    url        = Column(Text,        nullable=True)
    host       = Column(String(255), nullable=True)

    request = relationship("Request", back_populates="detections")


class IPAnalysis(Base):
    __tablename__ = "ip_analysis"
    __table_args__ = (
        # Phase 2: per-user uniqueness (each user has their own IP risk profile)
        UniqueConstraint("user_id", "ip_address", name="uq_user_ip"),
    )

    id            = Column(BigInteger, primary_key=True, index=True)
    user_id       = _uuid_col(nullable=False, index=True)              # ← Phase 2
    ip_address    = Column(String(45), nullable=False, index=True)
    risk_score    = Column(Integer,    default=0)
    risk_level    = Column(String(20), default="LOW")                  # LOW | MEDIUM | HIGH | CRITICAL
    attack_count  = Column(Integer,    default=0)
    request_count = Column(Integer,    default=0)
    attack_types  = Column(Text,       nullable=True)                  # JSON-encoded list
    last_seen     = Column(DateTime,   nullable=True)
    geo_country   = Column(String(100), nullable=True)
    geo_city      = Column(String(100), nullable=True)
    isp           = Column(String(200), nullable=True)
    first_seen    = Column(DateTime, default=datetime.utcnow)
    updated_at    = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

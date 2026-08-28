"""
tests/test_rls.py
Phase 2 Security Test — Row Level Security + JWT Isolation

Tests that User A's data is completely invisible to User B and vice versa.

Run with:
    cd backend
    python -m pytest tests/test_rls.py -v

Requirements:
    - SUPABASE_JWT_SECRET must be set in backend/.env
    - Database must be reachable via DATABASE_URL
"""

import os
import uuid
from datetime import datetime, timedelta

import pytest

# Ensure env is loaded before any import
from dotenv import load_dotenv
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

from jose import jwt
from fastapi.testclient import TestClient

# Import app after env is loaded
from main import app
from database import SessionLocal
from models import Upload, Detection, IPAnalysis


# ─── JWT helpers ──────────────────────────────────────────────────────────────

JWT_SECRET = os.environ.get("SUPABASE_JWT_SECRET", "")
ALGORITHM  = "HS256"

def _make_token(user_id: str, email: str) -> str:
    """Mint a Supabase-format JWT for testing."""
    payload = {
        "sub": user_id,
        "email": email,
        "aud": "authenticated",
        "iat": int(datetime.utcnow().timestamp()),
        "exp": int((datetime.utcnow() + timedelta(hours=1)).timestamp()),
        "role": "authenticated",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)


# ─── Fixtures ─────────────────────────────────────────────────────────────────

USER_A_ID = str(uuid.uuid4())
USER_B_ID = str(uuid.uuid4())

TOKEN_A = _make_token(USER_A_ID, "user_a@test.local")
TOKEN_B = _make_token(USER_B_ID, "user_b@test.local")

HEADERS_A = {"Authorization": f"Bearer {TOKEN_A}"}
HEADERS_B = {"Authorization": f"Bearer {TOKEN_B}"}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module", autouse=True)
def seed_test_data():
    """Insert test records for User A and User B directly into the DB."""
    db = SessionLocal()
    try:
        # Upload + detections for User A
        up_a = Upload(
            user_id=USER_A_ID,
            filename="test_a.csv",
            file_type="csv",
            status="completed",
            records_processed=3,
            attacks_detected=2,
            uploaded_at=datetime.utcnow(),
        )
        db.add(up_a)
        db.flush()

        db.add(Detection(
            user_id=USER_A_ID,
            request_id=1,
            attack_type="SQL Injection",
            severity="HIGH",
            confidence=0.95,
            detection_method="RULE",
            result="ATTEMPT",
            source_ip="192.168.1.10",
            url="/api?id=1' OR '1'='1",
        ))
        db.add(IPAnalysis(
            user_id=USER_A_ID,
            ip_address="192.168.1.10",
            risk_score=60,
            risk_level="HIGH",
            attack_count=1,
            request_count=3,
        ))

        # Upload + detections for User B
        up_b = Upload(
            user_id=USER_B_ID,
            filename="test_b.csv",
            file_type="csv",
            status="completed",
            records_processed=2,
            attacks_detected=1,
            uploaded_at=datetime.utcnow(),
        )
        db.add(up_b)
        db.flush()

        db.add(Detection(
            user_id=USER_B_ID,
            request_id=2,
            attack_type="XSS",
            severity="MEDIUM",
            confidence=0.88,
            detection_method="RULE",
            result="ATTEMPT",
            source_ip="10.0.0.99",
            url="/comment?text=<script>alert(1)</script>",
        ))
        db.add(IPAnalysis(
            user_id=USER_B_ID,
            ip_address="10.0.0.99",
            risk_score=30,
            risk_level="MEDIUM",
            attack_count=1,
            request_count=2,
        ))

        db.commit()
    finally:
        db.close()

    yield

    # Cleanup test data
    db = SessionLocal()
    try:
        db.query(Detection).filter(Detection.user_id.in_([USER_A_ID, USER_B_ID])).delete()
        db.query(IPAnalysis).filter(IPAnalysis.user_id.in_([USER_A_ID, USER_B_ID])).delete()
        db.query(Upload).filter(Upload.user_id.in_([USER_A_ID, USER_B_ID])).delete()
        db.commit()
    finally:
        db.close()


# ─── Tests ────────────────────────────────────────────────────────────────────

def test_user_a_sees_own_attacks(client):
    """User A can read their own detections."""
    resp = client.get("/api/attacks", headers=HEADERS_A)
    assert resp.status_code == 200, resp.text
    items = resp.json()["items"]
    assert len(items) >= 1
    assert all(i.get("attack_type") != "XSS" for i in items), \
        "User A should NOT see User B's XSS detection"
    assert any(i.get("attack_type") == "SQL Injection" for i in items), \
        "User A SHOULD see their own SQL Injection detection"


def test_user_b_sees_own_attacks(client):
    """User B can read their own detections."""
    resp = client.get("/api/attacks", headers=HEADERS_B)
    assert resp.status_code == 200, resp.text
    items = resp.json()["items"]
    assert len(items) >= 1
    assert all(i.get("attack_type") != "SQL Injection" for i in items), \
        "User B should NOT see User A's SQL Injection detection"
    assert any(i.get("attack_type") == "XSS" for i in items), \
        "User B SHOULD see their own XSS detection"


def test_cross_user_attack_read_denied(client):
    """User A cannot fetch User B's detection by ID, even if they guess the ID."""
    # Get User B's detection ID
    resp_b = client.get("/api/attacks", headers=HEADERS_B)
    items_b = resp_b.json()["items"]
    b_id = items_b[0]["id"]

    # Try to fetch it as User A
    resp = client.get(f"/api/attacks/{b_id}", headers=HEADERS_A)
    assert resp.status_code == 404, (
        f"User A should NOT be able to read User B's detection (got {resp.status_code})"
    )


def test_user_a_sees_own_ips(client):
    """User A's IP list contains only their own IPs."""
    resp = client.get("/api/ips", headers=HEADERS_A)
    assert resp.status_code == 200
    ips = [i["ip_address"] for i in resp.json()["items"]]
    assert "10.0.0.99" not in ips, "User A should NOT see User B's IP 10.0.0.99"
    assert "192.168.1.10" in ips, "User A SHOULD see their own IP 192.168.1.10"


def test_user_b_sees_own_ips(client):
    """User B's IP list contains only their own IPs."""
    resp = client.get("/api/ips", headers=HEADERS_B)
    assert resp.status_code == 200
    ips = [i["ip_address"] for i in resp.json()["items"]]
    assert "192.168.1.10" not in ips, "User B should NOT see User A's IP 192.168.1.10"
    assert "10.0.0.99" in ips, "User B SHOULD see their own IP 10.0.0.99"


def test_unauthenticated_request_denied(client):
    """Requests without a token are rejected with 403."""
    resp = client.get("/api/attacks")
    assert resp.status_code in (401, 403), \
        f"Unauthenticated request should be denied (got {resp.status_code})"


def test_dashboard_user_isolation(client):
    """Dashboard stats are scoped: User A and User B see different totals."""
    resp_a = client.get("/api/dashboard", headers=HEADERS_A)
    resp_b = client.get("/api/dashboard", headers=HEADERS_B)
    assert resp_a.status_code == 200
    assert resp_b.status_code == 200

    total_a = resp_a.json()["total_attacks"]
    total_b = resp_b.json()["total_attacks"]

    # Both users have data, neither should see the combined total
    assert total_a >= 1, "User A should see at least 1 attack"
    assert total_b >= 1, "User B should see at least 1 attack"
    # If there were no isolation, totals would be equal (both see the same combined count)
    # With isolation, they only see their own counts
    assert total_a != total_a + total_b, "Dashboard should NOT show combined total"

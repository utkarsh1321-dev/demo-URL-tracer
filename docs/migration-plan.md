# URL Tracer — Migration Plan

> Phase 0 Documentation | Architecture Decisions Frozen

---

## Frozen Architecture Decisions

These decisions are locked. Do not change without explicit team re-review.

| Decision | Choice | Rationale |
|---|---|---|
| Database | Supabase (PostgreSQL + RLS) | Built-in RLS, managed, scalable |
| Authentication | Supabase Auth + JWT | No custom auth code; direct RLS integration |
| URL Analysis | Static only — no server-side browsing | Prevents SSRF risk |
| ML Training Data | Real public datasets (Phase 4) | Synthetic data has no real-world validity |
| Detection Pipeline | Single shared engine | No duplication across web/PCAP/extension |
| PCAP Processing | Real `pcap/` module (Scapy) | Module is already built and tested |
| Chrome Extension auth | User JWT via backend only | Never holds service-role key |
| Backend deployment | Render (modular — portable) | Can move to Railway/GCP without app changes |
| Frontend deployment | Vercel (existing) | Existing deployment preserved |

---

## Phase Roadmap

### ✅ Phase 0 — Repository Audit & Architecture Freeze
**Goal:** Understand the codebase before changing anything.

**Deliverables:**
- [x] Full repository inventory
- [x] Security scan — clean
- [x] `.gitignore` hardened
- [x] `backend/.env.example` created
- [x] `frontend/.env.example` created
- [x] `docs/` directory created (this file)
- [x] Git tag: `v0.0-pre-production`

**Rule:** No source code modified.

---

### ✅ Phase 1 — Remove Synthetic Demo Data
**Goal:** Strip all fake data. Backend starts clean with an empty database.

**Files changed:**
- `backend/main.py` — Remove seed import/call, update branding
- `backend/utils/seed.py` → No-op stub
- `backend/services/pcap_service.py` → Clean stub (no synthetic generation)
- `backend/sample_data/test_upload.csv` → Deleted
- `frontend/src/mock/mockData.js` → Emptied
- `frontend/src/api/apiService.js` → `USE_MOCK` removed; all real API calls
- `frontend/src/pages/Dashboard.jsx` → STREAM_EVENTS, DEMO DATA badge, fake trends, 94% score removed; empty states added
- `frontend/src/pages/MLIntelligence.jsx` → DEMO_PAYLOADS → EXAMPLE_PAYLOADS

**Preserved:** All detection logic, ML pipeline, PCAP module, API routes, DB schema.

**Acceptance criteria:**
- Dashboard shows all zeros with empty states
- No mock data in any API response
- Frontend communicates with real backend
- Git commit: `phase-1: remove synthetic demo data`

---

### Phase 2 — Production Database + Authentication + RLS
**Goal:** Real users. Real user-scoped data. Supabase.

**New components:**
- Supabase project (fresh — created in Phase 2)
- `backend/auth.py` — JWT verification middleware
- `backend/supabase_client.py` — Supabase client
- `backend/database.py` — Replace SQLite with PostgreSQL via `DATABASE_URL`
- Supabase migration SQL — new schema with `user_id UUID` + RLS policies
- `frontend/src/auth/` — AuthContext, Login, Register pages
- `@supabase/supabase-js` added to frontend

**Database schema changes:**
```sql
-- Add user_id to uploads, detections, ip_analysis
ALTER TABLE uploads     ADD COLUMN user_id UUID NOT NULL;
ALTER TABLE detections  ADD COLUMN user_id UUID NOT NULL;
ALTER TABLE ip_analysis ADD COLUMN user_id UUID NOT NULL;

-- Row Level Security
ALTER TABLE uploads     ENABLE ROW LEVEL SECURITY;
ALTER TABLE detections  ENABLE ROW LEVEL SECURITY;
ALTER TABLE ip_analysis ENABLE ROW LEVEL SECURITY;

-- Policies: users see only their own data
CREATE POLICY "uploads_user_isolation"
  ON uploads FOR ALL
  USING (auth.uid() = user_id);
```

**Security rule (non-negotiable):**
> The backend NEVER trusts a `user_id` from the request body.
> It ALWAYS reads `user_id` from the verified Supabase JWT (`sub` claim).

**Acceptance criteria:**
- Users can register, log in, log out
- Each user sees only their own data
- RLS enforced at database level
- JWT verified on every protected endpoint

---

### Phase 3 — URL Analysis Engine
**Goal:** Direct URL submission. Static analysis only.

**New endpoint:** `POST /api/analyze/url`

```python
# Request
{ "url": "https://example.com/path?query=value" }

# Response
{
  "url": "...",
  "risk_level": "HIGH",
  "risk_score": 75,
  "detections": [...],
  "ml_prediction": {...},
  "features": {...}
}
```

**No server-side URL fetching.** Static feature extraction only:
- URL length, path depth, query parameter count
- Special character density, encoding patterns
- Typosquatting detection (domain similarity)
- Known phishing pattern matching
- ML classification

---

### Phase 4 — Real ML Dataset & Training
**Goal:** Replace synthetic training data with real public datasets.

**Data sources (no legal restrictions):**
- [Kaggle Phishing URL Dataset](https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls) — 11K+ URLs, labeled phishing/legitimate
- [PhishTank](https://www.phishtank.com/developer_info.php) — verified phishing URLs (CC0)
- [ISCX-URL-2016](https://www.unb.ca/cic/datasets/url-2016.html) — 35K URLs, 5 classes
- [URLhaus](https://urlhaus.abuse.ch/api/) — malicious URL feed

**Pipeline:**
1. Download datasets
2. Merge, deduplicate, stratify
3. Feature extraction (existing `features.py` — reuse)
4. Retrain RandomForest
5. Evaluate on real held-out data
6. Save model artifact

**Files changed:**
- `ML/ml_data/generate_dataset.py` → Replaced with `download_datasets.py`
- `ML/ml_data/train.py` → Updated for multi-source datasets
- `ML/ml_data/preprocessing.py` → Updated cleaning for real data

---

### Phase 5 — ML Integration with Backend
**Goal:** Connect real-trained model to backend. Update ML API.

**Files changed:**
- `backend/services/ml_service.py` — Confidence thresholds tuned for real data
- `backend/api/ml.py` — Remove "Prototype Prediction" labels
- Model path from `MODEL_PATH` env var

---

### Phase 6 — Authenticated Dashboard
**Goal:** Frontend shows authenticated user's own history.

**Files changed:**
- `frontend/src/App.jsx` — Add `<PrivateRoute>` guard
- All dashboard pages — scoped to authenticated user's data
- `frontend/src/api/apiService.js` — Add `Authorization: Bearer {jwt}` header

---

### Phase 7 — Real PCAP Analysis
**Goal:** Replace `pcap_service.py` stub with real Scapy-based parsing.

**One function change in `backend/services/pcap_service.py`:**
```python
from pcap.processor import process_pcap as _real_process

def process_pcap(file_path: str) -> list[dict]:
    result = _real_process(file_path)
    if result["status"] == "ERROR":
        raise ValueError(result["error"])
    return result["records"]
```

**Add to `backend/requirements.txt`:**
```
scapy>=2.5.0
```

The `pcap/` module is already complete and tested. This is a minimal integration.

---

### Phase 8 — Chrome Extension
**Goal:** Extension that checks the current tab URL against the URL analysis API.

**Architecture:**
```
Chrome Extension
  ↓  (user's Supabase JWT — obtained from web frontend session)
POST /api/analyze/url
  ↓  Authorization: Bearer {jwt}
FastAPI backend verifies JWT → runs analysis → returns risk result
  ↓
Extension popup shows risk badge
```

**Security rules:**
- Extension NEVER holds service-role key
- Extension uses user's JWT only
- JWT obtained via `chrome.storage.session` (not `localStorage`)
- Extension only sends current tab URL — does not intercept traffic

---

### Phase 9 — Security Hardening
**Goal:** Production-grade security on all endpoints.

**Changes:**
- `allow_origins` → restricted to frontend production URL
- Rate limiting via `slowapi`:
  - `POST /api/analyze/url`: 20 req/min per user
  - `POST /api/upload/pcap`: 5 req/min per user
  - `POST /api/ml/predict`: 30 req/min per user
- Input validation audit — all URL inputs sanitized before processing
- Security headers (HSTS, X-Frame-Options, CSP)
- Remove all stack traces from error responses

---

### Phase 10 — Production Deployment
**Goal:** CI/CD pipeline. Environment secrets. Production hosting.

**Backend (Render):**
- `render.yaml` — service configuration
- Environment variables set in Render dashboard (never in git)
- Auto-deploy on push to `main`

**Frontend (Vercel):**
- Environment variables set in Vercel dashboard
- Auto-deploy on push to `main`

**GitHub Actions CI:**
- Lint + tests on every PR
- Block merge if tests fail

---

## Environment Variables Reference

### Backend (`.env`)

| Variable | Required From | Description |
|---|---|---|
| `DATABASE_URL` | Phase 2 | PostgreSQL connection string |
| `SUPABASE_URL` | Phase 2 | Supabase project URL |
| `SUPABASE_ANON_KEY` | Phase 2 | Supabase public anon key |
| `SUPABASE_SERVICE_ROLE_KEY` | Phase 2 | Backend admin key — never frontend |
| `SUPABASE_JWT_SECRET` | Phase 2 | For JWT verification |
| `MODEL_PATH` | Phase 5 | Path to trained RF model |
| `APP_ENV` | Phase 2 | development \| staging \| production |
| `ALLOWED_ORIGINS` | Phase 9 | Comma-separated allowed CORS origins |
| `RATE_LIMIT_URL_ANALYSIS` | Phase 9 | Requests per minute |

### Frontend (`.env.local`)

| Variable | Required From | Description |
|---|---|---|
| `VITE_API_URL` | Phase 1 | Backend URL |
| `VITE_SUPABASE_URL` | Phase 2 | Supabase project URL |
| `VITE_SUPABASE_ANON_KEY` | Phase 2 | Supabase anon key (safe to expose) |
| `VITE_APP_ENV` | Phase 2 | Environment name |

# URL Tracer — Current Architecture

> Phase 0 Documentation | Status: Pre-Production Transition

---

## Current State (Phase 0 Baseline)

```
┌─────────────────────────────────────────────────────┐
│              React Frontend (Vite)                  │
│  USE_MOCK=true → mockData.js (25 KB synthetic data) │
│  Pages: Dashboard, Attacks, IPs, PCAP, ML, Reports  │
└──────────────────────┬──────────────────────────────┘
                       │ HTTP (proxied via Vite)
                       ▼
┌─────────────────────────────────────────────────────┐
│              FastAPI Backend                        │
│  No authentication. CORS: allow_origins=["*"]       │
│  Database: SQLite (demo.db, auto-seeded on startup) │
│                                                     │
│  Routers:                                           │
│    /api/dashboard   /api/attacks   /api/ips         │
│    /api/upload      /api/export    /api/ml          │
│                                                     │
│  Detection Engine (backend/detection/)              │
│    12 rule-based detectors (SQL, XSS, SSRF, ...)    │
│    + ML service bridge (graceful degradation)       │
│                                                     │
│  ML Pipeline (ML/ml_data/)                         │
│    RandomForest, synthetic dataset, ~1100 records   │
│                                                     │
│  PCAP service (backend/services/pcap_service.py)    │
│    STUB: generates synthetic records from file size │
│    Real Scapy module exists in pcap/ but UNUSED     │
└──────────────────────┬──────────────────────────────┘
                       │ SQLAlchemy ORM
                       ▼
              ┌─────────────────┐
              │  SQLite demo.db │
              │  No RLS. No     │
              │  user isolation │
              └─────────────────┘
```

---

## Target Architecture (Post-Production)

```
                    ┌─────────────────────┐
                    │   Chrome Extension  │  (Phase 8)
                    └──────────┬──────────┘
                               │ JWT via backend
                    ┌──────────▼──────────┐
                    │   React Frontend    │  Vercel
                    │   Supabase Auth     │
                    └──────────┬──────────┘
                               │ Bearer JWT
                               ▼
                    ┌─────────────────────┐
                    │   FastAPI Backend   │  Render
                    │   JWT verification  │
                    │   Rate limiting     │
                    │   CORS: locked      │
                    └──────────┬──────────┘
                               │
              ┌────────────────┼────────────────┐
              │                │                │
              ▼                ▼                ▼
        URL Analysis      PCAP Analysis    Supabase Auth
        (Phase 3)         (Phase 7)
              │                │
              └────────────────┘
                       │
                  ML Inference
                  Real Dataset
                  (Phase 4+5)
                       │
                  Risk Scoring
                       │
              ┌────────────────┐
              │  PostgreSQL    │  Supabase
              │  RLS enabled   │
              │  user_id FK    │
              └────────────────┘
```

---

## Component Inventory

### Backend (`backend/`)

| File | Role | Phase to Modify |
|---|---|---|
| `main.py` | FastAPI app, CORS, lifespan | Phase 1, 9 |
| `database.py` | SQLAlchemy engine — SQLite hardcoded | Phase 2 |
| `models.py` | ORM models — no `user_id` | Phase 2 |
| `schemas.py` | Pydantic schemas | Phase 2, 3 |
| `api/dashboard.py` | Aggregate stats | Phase 2, 6 |
| `api/attacks.py` | Paginated detections | Phase 2 |
| `api/ips.py` | IP profiles | Phase 2 |
| `api/upload.py` | CSV + PCAP upload | Phase 2, 7 |
| `api/ml.py` | ML endpoints | Phase 5 |
| `api/export.py` | CSV/JSON export | Phase 2 |
| `detection/engine.py` | 12-detector orchestrator | **Preserve** |
| `detection/*.py` | Rule detectors | **Preserve** |
| `services/ml_service.py` | ML bridge, graceful fallback | Phase 5 |
| `services/csv_service.py` | CSV processing pipeline | Phase 2 |
| `services/pcap_service.py` | PCAP stub → real | Phase 7 |
| `utils/seed.py` | Demo seeder | **Removed Phase 1** |
| `utils/normalizer.py` | Timestamp/column normalizer | **Preserve** |
| `risk/scorer.py` | Risk scoring | **Preserve** |

### Frontend (`frontend/`)

| File/Dir | Role | Phase to Modify |
|---|---|---|
| `src/api/apiService.js` | Central API client | Phase 1, 2 |
| `src/mock/mockData.js` | 25 KB synthetic data | **Removed Phase 1** |
| `src/App.jsx` | Router — no auth guard | Phase 2, 6 |
| `src/pages/Dashboard.jsx` | Main dashboard | Phase 1, 6 |
| `src/pages/MLIntelligence.jsx` | ML tester | Phase 5 |
| `src/pages/PCAPAnalysis.jsx` | PCAP upload | Phase 7 |

### ML (`ML/ml_data/`)

| File | Role | Phase to Modify |
|---|---|---|
| `generate_dataset.py` | Synthetic data gen | **Replaced Phase 4** |
| `train.py` | Training pipeline | Phase 4 |
| `features.py` | Feature extraction (13 features) | Phase 4 |
| `predict.py` | Inference | Phase 5 |
| `model.py` | RF model build/eval | Phase 4 |
| `preprocessing.py` | Data cleaning | Phase 4 |

### PCAP (`pcap/`)

| File | Role | Phase to Modify |
|---|---|---|
| `processor.py` | Entry point: `process_pcap()` | **Phase 7 integrates** |
| `extractor.py` | Packet extraction, TLS detection | **Preserve** |
| `parser.py` | File validation + Scapy load | **Preserve** |
| `normalizer.py` | Canonical schema output | **Preserve** |
| `models.py` | ProcessingResult dataclass | **Preserve** |

---

## Technology Stack

| Layer | Technology |
|---|---|
| Frontend | React 18, Vite, Tailwind CSS, Recharts, react-router-dom v6 |
| Backend | FastAPI 0.111, Uvicorn, SQLAlchemy 2.0, Pydantic v2 |
| Database (current) | SQLite |
| Database (target) | PostgreSQL via Supabase |
| Auth (target) | Supabase Auth + JWT |
| ML | scikit-learn RandomForest, pandas, numpy |
| PCAP | Scapy |
| Backend deployment | Render |
| Frontend deployment | Vercel |

---

## Reusable Components — Do Not Modify Unless Required

| Component | Why Protected |
|---|---|
| `backend/detection/` | 12 clean rule detectors; modular; exception-safe |
| `backend/risk/scorer.py` | Correct risk scoring logic |
| `backend/utils/normalizer.py` | Used by CSV and upload pipeline |
| `backend/services/ml_service.py` | Caller interface is stable |
| `pcap/` (entire module) | Real, tested, Scapy-based — ready for Phase 7 |

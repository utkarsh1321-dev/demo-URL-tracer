# URL Tracer — Repository Audit

> Phase 0 Security & Inventory Audit | Date: 2026-08-28

---

## Security Scan Results

> **RESULT: CLEAN — No real credentials found anywhere.**

### Scan Coverage

| Scan | Method | Result |
|---|---|---|
| `.env` files in git history | `git log --all -p -- "*.env"` | No real `.env` files ever committed |
| `.env` in working tree | Filesystem search | None present |
| Supabase keys | Pattern: `eyJhbGciOiJ` (JWT prefix) | Not found |
| Database passwords | Pattern: `postgresql://[user]:[pass]@` | Not found |
| API keys | Patterns: `sk-`, `ghp_`, `service_role` | Not found |
| Credential files | `credentials.json`, `service-account.json` | Not found |
| Git history (5 commits) | Full diff scan | No sensitive files |

### False Positives (Synthetic Attack Data)

All `password`, `token`, and `secret` matches in source code are **synthetic attack URL patterns** used as test data — not real credentials:

```
/api/user?id=1 UNION SELECT username,password FROM users--   ← SQL injection test URL
/login?email=user@test.com&password=P@ssw0rd1                ← synthetic credential stuffing URL
/submit?token=abc&token=hacked                               ← HTTP parameter pollution test
```

These strings exist inside:
- `backend/utils/seed.py` (demo seeder — removed Phase 1)
- `ML/ml_data/generate_dataset.py` (synthetic dataset generator)
- `frontend/src/mock/mockData.js` (demo mock data)
- `pcap/demo/generate_demo_pcap.py` (demo PCAP generator)

None of these are real credentials.

### `database.py` — NOT a credential

```python
DATABASE_URL = "sqlite:///./demo.db"
```

This is a local SQLite file path. There is no password. This is a development default that will be replaced by a real `DATABASE_URL` environment variable in Phase 2.

### Recommendation

**No credential rotation required.** No real secrets were exposed.

---

## Synthetic / Demo Data Locations

All synthetic data removed or emptied in Phase 1.

| Location | Type | Content | Phase |
|---|---|---|---|
| `backend/utils/seed.py` | Demo seeder | 36 attack records + 160 benign records; 8 fake IPs | Removed Phase 1 |
| `backend/services/pcap_service.py` | PCAP stub | Generates synthetic HTTP records from file size | Replaced Phase 1 |
| `frontend/src/mock/mockData.js` | Mock data | 25 KB: fake attacks, IPs, dashboard stats, PCAP results | Emptied Phase 1 |
| `frontend/src/api/apiService.js` | Mock flag | `USE_MOCK = true` — all API calls returned fake data | Removed Phase 1 |
| `backend/sample_data/test_upload.csv` | Test file | Sample CSV with synthetic HTTP records | Deleted Phase 1 |
| `Database/database/seed_demo_data.py` | Legacy seeder | Legacy SQLite seed (not used by backend) | Not used |
| `Database/database/reset_demo_database.py` | Legacy reset | Legacy DB reset script | Not used |
| `ML/ml_data/generate_dataset.py` | Synthetic ML | ~1100 synthetic URL records for RF training | Replaced Phase 4 |

---

## Hardcoded Values (Pre-Production)

| File | Hardcoded Value | Risk | Fix Phase |
|---|---|---|---|
| `backend/database.py` | `sqlite:///./demo.db` | No credential risk; not production-grade | Phase 2 |
| `backend/main.py` | `allow_origins=["*"]` | CORS wildcard — any origin can call API | Phase 9 |
| `frontend/src/api/apiService.js` | `USE_MOCK = true` | All data was fake | Phase 1 ✅ |
| `backend/main.py` | `seed_database(db)` on startup | Auto-populates with fake data | Phase 1 ✅ |

---

## API Endpoints (Full Inventory)

All endpoints are currently **unauthenticated**. Auth added in Phase 2.

| Method | Path | Description | Auth Phase |
|---|---|---|---|
| GET | `/` | Health check | Public forever |
| GET | `/api/health` | Health check | Public forever |
| GET | `/api/dashboard` | Aggregate stats | Phase 2 |
| GET | `/api/attacks` | Paginated detections | Phase 2 |
| GET | `/api/attacks/{id}` | Single detection | Phase 2 |
| GET | `/api/ips` | IP profiles list | Phase 2 |
| GET | `/api/ips/{ip}` | Single IP profile | Phase 2 |
| POST | `/api/upload/csv` | CSV upload + process | Phase 2 |
| POST | `/api/upload/pcap` | PCAP upload + process | Phase 2 |
| GET | `/api/export/csv` | CSV export | Phase 2 |
| GET | `/api/export/json` | JSON export | Phase 2 |
| GET | `/api/ml/status` | ML model status | Public |
| POST | `/api/ml/predict` | Single ML prediction | Phase 9 (rate limit) |
| POST | `/api/ml/predict/batch` | Batch ML prediction | Phase 9 (rate limit) |
| GET | `/api/ml/metrics` | Training metrics | Public |

---

## Database Schema (Current — SQLite)

### Table: `uploads`
| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| filename | VARCHAR(255) | |
| file_type | VARCHAR(10) | csv \| pcap |
| records_processed | INTEGER | |
| attacks_detected | INTEGER | |
| high_risk_ips | INTEGER | |
| status | VARCHAR(20) | pending \| processing \| completed \| error |
| uploaded_at | DATETIME | |
| error_message | TEXT | nullable |

### Table: `requests`
| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| timestamp | DATETIME | from source data |
| source_ip | VARCHAR(45) | indexed |
| destination_ip | VARCHAR(45) | |
| method | VARCHAR(10) | |
| host | VARCHAR(255) | |
| url | TEXT | |
| user_agent | TEXT | |
| status_code | INTEGER | |
| response_size | INTEGER | |
| upload_id | INTEGER FK | → uploads.id |

### Table: `detections`
| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| request_id | INTEGER FK | → requests.id (indexed) |
| attack_type | VARCHAR(100) | indexed |
| severity | VARCHAR(20) | LOW \| MEDIUM \| HIGH \| CRITICAL |
| confidence | FLOAT | |
| detection_method | VARCHAR(20) | RULE \| ML \| HYBRID |
| result | VARCHAR(30) | ATTEMPT \| POTENTIAL_SUCCESS |
| created_at | DATETIME | |
| source_ip | VARCHAR(45) | denormalized for fast queries |
| url | TEXT | denormalized |
| host | VARCHAR(255) | denormalized |

### Table: `ip_analysis`
| Column | Type | Notes |
|---|---|---|
| id | INTEGER PK | |
| ip_address | VARCHAR(45) UNIQUE | indexed |
| risk_score | INTEGER | computed score |
| risk_level | VARCHAR(20) | LOW \| MEDIUM \| HIGH \| CRITICAL |
| attack_count | INTEGER | |
| request_count | INTEGER | |
| attack_types | TEXT | JSON-encoded list |
| last_seen | DATETIME | |
| geo_country | VARCHAR(100) | "Simulated" (Phase 0) |
| geo_city | VARCHAR(100) | "Simulated" (Phase 0) |
| isp | VARCHAR(200) | "Simulated ISP" (Phase 0) |
| first_seen | DATETIME | |
| updated_at | DATETIME | |

> **Note:** No `user_id` column exists. No row-level security. Phase 2 migration adds `user_id UUID NOT NULL` and enables RLS.

---

## Authentication

**No authentication exists anywhere in the current system.**

- No login / register endpoints
- No JWT verification
- No user sessions
- No API keys
- No protected routes on backend or frontend

Phase 2 implements Supabase Auth + JWT.

---

## Dependencies

### Backend (`backend/requirements.txt`)

```
fastapi==0.111.0
uvicorn[standard]==0.29.0
sqlalchemy==2.0.30
pydantic==2.7.1
pandas>=2.0.0
python-multipart==0.0.9
aiofiles==23.2.1
python-Levenshtein==0.25.1
scikit-learn>=1.4.0
numpy>=1.26.0
```

**Missing for production** (added in later phases):
- `python-dotenv` — environment variable loading (Phase 2)
- `supabase` — Supabase Python client (Phase 2)
- `python-jose[cryptography]` — JWT verification (Phase 2)
- `slowapi` — rate limiting (Phase 9)
- `scapy` — real PCAP parsing (Phase 7)

### Frontend (`frontend/package.json`)

```json
"dependencies": {
  "react": "^18.3.1",
  "react-dom": "^18.3.1",
  "react-router-dom": "^6.26.1",
  "recharts": "^2.12.7",
  "lucide-react": "^0.441.0",
  "date-fns": "^3.6.0"
}
```

**Missing for production:**
- `@supabase/supabase-js` — Supabase Auth client (Phase 2)

---

## Security Findings

| ID | Finding | Severity | Fix Phase |
|---|---|---|---|
| S-01 | CORS `allow_origins=["*"]` | HIGH | Phase 9 |
| S-02 | No authentication on any endpoint | CRITICAL | Phase 2 |
| S-03 | No user isolation / RLS | CRITICAL | Phase 2 |
| S-04 | Backend would trust client `user_id` | CRITICAL | Phase 2 |
| S-05 | Frontend `USE_MOCK=true` — real backend never used | MEDIUM | Phase 1 ✅ |
| S-06 | Auto-seed fake data on startup | LOW | Phase 1 ✅ |
| S-07 | ML metrics 404 leaks internal file path | LOW | Phase 5 |
| S-08 | No rate limiting on any endpoint | HIGH | Phase 9 |
| S-09 | No `.env.example` template | MEDIUM | Phase 0 ✅ |
| S-10 | PCAP stub — uploaded file never actually parsed | MEDIUM | Phase 7 |
| S-11 | Real `pcap/` module not integrated | MEDIUM | Phase 7 |
| S-12 | ML trained on synthetic data only | HIGH | Phase 4 |
| S-13 | No rate limiting for ML inference | HIGH | Phase 9 |
| S-14 | Legacy `Database/database/` scripts unused | LOW | Documented |

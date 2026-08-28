# URL Tracer — Data Flow Documentation

> Phase 0 Documentation

---

## 1. Demo Seed Flow (Phase 0 — Removed in Phase 1)

```
Application startup
    ↓
lifespan() in main.py
    ↓
seed_database(db)  ← utils/seed.py
    ↓
Inserts ~200 synthetic records into SQLite:
  • 36 attack requests (SQL, XSS, SSRF, etc.)
  • 160 benign requests
  • ip_analysis rows for 8 attacker IPs
```

**Status:** Removed in Phase 1. `seed_database()` is now a no-op.

---

## 2. CSV Upload Flow

```
POST /api/upload/csv
    ↓
api/upload.py
  • Validate extension (.csv)
  • Read bytes, check size (max 50 MB)
    ↓
services/csv_service.process_csv_upload()
  • pandas read_csv
  • normalize_columns() → column name mapping
    ↓
Per-row loop:
  normalize_row()
      ↓
  INSERT Request → SQLite
      ↓
  detection/engine.run_detection(record)
      ↓  [returns best result or None]
  If None → services/ml_service.predict(record)
      ↓  [heuristic or RF model]
  If detection → INSERT Detection → SQLite
      ↓
  Track ip_detections, ip_request_counts
    ↓
_upsert_ip_analysis() → INSERT/UPDATE ip_analysis
    ↓
UPDATE Upload record (status=completed, counts)
    ↓
db.commit()
    ↓
UploadResponse { status, upload_id, records_processed,
                 attacks_detected, high_risk_ips }
```

---

## 3. PCAP Upload Flow

### Phase 0 (Stub — synthetic data)
```
POST /api/upload/pcap
    ↓
api/upload.py
  • Validate extension (.pcap/.pcapng/.cap)
  • Write to temp file
  • CREATE Upload record
    ↓
services/pcap_service.process_pcap(tmp_path)
  ← STUB: generates random records seeded by file size
  ← NOT real parsing
    ↓
[Same detection pipeline as CSV]
    ↓
os.unlink(tmp_path)
```

### Phase 1 (Stub — empty, no synthetic data)
```
POST /api/upload/pcap
    ↓
services/pcap_service.process_pcap(tmp_path)
  ← Returns [] (empty list)
  ← Upload completes with 0 records processed
```

### Phase 7 (Real — Scapy-based)
```
POST /api/upload/pcap
    ↓
pcap.processor.process_pcap(tmp_path)
  ← Real Scapy rdpcap() loading
  ← Per-packet: IP/TCP metadata extraction
  ← TLS/HTTPS detection → marked uninspectable
  ← HTTP/1.x request line + header parsing
  ← normalize_record() → canonical schema
    ↓
result["records"]  → [same detection pipeline as CSV]
```

---

## 4. Detection Pipeline

```
request: dict
  {source_ip, url, method, host, user_agent,
   status_code, response_size, ...}
    ↓
detection/engine.run_detection(request)
    ↓
Run all 12 detectors in priority order:
  1. command_injection   (CRITICAL — checked first)
  2. webshell            (CRITICAL)
  3. sql_injection
  4. directory_traversal
  5. lfi_rfi
  6. xxe
  7. ssrf
  8. brute_force
  9. credential_stuffing
  10. xss
  11. http_param_pollution
  12. typosquatting
    ↓
Each detector returns Optional[dict]:
  { attack_type, severity, confidence,
    detection_method, result }
  or None if no match
    ↓
Select best result:
  max(severity_rank, confidence)
    ↓
Optional[dict]  ← None if no attack detected
```

---

## 5. ML Inference Flow

```
services/ml_service.predict(request_data)
    ↓
Is RF model loaded?
  YES → ML/ml_data/predict.py
          extract_features(request_data)
          rf_model.predict_proba()
          → { prediction, confidence, model: "RandomForest",
              ml_available: True }
  NO  → _heuristic_predict(request_data)
          Keyword matching against URL, host, user_agent
          → { prediction, confidence, model: "heuristic-fallback",
              ml_available: False }
```

---

## 6. Dashboard Flow

```
GET /api/dashboard
    ↓
api/dashboard.py
    ↓
SQLAlchemy aggregate queries:
  COUNT(requests)              → total_requests
  COUNT(detections)            → total_attacks
  COUNT(ip_analysis WHERE risk IN HIGH,CRITICAL) → high_risk_ips
  COUNT(ip_analysis WHERE risk = CRITICAL) → critical_ips
  GROUP BY attack_type         → attacks_by_type[]
  GROUP BY severity            → attacks_by_severity[]
  ORDER BY risk_score DESC LIMIT 10 → top_attacking_ips[]
  ORDER BY created_at DESC LIMIT 20 → recent_detections[]
  COUNT WHERE result=POTENTIAL_SUCCESS → potential_success_count
    ↓
DashboardResponse (all real DB counts, zero if empty)
```

---

## 7. Frontend Data Flow

### Phase 0 (Mock — removed in Phase 1)
```
React Component
    ↓
apiService.js  USE_MOCK=true
    ↓
mockData.js → hardcoded synthetic data
    ↓
Component renders fake stats
```

### Phase 1+ (Real)
```
React Component
    ↓
apiService.js  → fetch(VITE_API_URL + /api/...)
    ↓
FastAPI backend
    ↓
SQLite → real data (or empty zeros)
    ↓
Component renders real data / empty state
```

---

## 8. Risk Scoring Flow

```
ip_detections: list[dict]  (detections for one IP)
request_count: int
    ↓
risk/scorer.calculate_risk_score(detections, request_count)
    ↓
Base score = sum of severity weights:
  CRITICAL = 40 points
  HIGH     = 20 points
  MEDIUM   = 10 points
  LOW      =  5 points

Bonus for POTENTIAL_SUCCESS results
Bonus for high request volume
    ↓
risk_score: int
risk_level: LOW | MEDIUM | HIGH | CRITICAL
```

---

## 9. Single Reusable Analysis Pipeline (Target — Phase 3+)

All input sources funnel into the same pipeline:

```
Input Source
  ├── Web URL form (Phase 3)
  ├── PCAP upload (Phase 7)
  └── Chrome extension (Phase 8)
         ↓
  URL Normalization
         ↓
  Feature Extraction
         ↓
  Rule Detection (detection/engine.py)
         ↓
  ML Inference (ml_service.predict)
         ↓
  Risk Scoring (risk/scorer.py)
         ↓
  Result → Store → User
```

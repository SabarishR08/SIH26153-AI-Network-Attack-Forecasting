# Architecture — SIH26153 AI-Based Network Attack Forecasting

## Overview

NetWatch is a four-stage threat detection and forecasting pipeline that integrates three
existing open-source repositories into a single cohesive system. The pipeline ingests raw
network traffic, detects anomalies heuristically, forecasts escalation probability using
a sequence-aware ML model, and enriches detected incidents with MITRE ATT&CK kill chain
context — all surfaced through a Flask dashboard.

```
Network Traffic (synthetic CSV or live pcap)
        │
        ▼
┌───────────────────────────────────────────────┐
│  Stage 1 — Ingest & Anomaly Detection         │
│  Source: Network-Threat-Anomaly-Visualizer    │
│  Files:  repos/Network-Threat-Anomaly-        │
│          Visualizer/src/anomaly_detection.py  │
│  Output: data/packets.jsonl                   │
│          data/anomalies.jsonl                 │
└───────────────────┬───────────────────────────┘
                    │
                    ▼
┌───────────────────────────────────────────────┐
│  Stage 2 — Feature Extraction                 │
│  Source: NEW (integration layer)              │
│  Files:  integration/forecast_features.py     │
│  Method: 30s sliding windows per src-dst IP   │
│  Output: data/forecast_features.jsonl         │
└───────────────────┬───────────────────────────┘
                    │
                    ▼
┌───────────────────────────────────────────────┐
│  Stage 3 — Dual-Model Classification          │
│                                               │
│  Model A (Point-in-time Classifier)           │
│  Source: network-intrusion-detection (PS40)   │
│  Files:  repos/network-intrusion-detection/   │
│          src/train_model.py + predict.py      │
│  Method: Random Forest / Gradient Boosting    │
│          on NSL-KDD-style features            │
│  Metrics: accuracy=0.9976, f1=0.9978          │
│                                               │
│  Model B (Escalation Forecaster)              │
│  Source: NEW (integration layer)              │
│  Files:  integration/model_forecaster.py      │
│  Method: Gradient Boosting on 8-feature       │
│          sliding-window vectors               │
│  Metrics: accuracy=0.9876, f1=0.50,           │
│           roc_auc=0.8192 (honest, on          │
│           class-imbalanced synthetic data)    │
│  Output: data/forecast_features.jsonl         │
│          (augmented with escalation scores)   │
└───────────────────┬───────────────────────────┘
                    │
                    ▼
┌───────────────────────────────────────────────┐
│  Stage 4 — Kill Chain / MITRE Enrichment      │
│  Source: cyber-killchain-reconstruction-      │
│          engine + adapter (NEW)               │
│  Files:  integration/killchain_adapter.py     │
│          repos/cyber-killchain-.../           │
│            correlation/rules.py  (patched)   │
│            correlation/correlator.py (patched)│
│            killchain/mitre_mapping.py (patched│
│  Method: Rule-based correlation + MITRE ATT&CK│
│  Output: data/killchain_events.json           │
│          data/killchain_incidents.jsonl       │
└───────────────────┬───────────────────────────┘
                    │
                    ▼
┌───────────────────────────────────────────────┐
│  Stage 5 — Dashboard                          │
│  Source: NEW (integration layer)              │
│  Files:  integration/app.py                   │
│          integration/templates/               │
│          integration/static/                  │
│  Stack:  Flask 3 + Tailwind CSS + Plotly      │
│  Deploy: Render (gunicorn) / any WSGI host    │
└───────────────────────────────────────────────┘
```

---

## Source Repository Provenance

| Component | Original Repo | What we reused | What we added |
|---|---|---|---|
| Packet ingestion | Network-Threat-Anomaly-Visualizer | `AnomalyDetector`, `SyntheticDataGenerator` | — |
| Feature extraction | — | — | `ForecastFeatureExtractor` (NEW) |
| Model A classifier | network-intrusion-detection (PS40) | `train_model.py`, pre-trained `.pkl` | — |
| Model B forecaster | — | — | `EscalationForecaster` (NEW) |
| Kill chain rules | cyber-killchain-reconstruction-engine | `correlator.py`, `mitre_mapping.py`, `scoring.py` | 2 new rules + adapter |
| Dashboard | — | — | Full Flask app (NEW) |
| Test traffic generator | network-port-scanner | Used standalone for demo traffic | — |

---

## File Layout

```
sih153/                              ← workspace root
├── run.py                           ← single entry point
├── requirements.txt                 ← merged, pinned deps
├── Procfile                         ← Render / Heroku deploy
├── render.yaml                      ← Render service config
├── .env.example                     ← env var template
├── .gitignore
│
├── integration/                     ← all NEW integration code
│   ├── app.py                       ← Flask app + REST API + SSE
│   ├── config.py                    ← shared paths + feature flags
│   ├── forecast_features.py         ← sliding-window extractor
│   ├── model_forecaster.py          ← Model B training + inference
│   ├── killchain_adapter.py         ← network→killchain schema adapter
│   ├── pipeline_runner.py           ← end-to-end orchestrator
│   ├── templates/
│   │   ├── base.html
│   │   ├── index.html               ← Overview (stat cards + charts)
│   │   ├── events.html              ← Anomaly table + detail drawer
│   │   ├── graph.html               ← Plotly attack graph
│   │   └── killchain.html           ← MITRE incident cards
│   └── static/
│       ├── css/main.css
│       └── js/
│           ├── main.js              ← shared (pipeline trigger)
│           ├── overview.js
│           ├── events.js
│           ├── graph.js
│           └── killchain.js
│
├── data/                            ← generated at runtime (gitignored)
│   ├── packets.jsonl
│   ├── anomalies.jsonl
│   ├── forecast_features.jsonl
│   ├── forecast_model.pkl
│   ├── killchain_events.json
│   ├── killchain_incidents.jsonl
│   └── graph.json
│
├── repos/                           ← original repos (git history intact)
│   ├── Network-Threat-Anomaly-Visualizer/
│   ├── network-intrusion-detection/
│   ├── cyber-killchain-reconstruction-engine/
│   └── network-port-scanner/        ← test-traffic generator ONLY
│
└── docs/
    ├── ARCHITECTURE.md              ← this file
    ├── DEMO_SCRIPT.md
    └── RESULTS.md
```

---

## Data Schema

### packets.jsonl
Each line is one packet:
```json
{
  "timestamp": "2026-08-27T15:23:07",
  "src_ip": "192.168.1.101",
  "dst_ip": "10.0.0.5",
  "protocol": "TCP",
  "src_port": 54321,
  "dst_port": 22,
  "flags": "S",
  "payload_size": 0,
  "ttl": 64
}
```

### forecast_features.jsonl
Each line is one 30-second sliding window:
```json
{
  "src_ip": "192.168.1.101",
  "dst_ip": "10.0.0.5",
  "window_start": "...",
  "window_end": "...",
  "total_packets": 10,
  "port_diversity": 9,
  "connection_rate": 1.0,
  "syn_count": 9,
  "rst_count": 1,
  "syn_rst_ratio": 9.0,
  "payload_size_mean": 0.0,
  "payload_size_max": 0,
  "escalation_label": 1,
  "escalation_probability": 0.73,
  "escalation_predicted": true
}
```

### killchain_incidents.jsonl
```json
{
  "entity": "192.168.1.103",
  "pattern": "DoS Traffic Spike",
  "kill_chain_stage": "Actions on Objectives",
  "event_count": 6,
  "mitre": {
    "technique_id": "T1499",
    "technique_name": "Endpoint Denial of Service",
    "tactic": "Impact"
  },
  "risk_score": 70
}
```

---

## Feature Flags

| Variable | Default | Effect |
|---|---|---|
| `ENABLE_FORECASTING_MODEL` | `1` | Enable/disable Model B entirely |
| `ENABLE_KILLCHAIN` | `1` | Enable/disable kill chain enrichment |
| `FLASK_DEBUG` | `0` | Hot-reload for development |
| `PORT` | `5000` | Web server port |

---

## Kill Chain Correlation Rules

The engine runs four deterministic rules in order:

| Rule | Source | Trigger |
|---|---|---|
| `is_bruteforce` | original repo | ≥3 `login_failed` events in window |
| `is_credential_compromise` | original repo | `login_failed` → `login_success` |
| `is_portscan_to_exploit` | **NEW** | `port_scan_detected` followed by `brute_force_attempt` from same IP |
| `is_dos_traffic_spike` | **NEW** | ≥3 network anomalies from same IP, or connection cycling with ≥50 packets |

---

## Deployment

**Local:**
```bash
cp .env.example .env
pip install -r requirements.txt
python run.py
# open http://localhost:5000
```

**Render:**
- Connect repo → Render detects `render.yaml` automatically
- Set `FLASK_SECRET_KEY` as a secret env var in Render dashboard

**Vercel** (static front-end only — not applicable here, this is a Python backend app):
- Vercel does not natively run Python WSGI apps without serverless functions.
- Use Render, Railway, or Fly.io for this stack.

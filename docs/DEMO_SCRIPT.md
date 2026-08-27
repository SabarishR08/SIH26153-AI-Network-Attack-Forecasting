# Demo Script — SIH26153 NetWatch (3–5 minute live demo)

**Problem statement:** AI Based Network Attack Forecasting from Network Traffic Data  
**Problem owner:** NTRO  
**Team:** Sabarish R et al.

---

## Before the Demo (setup — do this in advance)

```bash
# 1. Install dependencies (once)
pip install -r requirements.txt

# 2. Copy environment config
cp .env.example .env

# 3. Verify setup
python run.py --no-pipeline
# Should print: Starting NetWatch dashboard at http://localhost:5000
# Ctrl+C to stop for now
```

---

## Step-by-step Live Demo

### 0:00 — Open the dashboard (empty state)

```bash
python run.py --no-pipeline
```

Open `http://localhost:5000` in browser.

**Say:** "This is NetWatch — our integrated threat forecasting system for SIH-26153.
Right now it's showing an empty state because no data has been processed yet.
Watch what happens when we run the full pipeline."

---

### 0:30 — Run the pipeline (click "Run Pipeline" button)

Click the green **"Run Pipeline"** button in the top-right corner of the dashboard.

A toast notification appears: "Running pipeline… Generating traffic, detecting anomalies,
forecasting escalations…"

The pipeline runs in ~3–5 seconds and the toast updates to show results:
`845 packets · 6 anomalies · 1 incident`

**Say:** "In one click, we just ran our entire 6-step pipeline:  
First, our synthetic traffic generator (from the Network Threat Anomaly Visualizer)
produced 845 packets — 800 normal baseline, plus injected attack patterns:
a port scan, a brute-force SSH attack, and connection cycling.  
Then our anomaly detector found 6 events.  
Then Model B analyzed 804 time windows to forecast escalation risk.  
Then our kill chain engine mapped everything to MITRE ATT&CK."

*(The dashboard auto-refreshes and all charts populate.)*

---

### 1:15 — Walk through the Overview page

Point to the **stat cards** at the top:
- "845 packets captured from 4 unique source IPs"
- "6 anomalies detected — Port Scan, Brute Force, Connection Cycling"
- "10 windows predicted to escalate by Model B"
- "1 kill chain incident confirmed by our rule-based correlator"

Point to the **Model A vs Model B panels**:

**Say:** "We have two complementary models. Model A is our baseline — a Random Forest
classifier trained on NSL-KDD data, achieving 99.76% accuracy on known attack signatures.
It tells us *is this traffic malicious right now.*

Model B is our forecasting layer — a Gradient Boosting model that analyzes 30-second
sliding windows per source IP, looking at port diversity, connection rate, SYN/RST ratios,
and payload statistics. It predicts the probability of escalation to a fuller attack
*before* it fully executes. That's the core innovation here."

Point to the **timeline chart**: "This shows anomaly frequency over time — you can see
the spike when our injected attacks hit."

---

### 2:00 — Switch to Events tab

Click **Events** in the nav.

**Say:** "Every detected anomaly is logged here with full context. Let me click on one."

Click any **Brute Force** row.

The right-side drawer opens showing:
- Source IP, target IP, destination port (22 = SSH)
- Severity: CRITICAL
- Model B forecast probability

**Say:** "Port 22, source 192.168.1.102, CRITICAL severity. Model B assigned this
source IP an escalation probability — early warning before the attacker completes
the full compromise cycle."

Use the **severity filter** to show only CRITICAL events — "you can filter by severity
or attack type to focus the analyst's attention."

---

### 2:45 — Switch to Attack Graph tab

Click **Attack Graph** in the nav.

**Say:** "This is the network topology view. Diamonds are attacker IPs, circles are
targets. Edges are colored by severity — red for critical, amber for high.
You can see 3 distinct attacker IPs converging on 3 target IPs with different
attack vectors.

This view directly answers the NTRO requirement for network-flow-based forecasting —
we can see the attack surface at a glance."

*(Pan/zoom the graph to show interactivity.)*

---

### 3:15 — Switch to Kill Chain tab

Click **Kill Chain** in the nav.

An incident card shows: **DoS Traffic Spike** — Risk Score 70/100 — MITRE T1499

**Say:** "Our kill chain engine is entirely rule-based — no ML, fully explainable,
which is important for a defensive intelligence tool. It correlates events across
a 10-minute window and maps them to the Lockheed Martin kill chain stages and
MITRE ATT&CK technique IDs.

This incident is mapped to T1499 — Endpoint Denial of Service under the Impact tactic.
The connection cycling from 192.168.1.103 triggered our new DoS traffic spike rule.

We also have a port-scan-to-exploit rule that fires when reconnaissance is followed
by exploitation attempts from the same IP — catching the classic recon→attack sequence."

---

### 3:45 — Close with architecture summary

Switch back to Overview.

**Say:** "To summarize the architecture:  
The system ingests traffic — live pcap or synthetic CSV.  
NTAV's heuristic engine flags point-in-time anomalies.  
Our new sliding-window forecaster predicts escalation 30–60 seconds ahead.  
The kill chain engine enriches everything with MITRE ATT&CK context.  
All of this feeds into this unified dashboard built on Flask, deployable to Render.

The system is modular — Model B and kill chain enrichment are behind feature flags,
so Model A alone is always a stable fallback. The four source repos' git histories
are all intact for the SIH submission provenance trail."

---

## Backup talking points (if asked)

**"Why not use a real dataset?"**  
The NSL-KDD dataset powers Model A (training accuracy 0.9976). Model B is trained on
synthetic data because we need labeled escalation sequences — NSL-KDD is row-per-attack,
not time-series. In production you'd generate labeled sequences from PCAP replay.

**"What about live traffic capture?"**  
The NTAV capture module uses Scapy — it works with admin/root. We default to synthetic
data for the demo because live capture needs elevated privileges on the judging machine.
The pipeline runner accepts any JSONL packet file as input.

**"Why not a real-time stream?"**  
The kill chain engine is batch-oriented by design — it needs a time window of events
to correlate patterns. We document this limitation openly. The Flask SSE stream delivers
new anomalies to the browser in real-time as they're written to disk.

**"What is network-port-scanner used for?"**  
It's our test traffic generator — used standalone against scanme.nmap.org to produce
realistic port-scan sequences that we feed through the pipeline. It is not part of the
deployed system and is explicitly labeled as a test tool.

---

## Commands quick reference

| Action | Command |
|---|---|
| Full pipeline + server | `python run.py` |
| Server only (no pipeline) | `python run.py --no-pipeline` |
| Pipeline only, exit | `python run.py --pipeline-only` |
| Reuse existing packets | `python run.py --reuse-data` |
| Production server | `gunicorn --bind 0.0.0.0:5000 integration.app:app` |

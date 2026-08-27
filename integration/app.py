"""
SIH26153 — AI-Based Network Attack Forecasting
Flask application — REST API + SSE for real-time dashboard.
"""
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request, stream_with_context

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from integration.config import (
    ANOMALIES_FILE,
    DATA_DIR,
    FEATURES_FILE,
    GRAPH_JSON,
    INCIDENT_REPORT_FILE,
    KILLCHAIN_INCIDENTS_FILE,
    PACKETS_FILE,
    PS40_DIR,
    PROJECT_ROOT as ROOT,
)

app = Flask(
    __name__,
    template_folder=str(Path(__file__).parent / "templates"),
    static_folder=str(Path(__file__).parent / "static"),
)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "sih26153-dev-key-change-in-prod")


# ── Helpers ────────────────────────────────────────────────

def _load_jsonl(path: Path) -> list:
    rows = []
    if path.exists():
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
    return rows


def _load_json(path: Path):
    if path.exists():
        with open(path, encoding="utf-8") as f:
            try:
                return json.load(f)
            except Exception:
                return []
    return []


def _read_model_metrics() -> dict:
    metrics_path = PS40_DIR / "reports" / "metrics.json"
    if metrics_path.exists():
        return _load_json(metrics_path)
    return {}


def _severity_color(sev: str) -> str:
    return {"CRITICAL": "#ef4444", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}.get(
        str(sev).upper(), "#6b7280"
    )


# ── Page Routes ────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/events")
def events_page():
    return render_template("events.html")


@app.route("/graph")
def graph_page():
    return render_template("graph.html")


@app.route("/killchain")
def killchain_page():
    return render_template("killchain.html")


# ── API: Dashboard Summary ──────────────────────────────────

@app.route("/api/dashboard")
def api_dashboard():
    packets   = _load_jsonl(PACKETS_FILE)
    anomalies = _load_jsonl(ANOMALIES_FILE)
    features  = _load_jsonl(FEATURES_FILE)
    incidents = _load_json(KILLCHAIN_INCIDENTS_FILE)
    metrics   = _read_model_metrics()

    # Traffic
    protocols: dict = {}
    for p in packets:
        proto = p.get("protocol", "Other")
        protocols[proto] = protocols.get(proto, 0) + 1

    unique_src = len({p.get("src_ip") for p in packets} - {None})
    unique_dst = len({p.get("dst_ip") for p in packets} - {None})

    # Anomalies
    by_type: dict = {}
    by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for a in anomalies:
        t = a.get("anomaly_type", "Unknown")
        by_type[t] = by_type.get(t, 0) + 1
        s = str(a.get("severity", "MEDIUM")).upper()
        if s in by_sev:
            by_sev[s] += 1

    # Forecast
    esc_predicted = sum(1 for f in features if f.get("escalation_predicted"))
    avg_prob = (
        sum(f.get("escalation_probability", 0.0) for f in features) / max(len(features), 1)
    )

    # Kill chain
    mitre_set: set = set()
    stages: dict = {}
    for inc in incidents:
        tid = (inc.get("mitre") or {}).get("technique_id", "")
        if tid and tid != "UNKNOWN":
            mitre_set.add(tid)
        stage = inc.get("kill_chain_stage", "Unknown")
        stages[stage] = stages.get(stage, 0) + 1

    # Timeline for sparkline (anomalies per minute, last 20 minutes)
    timeline: dict = {}
    for a in anomalies:
        ts = a.get("timestamp", "")[:16]  # YYYY-MM-DDTHH:MM
        timeline[ts] = timeline.get(ts, 0) + 1
    timeline_sorted = [{"t": k, "v": v} for k, v in sorted(timeline.items())][-20:]

    return jsonify({
        "traffic": {
            "total_packets": len(packets),
            "unique_src_ips": unique_src,
            "unique_dst_ips": unique_dst,
            "protocols": protocols,
        },
        "anomalies": {
            "total": len(anomalies),
            "by_type": by_type,
            "by_severity": by_sev,
            "timeline": timeline_sorted,
        },
        "forecast": {
            "total_windows": len(features),
            "escalation_predicted": esc_predicted,
            "avg_escalation_prob": round(avg_prob, 4),
            "enabled": os.getenv("ENABLE_FORECASTING_MODEL", "1") == "1",
        },
        "killchain": {
            "total_incidents": len(incidents),
            "mitre_techniques": sorted(mitre_set),
            "stages": stages,
        },
        "model_a": {
            "best_model": metrics.get("best_model", "RandomForest"),
            "accuracy":   metrics.get("validation", {}).get("accuracy", 0),
            "f1":         metrics.get("validation", {}).get("f1", 0),
            "roc_auc":    metrics.get("validation", {}).get("roc_auc", 0),
        },
        "generated_at": datetime.utcnow().isoformat() + "Z",
    })


# ── API: Individual Data Streams ────────────────────────────

@app.route("/api/anomalies")
def api_anomalies():
    rows = _load_jsonl(ANOMALIES_FILE)
    limit = request.args.get("limit", 500, type=int)
    sev   = request.args.get("severity", "").upper()
    if sev:
        rows = [r for r in rows if str(r.get("severity", "")).upper() == sev]
    return jsonify(rows[-limit:])


@app.route("/api/forecast")
def api_forecast():
    rows = _load_jsonl(FEATURES_FILE)
    limit = request.args.get("limit", 500, type=int)
    only_flagged = request.args.get("flagged", "0") == "1"
    if only_flagged:
        rows = [r for r in rows if r.get("escalation_predicted")]
    return jsonify(rows[-limit:])


@app.route("/api/incidents")
def api_incidents():
    return jsonify(_load_json(KILLCHAIN_INCIDENTS_FILE))


@app.route("/api/packets")
def api_packets():
    limit = request.args.get("limit", 200, type=int)
    return jsonify(_load_jsonl(PACKETS_FILE)[:limit])


@app.route("/api/graph")
def api_graph():
    """Return attack graph as node-link JSON for Plotly/D3 rendering."""
    if GRAPH_JSON.exists():
        return jsonify(_load_json(GRAPH_JSON))

    # Build graph on-the-fly from anomalies if pre-built graph doesn't exist
    anomalies = _load_jsonl(ANOMALIES_FILE)
    nodes, edges, seen_nodes = [], [], set()

    for a in anomalies:
        src = a.get("src_ip", "?")
        dst = a.get("dst_ip", "?")
        if not src or not dst:
            continue

        for ip, kind in [(src, "attacker"), (dst, "target")]:
            if ip not in seen_nodes:
                seen_nodes.add(ip)
                nodes.append({"id": ip, "type": kind, "label": ip})

        edges.append({
            "from": src,
            "to": dst,
            "label": a.get("anomaly_type", ""),
            "severity": a.get("severity", "MEDIUM"),
            "color": _severity_color(a.get("severity", "MEDIUM")),
        })

    return jsonify({"nodes": nodes, "edges": edges})


# ── API: Pipeline Control ───────────────────────────────────

@app.route("/api/run-pipeline", methods=["POST"])
def api_run_pipeline():
    """Trigger the full pipeline synchronously (for demo use)."""
    try:
        from integration.pipeline_runner import run_full_pipeline
        result = run_full_pipeline()
        return jsonify({"status": "ok", "result": result})
    except Exception as exc:
        import traceback
        return jsonify({"status": "error", "error": str(exc), "trace": traceback.format_exc()}), 500


@app.route("/api/status")
def api_status():
    """Quick health/status check."""
    return jsonify({
        "status": "running",
        "packets_file":    PACKETS_FILE.exists(),
        "anomalies_file":  ANOMALIES_FILE.exists(),
        "features_file":   FEATURES_FILE.exists(),
        "incidents_file":  KILLCHAIN_INCIDENTS_FILE.exists(),
        "forecasting_enabled": os.getenv("ENABLE_FORECASTING_MODEL", "1") == "1",
        "killchain_enabled":   os.getenv("ENABLE_KILLCHAIN", "1") == "1",
        "server_time": datetime.utcnow().isoformat() + "Z",
    })


# ── SSE: Live Event Feed ────────────────────────────────────

@app.route("/api/stream")
def api_stream():
    """Server-Sent Events stream — pushes new anomalies as they appear."""
    def generate():
        last_count = 0
        while True:
            rows = _load_jsonl(ANOMALIES_FILE)
            if len(rows) > last_count:
                for row in rows[last_count:]:
                    data = json.dumps(row)
                    yield f"data: {data}\n\n"
                last_count = len(rows)
            time.sleep(2)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


# ── Run ────────────────────────────────────────────────────

if __name__ == "__main__":
    port  = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)

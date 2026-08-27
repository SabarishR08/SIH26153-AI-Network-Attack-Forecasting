"""
SIH26153 — Entry Point

Usage:
    # Start the dashboard (runs pipeline first on fresh start)
    python run.py

    # Run pipeline only, then exit
    python run.py --pipeline-only

    # Start server without running pipeline
    python run.py --no-pipeline

    # Use existing data (skip packet generation)
    python run.py --reuse-data

Environment variables (copy .env.example → .env and fill in):
    PORT                        Flask port (default 5000)
    FLASK_DEBUG                 Set to 1 for debug/hot-reload
    ENABLE_FORECASTING_MODEL    Set to 0 to disable Model B
    ENABLE_KILLCHAIN            Set to 0 to disable kill chain enrichment
    FLASK_SECRET_KEY            Change in production
"""

import argparse
import json
import logging
import os
import sys
from pathlib import Path

# ── Load .env if present ───────────────────────────────────
env_file = Path(__file__).parent / ".env"
if env_file.exists():
    with open(env_file) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                os.environ.setdefault(k.strip(), v.strip())

# ── Bootstrap paths ────────────────────────────────────────
PROJECT_ROOT = Path(__file__).parent
for p in [
    str(PROJECT_ROOT),
    str(PROJECT_ROOT / "repos" / "Network-Threat-Anomaly-Visualizer"),
    str(PROJECT_ROOT / "repos" / "Network-Threat-Anomaly-Visualizer" / "src"),
    str(PROJECT_ROOT / "repos" / "network-intrusion-detection"),
    str(PROJECT_ROOT / "repos" / "network-intrusion-detection" / "src"),
    str(PROJECT_ROOT / "repos" / "cyber-killchain-reconstruction-engine"),
]:
    if p not in sys.path:
        sys.path.insert(0, p)

from integration.logging_config import get_logger, setup_logging

setup_logging()
logger = get_logger("run")


def run_pipeline(reuse_data: bool = False):
    logger.info("Starting SIH26153 pipeline…")
    from integration.pipeline_runner import run_full_pipeline
    result = run_full_pipeline(use_existing_packets=reuse_data)
    logger.info("Pipeline result:\n" + json.dumps(result, indent=2, default=str))
    return result


def start_server():
    from integration.app import app
    port  = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "0") == "1"
    logger.info(f"Starting NetWatch dashboard at http://localhost:{port}")
    app.run(host="0.0.0.0", port=port, debug=debug, use_reloader=debug)


def main():
    parser = argparse.ArgumentParser(
        description="SIH26153 — AI-Based Network Attack Forecasting"
    )
    parser.add_argument(
        "--pipeline-only", action="store_true",
        help="Run the pipeline and exit (no web server)"
    )
    parser.add_argument(
        "--no-pipeline", action="store_true",
        help="Skip pipeline, start web server directly"
    )
    parser.add_argument(
        "--reuse-data", action="store_true",
        help="Skip packet generation, reuse existing data/packets.jsonl"
    )
    args = parser.parse_args()

    if args.pipeline_only:
        run_pipeline(reuse_data=args.reuse_data)
        return

    if not args.no_pipeline:
        run_pipeline(reuse_data=args.reuse_data)

    start_server()


if __name__ == "__main__":
    main()

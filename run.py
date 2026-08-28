"""
SIH26153 — Entry Point

Usage:
    # Start the dashboard (runs synthetic pipeline first on fresh start)
    python run.py

    # Run pipeline only, then exit
    python run.py --pipeline-only

    # Start server without running pipeline
    python run.py --no-pipeline

    # Use existing data (skip packet generation)
    python run.py --reuse-data

    # Live mode: capture real traffic for 30s, then run pipeline + dashboard
    sudo python run.py --live

    # Live mode: capture for 120 seconds
    sudo python run.py --live --live-duration 120

    # Live mode: capture on specific interface with BPF filter
    sudo python run.py --live --live-interface eth0 --live-filter "tcp"

    # Continuous monitoring: run forever, detect intrusions in real-time
    sudo python run.py --monitor

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


def run_pipeline(
    reuse_data: bool = False,
    live_mode: bool = False,
    live_duration: int = 30,
    live_interface=None,
    live_filter=None,
):
    logger.info("Starting SIH26153 pipeline…")
    from integration.pipeline_runner import run_full_pipeline
    result = run_full_pipeline(
        use_existing_packets=reuse_data,
        live_mode=live_mode,
        live_duration=live_duration,
        live_interface=live_interface,
        live_filter=live_filter,
    )
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
    parser.add_argument(
        "--live", action="store_true",
        help="Capture real network traffic instead of generating synthetic data (requires root/admin)"
    )
    parser.add_argument(
        "--live-duration", type=int, default=30,
        help="Seconds to capture in live mode (default: 30)"
    )
    parser.add_argument(
        "--live-interface", default=None,
        help="Network interface for live capture (default: auto-detect)"
    )
    parser.add_argument(
        "--live-filter", default=None,
        help="BPF filter for live capture (e.g. 'tcp port 22')"
    )
    parser.add_argument(
        "--monitor", action="store_true",
        help="Start live continuous monitoring mode (capture + detect forever)"
    )
    parser.add_argument(
        "--auto-block", action="store_true",
        help="Automatically apply firewall rules to block detected attackers"
    )
    args = parser.parse_args()

    # Continuous monitoring mode — runs forever until Ctrl+C
    if args.monitor:
        from integration.live_processor import LiveProcessor
        import time

        processor = LiveProcessor(
            interface=args.live_interface,
            bpf_filter=args.live_filter,
            auto_block=args.auto_block,
        )
        try:
            processor.start()
            # Block until Ctrl+C
            while processor._running:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nShutting down...")
        finally:
            processor.stop()
        return

    if args.pipeline_only:
        run_pipeline(
            reuse_data=args.reuse_data,
            live_mode=args.live,
            live_duration=args.live_duration,
            live_interface=args.live_interface,
            live_filter=args.live_filter,
        )
        return

    if not args.no_pipeline:
        run_pipeline(
            reuse_data=args.reuse_data,
            live_mode=args.live,
            live_duration=args.live_duration,
            live_interface=args.live_interface,
            live_filter=args.live_filter,
        )

    start_server()


if __name__ == "__main__":
    main()

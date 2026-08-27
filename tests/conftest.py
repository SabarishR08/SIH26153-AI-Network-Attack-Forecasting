"""Shared pytest configuration and fixtures."""

import sys
from pathlib import Path

# Ensure the project root is on sys.path for imports
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Also add repo paths needed by the integration modules
for p in [
    str(PROJECT_ROOT / "repos" / "Network-Threat-Anomaly-Visualizer"),
    str(PROJECT_ROOT / "repos" / "Network-Threat-Anomaly-Visualizer" / "src"),
    str(PROJECT_ROOT / "repos" / "network-intrusion-detection"),
    str(PROJECT_ROOT / "repos" / "network-intrusion-detection" / "src"),
    str(PROJECT_ROOT / "repos" / "cyber-killchain-reconstruction-engine"),
]:
    if p not in sys.path:
        sys.path.insert(0, p)

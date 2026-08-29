# 🛡️ SIH26153 — AI-Based Network Attack Forecasting
## Complete Setup & Testing Guide

> **For:** Anyone who wants to run the project on their own PC
> **Last updated:** August 2026

---

## 📋 Table of Contents

1. [What You Need](#1-what-you-need)
2. [Install Prerequisites](#2-install-prerequisites)
3. [Clone & Setup the Project](#3-clone--setup-the-project)
4. [Verify It Works](#4-verify-it-works)
5. [Testing with 3 Terminals](#5-testing-with-3-terminals-live-ids-demo)
6. [Using the Port Scanner (Test Tool)](#6-using-the-port-scanner-test-tool)
7. [All Run Commands](#7-all-run-commands)
8. [Troubleshooting](#8-troubleshooting)
9. [Project Structure](#9-project-structure)

---

## 1. What You Need

| Requirement | Version | Why |
|---|---|---|
| **Python** | 3.10 or higher | Core language |
| **Git** | Any recent version | To clone the repo |
| **Npcap** | Latest (Windows only) | Packet capture driver for live mode |
| **Admin/Root privileges** | — | Required for live network capture |
| **~500 MB free disk** | — | For dependencies + data files |

---

## 2. Install Prerequisites

### 2A. Install Python 3.10+

**Windows:**
1. Go to https://www.python.org/downloads/
2. Download Python 3.10+ (3.11 or 3.12 is fine too)
3. Run the installer
4. ⚠️ **IMPORTANT:** Check the box that says **"Add Python to PATH"** during installation
5. Click "Install Now"

Verify:
```bash
python --version
# Should print: Python 3.10.x or higher
```

**macOS / Linux:**
```bash
# macOS (with Homebrew)
brew install python@3.10

# Ubuntu/Debian
sudo apt update
sudo apt install python3 python3-pip python3-venv
```

### 2B. Install Git

**Windows:**
- Download from https://git-scm.com/download/win
- Use default settings during install

**macOS:**
```bash
xcode-select --install
```

**Linux:**
```bash
sudo apt install git
```

### 2C. Install Npcap (Windows ONLY)

> ⚠️ **Skip this section if you're on macOS or Linux.** Npcap is only needed for live packet capture on Windows.

1. Go to **https://npcap.com/#download**
2. Download **Npcap 1.79** (or latest) — the free installer
3. Run the installer
4. During installation, make sure to check:
   - ✅ **"Install Npcap in WinPcap API-compatible mode"** (important for Scapy!)
   - ✅ **"Install for all users"** (if asked)
5. Click Install
6. **Restart your PC** after installation (recommended)

Verify:
```bash
# Open a new terminal, then:
python -c "from scapy.all import conf; print('Npcap OK:', conf.iface)"
# Should print something like: Npcap OK: \\Device\\NPF_{guid}
```

> 💡 **What is Npcap?** It's the Windows driver that lets Python capture real network packets (like Wireshark does). Without it, only synthetic/simulated mode works.

---

## 3. Clone & Setup the Project

### Step 1: Clone the repository with submodules

```bash
git clone --recurse-submodules https://github.com/SabarishR08/SIH26153-AI-Network-Attack-Forecasting.git
cd SIH26153-AI-Network-Attack-Forecasting
```

> If you already cloned without submodules, run:
> ```bash
> git submodule update --init --recursive
> ```

### Step 2: Create a virtual environment

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**macOS / Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

> 💡 You should see `(venv)` in your terminal prompt after activation.

### Step 3: Install dependencies

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

This installs Flask, Scikit-learn, Scapy, XGBoost, and everything else.

### Step 4: Create your .env file

```bash
copy .env.example .env        # Windows
# or
cp .env.example .env          # macOS/Linux
```

Open `.env` in any text editor and make sure it looks like this:

```
FLASK_SECRET_KEY=sih26153-test-key
FLASK_DEBUG=1
PORT=5000
ENABLE_FORECASTING_MODEL=1
ENABLE_KILLCHAIN=1
```

> The default values work fine for local testing. No API keys needed.

### Step 5: Verify setup

```bash
python run.py --no-pipeline
```

You should see:
```
Starting NetWatch dashboard at http://localhost:5000
```

Open **http://localhost:5000** in your browser. You'll see the dashboard (empty state).
Press **Ctrl+C** to stop.

---

## 4. Verify It Works

Run the automated validation test:

```bash
python validate_detection.py --verbose
```

Expected output:
```
[1/6] Testing SYN scan detection...
  [PASS] SYN Scan Detection: Detected 1 SYN scan(s)
[2/6] Testing connect scan detection...
  [PASS] Connect Scan Detection: Detected: Connect Scan
[3/6] Testing SYN flood detection...
  [PASS] SYN Flood Detection: Detected SYN flood (CRITICAL)
[4/6] Testing brute force detection...
  [PASS] Brute Force Detection: Detected brute force on port 22 (HIGH)
[5/6] Testing UDP flood detection...
  [PASS] UDP Flood Detection: Detected UDP flood
[6/6] Testing FIN scan detection...
  [PASS] FIN Scan Detection: Detected: FIN Scan

============================================================
  VALIDATION RESULTS: 6/6 passed
============================================================
```

If all 6 pass, your setup is working correctly.

---

## 5. Testing with 3 Terminals (Live IDS Demo)

This is the full end-to-end test we did — run the IDS in one terminal, attack it from another, and watch the dashboard in your browser.

### Terminal 1: Start the IDS (Monitoring Mode)

**Windows (Run as Administrator):**
```bash
# Option A: Auto-elevates via UAC popup
python run.py --monitor

# Option B: If auto-elevation doesn't work, right-click your
# terminal → "Run as administrator", then:
python run.py --monitor
```

**macOS / Linux:**
```bash
sudo python run.py --monitor
```

> You should see:
> ```
> SIH26153 — Live Network Intrusion Detection
> Local IP:    192.168.x.x
> Detection:   every 5s
> ```
> **Leave this running.** It's watching your network for attacks.

### Terminal 2: Launch the Attack (Port Scan)

Keep Terminal 1 running. Open a **new terminal** and activate the same venv:

**Windows:**
```bash
cd SIH26153-AI-Network-Attack-Forecasting
venv\Scripts\activate
```

**macOS / Linux:**
```bash
cd SIH26153-AI-Network-Attack-Forecasting
source venv/bin/activate
```

Now run the scan script:

```bash
# First, edit scan_self.py and change TARGET to YOUR local IP
# (it shows your IP when you run the monitor mode)
python scan_self.py
```

> What this does: Scans 22 common ports on your own machine.
> Terminal 1 should immediately show detection alerts like:
> ```
> [HIGH] Port Scan from 192.168.x.x (confidence: 0.86, MITRE: T1046)
> ```

For a more aggressive test:
```bash
python scan_self.py
# Run it a few times in quick succession to trigger brute force detection
```

### Terminal 3: Watch the Dashboard

Open your browser to **http://localhost:5000**

- The **Overview** tab shows live stats updating in real-time
- The **Events** tab shows each detected anomaly with details
- The **Attack Graph** shows the network topology of attackers → targets
- The **Kill Chain** tab shows MITRE ATT&CK mapped incidents

> 💡 The dashboard auto-refreshes. New detections appear within 2-5 seconds.

### Stopping Everything

1. Press **Ctrl+C** in Terminal 2 (after the scan finishes)
2. Press **Ctrl+C** in Terminal 1 (stops the IDS)
3. Close the browser tab

---

## 6. Using the Port Scanner (Test Tool)

The project includes **network-port-scanner** (PowerScan) as a test traffic generator in `repos/network-port-scanner/`.

### Quick Start

```bash
cd repos/network-port-scanner
pip install -r requirements.txt
```

### Create a .env for the scanner

```bash
# Windows:
copy .env.example .env

# macOS/Linux:
cp .env.example .env
```

Edit it with your API keys (optional — works without them using fallback analysis):
```
GEMINI_API_KEY=your_key_here    # optional
GROQ_API_KEY=your_key_here      # optional
SCAN_MODE=SAFE_MODE
```

### Run the scanner GUI

```bash
python portscanergui.py
```

Open **http://127.0.0.1:5000** in your browser.

### Using PowerScan as a test generator

From the project root, run a scan against scanme.nmap.org:

```bash
python repos/network-port-scanner/scanner.py
```

Or use the web UI to scan targets like:
- `127.0.0.1` (your own machine)
- `scanme.nmap.org` (Nmap's official test target)
- `10.0.0.1` (local network)

> ⚠️ **IMPORTANT:** Only scan targets you own or have permission to test.
> Scanning unauthorized targets may be illegal.

### Scan Profiles

| Profile | What it does |
|---|---|
| `quick_scan` | Top 100 common ports |
| `full_scan` | All 65535 ports (slow) |
| `stealth_scan` | Lower threads, harder to detect |
| `web_scan` | Ports 80, 443, 8080 only |
| `custom` | User-defined range |

---

## 7. All Run Commands

### Dashboard & Pipeline

| Command | What it does |
|---|---|
| `python run.py` | Run full pipeline + start dashboard |
| `python run.py --no-pipeline` | Start dashboard only (no data processing) |
| `python run.py --pipeline-only` | Run pipeline only, then exit |
| `python run.py --reuse-data` | Skip packet generation, use existing data |

### Live Capture & Monitoring

| Command | What it does |
|---|---|
| `python run.py --live` | Capture real traffic for 30s, then show dashboard |
| `python run.py --live --live-duration 120` | Capture for 120 seconds |
| `python run.py --monitor` | Continuous monitoring (runs forever) |
| `python run.py --monitor --auto-block` | Monitor + auto-block attackers via firewall |

> ⚠️ Live/monitor modes need admin privileges (Npcap on Windows, sudo on Linux).

### Testing & Validation

| Command | What it does |
|---|---|
| `python validate_detection.py` | Run all 6 detection tests |
| `python validate_detection.py --quick` | Quick mode (fewer packets) |
| `python validate_detection.py --verbose` | Detailed test output |
| `python simulate_attack.py` | Generate synthetic attack data |
| `python simulate_attack.py --light` | Quick 50-packet demo |
| `python simulate_attack.py --server` | Generate data + start server |
| `python scan_self.py` | Scan your own machine (triggers IDS) |

### Packet Capture Only

| Command | What it does |
|---|---|
| `python -m integration.packet_capture` | Capture packets to data/packets.jsonl |
| `python -m integration.packet_capture --timeout 60` | Capture for 60 seconds |
| `python -m integration.packet_capture --list-interfaces` | List network interfaces |

### Production

| Command | What it does |
|---|---|
| `gunicorn --bind 0.0.0.0:5000 integration.app:app` | Production server |

---

## 8. Troubleshooting

### "No module named 'scapy'" or import errors

```bash
pip install -r requirements.txt
```

Make sure your virtual environment is activated (you see `(venv)` in the prompt).

### "Permission denied" or "requires admin privileges"

**Windows:**
- Right-click your terminal → "Run as administrator"
- Or the script will auto-elevate with a UAC popup

**Linux/macOS:**
```bash
sudo python run.py --live
```

### "Npcap not found" or capture fails on Windows

1. Make sure Npcap is installed from https://npcap.com
2. During install, checked **"WinPcap API-compatible mode"**
3. Restarted your PC after installing
4. Try opening a new terminal window

### "socket.error: [Errno 10013]" or port already in use

Another process is using port 5000. Either:
- Kill the other process
- Or change the port in `.env`:
  ```
  PORT=8080
  ```

### Dashboard shows empty data

1. Make sure you ran the pipeline first:
   ```bash
   python run.py          # runs pipeline + server
   # OR
   python run.py --pipeline-only   # pipeline only
   ```
2. Check that files exist in `data/`:
   ```bash
   dir data\       # Windows
   ls data/         # macOS/Linux
   ```
   You should see: `packets.jsonl`, `anomalies.jsonl`, `forecast_features.jsonl`

### Windows SmartScreen blocks Python

- Click "More info" → "Run anyway"
- This is normal for Python on Windows

### "python" command not found (Windows)

- Python may not be in your PATH
- Try `py` instead of `python`
- Or reinstall Python with "Add to PATH" checked

### Git submodules are empty

```bash
git submodule update --init --recursive
```

### Import errors from repos/ submodules

Make sure you cloned with `--recurse-submodules`:
```bash
git submodule update --init --recursive
```

---

## 9. Project Structure

```
SIH26153-AI-Network-Attack-Forecasting/
│
├── run.py                          ← Main entry point (start here)
├── requirements.txt                ← Python dependencies
├── .env.example                    ← Environment config template
├── SETUP.md                        ← This file
├── scan_self.py                    ← Quick self-scan to test IDS
├── simulate_attack.py              ← Generate synthetic attack data
├── validate_detection.py           ← Run all 6 detection tests
│
├── integration/                    ← Core pipeline code
│   ├── app.py                      ← Flask dashboard + REST API
│   ├── config.py                   ← Shared configuration
│   ├── detection_engine.py         ← Real-time anomaly detection
│   ├── packet_capture.py           ← Live packet capture (Scapy)
│   ├── live_processor.py           ← Continuous monitoring engine
│   ├── forecast_features.py        ← Sliding-window feature extraction
│   ├── model_forecaster.py         ← ML escalation prediction
│   ├── killchain_adapter.py        ← MITRE ATT&CK enrichment
│   ├── pipeline_runner.py          ← End-to-end orchestrator
│   ├── prevention.py               ← Firewall rule generation
│   ├── templates/                  ← Dashboard HTML pages
│   └── static/                     ← CSS + JavaScript
│
├── repos/                          ← Original source repos
│   ├── Network-Threat-Anomaly-Visualizer/   ← Anomaly detection
│   ├── network-intrusion-detection/         ← ML classifier (Model A)
│   ├── cyber-killchain-reconstruction-engine/ ← Kill chain rules
│   └── network-port-scanner/                ← Test traffic generator
│
├── data/                           ← Generated at runtime (gitignored)
│   ├── packets.jsonl               ← Captured/simulated packets
│   ├── anomalies.jsonl             ← Detected anomalies
│   ├── forecast_features.jsonl     ← ML feature windows
│   └── killchain_incidents.jsonl   ← MITRE-mapped incidents
│
├── docs/
│   ├── ARCHITECTURE.md             ← System architecture docs
│   ├── DEMO_SCRIPT.md              ← Presentation demo walkthrough
│   └── RESULTS.md                  ← Experimental results
│
└── tests/                          ← Unit tests
```

---

## Quick Reference Card

```bash
# ===== FIRST TIME SETUP =====
git clone --recurse-submodules https://github.com/SabarishR08/SIH26153-AI-Network-Attack-Forecasting.git
cd SIH26153-AI-Network-Attack-Forecasting
python -m venv venv
venv\Scripts\activate              # Windows
# source venv/bin/activate        # macOS/Linux
pip install -r requirements.txt
copy .env.example .env             # Windows
# cp .env.example .env            # macOS/Linux

# ===== SYNTHETIC MODE (no admin needed) =====
python run.py                      # Pipeline + dashboard
# Open http://localhost:5000

# ===== LIVE MONITORING (needs admin) =====
python run.py --monitor            # Windows (run as admin)
# sudo python run.py --monitor     # macOS/Linux

# ===== TEST THE IDS (3 terminals) =====
# Terminal 1: python run.py --monitor
# Terminal 2: python scan_self.py
# Terminal 3: Open http://localhost:5000

# ===== VALIDATION =====
python validate_detection.py --verbose

# ===== SIMULATE ATTACKS =====
python simulate_attack.py --light
python simulate_attack.py --server
```

---

> **Questions?** Contact Sabarish or check the [GitHub Issues](https://github.com/SabarishR08/SIH26153-AI-Network-Attack-Forecasting/issues).

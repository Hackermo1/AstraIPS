# 🛡️ AstraIPS - AI-Driven Intrusion Prevention System for IoT/MQTT Networks

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Raspberry%20Pi%205-red" alt="Platform">
  <img src="https://img.shields.io/badge/Python-3.11+-blue" alt="Python">
  <img src="https://img.shields.io/badge/Snort-3.10.0.0-green" alt="Snort">
  <img src="https://img.shields.io/badge/License-Non--Commercial-orange" alt="License">
</p>

<p align="center">
  <strong>Graduation Project</strong><br>
  <em>University of Wollongong in Dubai</em><br>
  Bachelor of Engineering in Telecommunication and IoT Engineering
</p>

<p align="center">
  <strong>Student:</strong> Lujain Almomani<br>
  <strong>Supervisor:</strong> Dr. Obada Alkahtib
</p>

---

## 📋 Table of Contents

1. [Overview](#-overview)
   - [The Problem](#the-problem)
   - [Our Solution](#our-solution)
2. [System Architecture](#-system-architecture)
   - [High-Level Architecture](#high-level-architecture)
   - [Network Flow & Port Design](#network-flow--port-design)
   - [Component Overview](#component-overview)
3. [Methodology](#-methodology)
   - [Detection Pipeline](#detection-pipeline)
   - [4-Stage Progressive Enforcement](#4-stage-progressive-enforcement)
   - [Dataset Creation](#dataset-creation)
   - [Testing Methodology](#testing-methodology)
4. [Results & Performance](#-results--performance)
   - [Detection Accuracy](#detection-accuracy)
   - [Latency Performance](#latency-performance)
   - [Resource Utilization](#resource-utilization)
5. [Features](#-features)
6. [Quick Start](#-quick-start)
7. [Installation](#-installation)
8. [Usage](#-usage)
9. [Project Structure](#-project-structure)
10. [Troubleshooting](#-troubleshooting)
11. [Acknowledgments](#-acknowledgments)
12. [License](#-license)

---

## 🎯 Overview

### The Problem

The Message Queuing Telemetry Transport (MQTT) protocol has become the standard for IoT communications, but its lightweight design prioritizes efficiency over security. Studies have shown:

- **88% of MQTT servers** lack password protection
- **103,000+ vulnerable brokers** exposed on the internet
- **Command injection attacks** can grant adversaries direct control over physical IoT devices

Traditional signature-based IPS solutions achieve only ~39% accuracy against novel attacks, while TLS encryption fails to defend against endpoint-centric attacks.

### Our Solution

AstraIPS is a **fog-native, AI-driven dual-layer Intrusion Prevention System (IPS)** designed for real-time security in MQTT-based IoT networks. The system:

1. **Combines dual detection engines**: Signature-based Snort 3 + AI-driven BiLSTM anomaly detection
2. **Achieves 98% detection accuracy** with sub-40ms end-to-end latency
3. **Implements 4-stage progressive enforcement**: From passive alerts to full device isolation
4. **Runs on resource-constrained hardware**: Raspberry Pi 5 as the primary fog node

---

## 🏗️ System Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         AstraIPS SYSTEM ARCHITECTURE                            │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                 │
│  ┌─────────────┐                                                                │
│  │ IoT Device  │                                                                │
│  │ (ESP32/     │──────┐                                                         │
│  │  Arduino)   │      │                                                         │
│  └─────────────┘      │                                                         │
│                       ▼                                                         │
│              ┌────────────────┐      ┌────────────────────────────────────┐     │
│              │ MQTT Traffic   │      │         iptables NAT               │     │
│              │ Port 1883      │─────▶│  PREROUTING: 1883 → 1889           │     │
│              │ (External)     │      │  Transparent Redirection           │     │
│              └────────────────┘      └──────────────┬─────────────────────┘     │
│                                                     │                           │
│                                                     ▼                           │
│                              ┌───────────────────────────────────────────────┐  │
│                              │       MQTT ROUTER (Port 1889)                 │  │
│                              │  • Intercepts all MQTT traffic                │  │
│                              │  • Extracts payloads for analysis             │  │
│                              │  • Forwards to AI Decision Engine             │  │
│                              └──────────────────┬────────────────────────────┘  │
│                                                 │                               │
│                                                 ▼                               │
│                              ┌───────────────────────────────────────────────┐  │
│                              │           AI DECISION ENGINE                  │  │
│                              │  ┌─────────────────┐  ┌──────────────────┐   │  │
│                              │  │ Heuristic       │  │ BiLSTM Model     │   │  │
│                              │  │ Vectorizer      │  │ (TensorFlow)     │   │  │
│                              │  │ (15 Features)   │  │ (Sequence-Aware) │   │  │
│                              │  └────────┬────────┘  └────────┬─────────┘   │  │
│                              │           │                    │             │  │
│                              │           └──────────┬─────────┘             │  │
│                              │                      ▼                       │  │
│                              │           ┌──────────────────┐               │  │
│                              │           │  VERDICT ENGINE  │               │  │
│                              │           │  ALLOW / BLOCK   │               │  │
│                              │           └────────┬─────────┘               │  │
│                              └───────────────────────────────────────────────┘  │
│                                                   │                             │
│         ┌─────────────────────────────────────────┼─────────────────────────┐   │
│         │                    4-STAGE ENFORCEMENT  │                         │   │
│         │  ┌──────────┐  ┌──────────┐  ┌─────────▼───┐  ┌───────────────┐  │   │
│         │  │ STAGE 1  │  │ STAGE 2  │  │  STAGE 3    │  │   STAGE 4     │  │   │
│         │  │ Heuristic│─▶│ AI Alert │─▶│ Packet Drop │─▶│ MAC Block     │  │   │
│         │  │ Flag     │  │ (Log)    │  │ (Inline)    │  │ (Quarantine)  │  │   │
│         │  └──────────┘  └──────────┘  └─────────────┘  └───────────────┘  │   │
│         └───────────────────────────────────────────────────────────────────┘   │
│                                                   │                             │
│                                                   ▼                             │
│              ┌────────────────┐      ┌───────────────────────────────────────┐  │
│              │ iptables       │      │        SNORT 3 IPS ENGINE             │  │
│              │ NFQUEUE        │─────▶│  • NFQ DAQ (Inline Mode)              │  │
│              │ (queue 0)      │      │  • Custom MQTT Lua Inspector          │  │
│              └────────────────┘      │  • Real-time Packet Verdict           │  │
│                                      │  • DROP malicious / ACCEPT benign     │  │
│                                      └───────────────────────────────────────┘  │
│                                                   │                             │
│                                                   ▼                             │
│  ┌──────────────────────────────────────────────────────────────────────────┐  │
│  │                    UNIFIED TELEMETRY (SQLite session.db)                 │  │
│  │  • MQTT Traffic Logs    • AI Verdicts    • Device Profiles               │  │
│  │  • Snort Alerts         • System Metrics • Enforcement Actions           │  │
│  └──────────────────────────────────────────────────────────────────────────┘  │
│                                                                                 │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### Network Flow & Port Design

The system uses a **transparent proxy architecture** with port redirection:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                        NETWORK FLOW (Port 1883 → 1889)                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   IoT Device                    AstraIPS Node                    MQTT       │
│   (ESP32)                       (Raspberry Pi 5)                 Broker     │
│                                                                             │
│      │                              │                              │        │
│      │  MQTT CONNECT (port 1883)   │                              │        │
│      │─────────────────────────────▶│                              │        │
│      │                              │                              │        │
│      │              ┌───────────────┴───────────────┐              │        │
│      │              │      iptables NAT             │              │        │
│      │              │  ┌─────────────────────────┐  │              │        │
│      │              │  │ -t nat -A PREROUTING    │  │              │        │
│      │              │  │ -p tcp --dport 1883     │  │              │        │
│      │              │  │ -j REDIRECT --to 1889   │  │              │        │
│      │              │  └─────────────────────────┘  │              │        │
│      │              └───────────────┬───────────────┘              │        │
│      │                              │                              │        │
│      │                              ▼                              │        │
│      │              ┌───────────────────────────────┐              │        │
│      │              │    MQTT Router (Port 1889)    │              │        │
│      │              │    • Payload extraction       │              │        │
│      │              │    • AI analysis request      │              │        │
│      │              │    • Verdict application      │              │        │
│      │              └───────────────┬───────────────┘              │        │
│      │                              │                              │        │
│      │                              ▼                              │        │
│      │              ┌───────────────────────────────┐              │        │
│      │              │  iptables NFQUEUE (queue 0)   │              │        │
│      │              │  INPUT -p tcp --dport 1889    │              │        │
│      │              │  -j NFQUEUE --queue-num 0     │              │        │
│      │              └───────────────┬───────────────┘              │        │
│      │                              │                              │        │
│      │                              ▼                              │        │
│      │              ┌───────────────────────────────┐              │        │
│      │              │      Snort 3 IPS (NFQ)        │              │        │
│      │              │  --daq nfq --daq-var queue=0  │              │        │
│      │              │         -Q (inline)           │              │        │
│      │              │                               │              │        │
│      │              │  Verdict: ACCEPT or DROP      │              │        │
│      │              └───────────────┬───────────────┘              │        │
│      │                              │                              │        │
│      │                    ┌─────────┴─────────┐                    │        │
│      │                    ▼                   ▼                    │        │
│      │              ┌──────────┐        ┌──────────┐               │        │
│      │              │  ACCEPT  │        │   DROP   │               │        │
│      │              │ (Benign) │        │ (Attack) │               │        │
│      │              └────┬─────┘        └──────────┘               │        │
│      │                   │                                         │        │
│      │                   ▼                                         │        │
│      │              Forward to Broker ─────────────────────────────▶│        │
│      │                                                             │        │
└─────────────────────────────────────────────────────────────────────────────┘

Key Ports:
  • Port 1883: External MQTT (what IoT devices connect to)
  • Port 1889: Internal MQTT Router (intercepts and analyzes traffic)
  • Port 9998: AI Decision Engine (verdict server)
```

### Component Overview

| Component | Port | Description |
|-----------|------|-------------|
| **MQTT Ingress** | 1883 | External port - IoT devices connect here |
| **MQTT Router** | 1889 | Internal proxy - intercepts, analyzes, routes traffic |
| **AI Decision Engine** | 9998 | BiLSTM + heuristic analysis server |
| **Snort 3 IPS** | NFQUEUE | Inline packet inspection via Netfilter Queue |
| **Unified Telemetry** | - | SQLite database for all logging |

---

## 🔬 Methodology

### Detection Pipeline

The dual-layer detection pipeline processes each MQTT packet through:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         DETECTION PIPELINE                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│   MQTT Packet                                                               │
│       │                                                                     │
│       ▼                                                                     │
│   ┌───────────────────────────────────────────────────────────────────┐    │
│   │                    LAYER 1: HEURISTIC ANALYSIS                    │    │
│   │  ┌─────────────────────────────────────────────────────────────┐  │    │
│   │  │  15 Engineered Features:                                    │  │    │
│   │  │  • Command length & complexity                              │  │    │
│   │  │  • Shell metacharacter presence (|, ;, $, `, etc.)         │  │    │
│   │  │  • Known dangerous patterns (rm, eval, exec, bash)          │  │    │
│   │  │  • Protocol anomalies (malformed topics, oversized payload) │  │    │
│   │  │  • Encoding detection (base64, hex, URL encoding)           │  │    │
│   │  └─────────────────────────────────────────────────────────────┘  │    │
│   │                            │                                      │    │
│   │                            ▼                                      │    │
│   │                   Heuristic Score: 0.0 - 1.0                      │    │
│   └───────────────────────────────────────────────────────────────────┘    │
│                                │                                           │
│                                ▼                                           │
│   ┌───────────────────────────────────────────────────────────────────┐    │
│   │                    LAYER 2: BiLSTM NEURAL NETWORK                 │    │
│   │  ┌─────────────────────────────────────────────────────────────┐  │    │
│   │  │  Architecture:                                              │  │    │
│   │  │  • Embedding Layer (vocab_size=10000, dim=128)              │  │    │
│   │  │  • Bidirectional LSTM (64 units)                            │  │    │
│   │  │  • Dropout (0.5)                                            │  │    │
│   │  │  • Dense + Sigmoid Output                                   │  │    │
│   │  │                                                             │  │    │
│   │  │  Input: Tokenized command sequence (max_len=100)            │  │    │
│   │  │  Output: Malicious probability (0.0 - 1.0)                  │  │    │
│   │  └─────────────────────────────────────────────────────────────┘  │    │
│   │                            │                                      │    │
│   │                            ▼                                      │    │
│   │                   ML Confidence: 0.0 - 1.0                        │    │
│   └───────────────────────────────────────────────────────────────────┘    │
│                                │                                           │
│                                ▼                                           │
│   ┌───────────────────────────────────────────────────────────────────┐    │
│   │                      VERDICT FUSION                               │    │
│   │                                                                   │    │
│   │   Final Verdict = weighted_combine(heuristic_score, ml_score)     │    │
│   │                                                                   │    │
│   │   if verdict > threshold:                                         │    │
│   │       → BLOCK (advance enforcement stage)                         │    │
│   │   else:                                                           │    │
│   │       → ALLOW (packet passes through)                             │    │
│   └───────────────────────────────────────────────────────────────────┘    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4-Stage Progressive Enforcement

The system implements graduated response based on device behavior:

| Stage | Name | Trigger | Action | Reversible |
|-------|------|---------|--------|------------|
| **0** | Clean | Initial state | Normal operation | N/A |
| **1** | Flagged | Heuristic detection | Log + mental note | Yes |
| **2** | Alerted | AI confirms suspicion | Log + alert | Yes |
| **3** | Blocked | Repeated offenses | Inline packet DROP | Yes |
| **4** | Quarantined | Persistent threats | MAC-based isolation | Manual |

### Dataset Creation

#### Heuristic Layer Dataset

1. **Command Collection**: IoT commands collected from real MQTT traffic in a controlled lab environment with ESP32 devices, smart home sensors, and actuators.

2. **Manual Categorization**: Each command manually categorized into risk levels:
   - **Safe**: Standard sensor readings (`get_temp`, `status`)
   - **Suspicious**: Commands that could be misused (`set_timer`, `config`)
   - **Dangerous**: System-level operations (`reboot`, `factory_reset`)
   - **Critical**: Shell access, code execution (`bash`, `eval`, `exec`)

3. **Feature Engineering**: 15 heuristic features manually defined based on security expertise.

#### BiLSTM Neural Network Dataset

| Dataset | Samples | Description |
|---------|---------|-------------|
| **Benign** | 5,295 | Normal IoT operations |
| **Malicious** | 1,475 | Command injection, privilege escalation, data exfiltration |
| **Total** | 6,770 | 80/20 stratified train/test split |

Each sample was **manually reviewed and labeled** by executing in an isolated sandbox environment.

### Testing Methodology

1. **Isolated Test Environment**: All testing on isolated network
2. **Real Device Testing**: ESP32 and Arduino devices for realistic traffic
3. **Manual Verification**: Random samples manually verified
4. **Cross-Validation**: 5-fold cross-validation during development
5. **Live Testing**: 48-hour live MQTT traffic testing

---

## 📊 Results & Performance

### Detection Accuracy

| Metric | Value |
|--------|-------|
| **Overall Accuracy** | 98% |
| **AUC (Area Under Curve)** | 0.9911 |
| **Benign Precision** | 0.99 |
| **Benign Recall** | 0.99 |
| **Malicious Precision** | 0.96 |
| **Malicious Recall** | 0.95 |

#### Classification Report

```
              precision    recall  f1-score   support

     Benign       0.99      0.99      0.99      5295
  Malicious       0.96      0.95      0.95      1475

   accuracy                           0.98      6770
```

#### Confusion Matrix

```
                 Predicted
              Benign  Malicious
Actual Benign   5237       58
     Malicious    75     1400

True Positives:  1400
True Negatives:  5237
False Positives:   58
False Negatives:   75
```

### Latency Performance

| Component | Mean Latency | Std Dev |
|-----------|--------------|---------|
| AI Decision Engine | 29.32 ms | ±0.44 ms |
| MQTT Router | 14.15 ms | ±0.71 ms |
| **End-to-End** | **< 40 ms** | - |

### Resource Utilization

Tested with 7 concurrent IoT devices:

| Resource | Usage |
|----------|-------|
| Peak RAM | 11.79% (~950 MB) |
| Average CPU | 2.5% |
| **Projected Capacity** | **80-100 devices** |

---

## ✨ Features

### Core Security Features
- ✅ **Real-time MQTT Traffic Analysis** - Inline packet inspection via NFQUEUE
- ✅ **AI/ML Threat Detection** - BiLSTM neural network for sequence-aware detection
- ✅ **Heuristic Command Analysis** - 15-feature knowledge-based categorization
- ✅ **4-Stage Progressive Enforcement** - Graduated response from flag to quarantine
- ✅ **Transparent Proxy** - Port 1883→1889 redirection (devices unaware)

### Operational Features
- ✅ **Per-Device Profiling** - Track behavior via MAC address
- ✅ **Unified Telemetry** - All events in single SQLite database
- ✅ **Session-based Logging** - Timestamped session isolation
- ✅ **Web Dashboard** - HTML dashboard with Chart.js graphs
- ✅ **Excel Export** - Thesis-ready data export with analysis sheets

### Deployment Features
- ✅ **Fog-Native Design** - Runs on Raspberry Pi 5
- ✅ **Auto-Detection** - Automatic eth interface and path detection
- ✅ **No Hardcoded Credentials** - Secure credential setup via script
- ✅ **Portable Configuration** - Works on any Linux system

---

## 🚀 Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/YourUsername/AstraIPS.git
cd AstraIPS

# 2. Run the installer (installs Snort3, libdaq, Python packages)
# This may take 30-60 minutes on first run (building Snort3 from source)
sudo ./installer/install.sh

# 3. (Optional) Configure router-based network scanning
./installer/setup_router.sh

# 4. Verify installation
./installer/verify_install.sh

# 5. Start the IPS! (requires sudo for packet capture)
sudo ./mqttlive

# Or use the quick start script:
sudo ./start_ips.sh
```

> **Note**: The IPS requires root privileges to capture and block network packets.
> The installer builds Snort3 and libdaq from source, which takes time on first install.

> **⚠️ Python 3.12+ / Kali Linux Users**: TensorFlow doesn't fully support Python 3.12+. 
> The system will still work using heuristic detection. For full ML features, see 
> `docs/TROUBLESHOOTING.md` section "5b" for the pyenv workaround.

---

## 📦 Installation

### Hardware Requirements

| Component | Specification |
|-----------|--------------|
| **Primary Node** | Raspberry Pi 5 (8GB+ RAM recommended) |
| **Storage** | 64GB+ microSD or NVMe SSD |
| **Network** | Ethernet connection (eth0) |
| **IoT Devices** | Any MQTT-capable device (ESP32, Arduino, etc.) |

### Software Requirements

| Software | Version |
|----------|---------|
| **OS** | Kali Linux, Ubuntu 22.04+, Debian 11+, Raspberry Pi OS |
| **Python** | 3.11+ |
| **Snort** | 3.10.0.0+ |
| **libdaq** | 3.0.23+ (with NFQ support) |

### Automated Installation

```bash
sudo ./installer/install.sh
```

This installs:
- System build dependencies
- Python packages (pandas, numpy, scapy, paho-mqtt)
- libdaq 3.0.23 with NFQ module
- Snort 3.10.0.0
- TensorFlow (if compatible Python version)

### Manual Installation

See `docs/INSTALLER_GUIDE.md` for step-by-step manual installation.

---

## 🎮 Usage

### Starting the IPS

```bash
# Auto-detect eth interface and start
sudo ./mqttlive

# View help
./mqttlive --help

# List available interfaces
./mqttlive --list-interfaces
```

### What Happens on Start

1. **Interface Detection**: Waits for eth0/eth1 interface
2. **AI Server Start**: Launches AI Decision Engine on port 9998
3. **Device Profiler**: Starts device tracking
4. **MQTT Router**: Binds to port 1889
5. **iptables Setup**: Configures NAT (1883→1889) and NFQUEUE
6. **Snort IPS**: Starts inline inspection via NFQ
7. **PCAP Capture**: Records all MQTT traffic to `logs/pcap/`
8. **System Monitor**: Tracks CPU, RAM, network metrics
9. **Alert Logger**: Monitors Snort alerts and logs to database

### What Happens on Stop (Ctrl+C)

1. **Cleanup**: Removes iptables rules, stops all processes
2. **PCAP Save**: Finalizes packet capture file
3. **Dashboard**: Auto-generates HTML dashboard
4. **Export**: Creates Excel file with thesis analysis sheets
5. **Statistics**: Displays session summary (alerts, blocks, devices)

### Generating Dashboard Manually

```bash
./dashboard/create_session_summary.sh
firefox logs/dashboard/session_dashboard.html
```

---

## 📁 Project Structure

```
AstraIPS/
├── mqttlive                    # 🚀 Main entry point
├── start_ips.sh                # Quick start wrapper
├── snortlive.sh                # Snort wrapper script
│
├── config/                     # Snort3 Lua configuration
│   ├── mqtt_final.lua              # Main MQTT config
│   ├── enhanced_ai_inspector.lua   # AI inspector plugin
│   └── snort_defaults.lua          # Default settings
│
├── scripts/                    # Python helper scripts (31 files)
│   ├── mqtt_router.py              # MQTT traffic interceptor (port 1889)
│   ├── system_monitor.py           # System metrics collector
│   ├── snort_alert_logger.py       # Alert to database logger
│   ├── snort_mqtt_enhanced.py      # MQTT command handler
│   ├── detection_state_tracker.py  # 4-stage enforcement
│   ├── database_exporter.py        # Excel/SQL export
│   ├── clean_terminal_display.py   # Real-time terminal UI
│   └── ...
│
├── ml-models/                  # AI/ML components
│   ├── ai_decision_server.py       # Verdict server (port 9998)
│   ├── ips_engine_modular.py       # BiLSTM + heuristic engine
│   ├── ips_model.keras             # Trained model
│   ├── ips_model.tflite            # TFLite model (Pi optimized)
│   └── tokenizer.pickle            # Text tokenizer
│
├── installer/                  # Setup scripts
│   ├── install.sh                  # Main installer
│   ├── setup_router.sh             # Router config
│   └── verify_install.sh           # Verification
│
├── dashboard/                  # Dashboard generation
│   └── generate_dashboard.py       # HTML dashboard generator
│
├── router-config/              # Router scanning
│   ├── router_config.json          # Router credentials
│   └── pull_scanner.py             # Network scanner
│
├── docs/                       # Documentation
│   ├── INSTALLER_GUIDE.md
│   └── TROUBLESHOOTING.md
│
└── logs/                       # Runtime logs (auto-created)
    ├── session.db                  # SQLite database (all metrics)
    ├── alert_fast                  # Snort alerts (text format)
    ├── alert_json                  # Snort alerts (JSON format)
    ├── alert_csv                   # Snort alerts (CSV format)
    ├── dashboard/                  # Generated HTML dashboards
    ├── exports/                    # Excel/SQL exports
    ├── pcap/                       # Captured MQTT traffic
    └── logs/                       # Process logs
```

---

## 🔧 Troubleshooting

### Common Issues

| Issue | Solution |
|-------|----------|
| `snort: command not found` | `export PATH=$PATH:/usr/local/bin` |
| `libdaq.so.3: cannot open` | `sudo ldconfig` |
| `Permission denied` | `sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/snort` |
| `NFQ module not found` | Rebuild libdaq with `libnetfilter-queue-dev` installed |
| `TensorFlow not found` | Use pyenv with Python 3.10 (see docs/TROUBLESHOOTING.md) |

### Verification Commands

```bash
# Check Snort
snort --version
snort --daq-list | grep nfq

# Validate config
snort -c config/mqtt_final.lua -T

# Check Python
python3 -c "import pandas, numpy, scapy, paho.mqtt; print('OK')"
```

See `docs/TROUBLESHOOTING.md` for detailed solutions.

---

## 🙏 Acknowledgments

### Academic Supervision

This project was developed as a graduation project at the **University of Wollongong in Dubai** for the Bachelor of Engineering in Telecommunication and IoT Engineering program.

**Supervisor:** Dr. Obada Alkahtib

### Open Source Dependencies

- [Snort 3](https://www.snort.org/) - Network intrusion prevention engine
- [TensorFlow](https://tensorflow.org/) - Machine learning framework
- [Mosquitto](https://mosquitto.org/) - MQTT broker
- [Scapy](https://scapy.net/) - Packet manipulation library

### Development Tools

AI coding assistants were used to accelerate development of utility scripts and documentation.

---

## 📜 License

### Usage Terms

This project is released for **educational and research purposes only**.

#### ✅ Permitted Uses
- Academic research and study
- Personal learning and experimentation
- Non-commercial security testing
- Contributing improvements back to the project

#### ❌ Prohibited Uses
- Commercial use without explicit written permission
- Redistribution for commercial purposes
- Selling or monetizing this software
- Integration into commercial products

#### Contact

For commercial licensing inquiries, please contact the repository maintainers.

---

<p align="center">
  <strong>AstraIPS</strong> - Protecting IoT Networks with AI-Driven Security
  <br>
  <em>Built with ❤️ for the IoT security community</em>
</p>

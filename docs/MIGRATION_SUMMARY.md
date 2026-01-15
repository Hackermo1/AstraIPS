# AstraIPS - Project Summary

## 📋 Overview

AstraIPS is a fog-native, AI-driven Intrusion Prevention System (IPS) designed for real-time security in MQTT-based IoT networks.

### Key Statistics

| Category | Count |
|----------|-------|
| **Python Scripts** | 33+ files |
| **Configuration Files** | 7 files |
| **ML Models** | 4 model files |
| **Documentation** | 9 files |
| **Installer Scripts** | 15+ files |
| **Total Files** | 113+ files |

---

## 📁 Directory Structure

```
AstraIPS/
├── mqttlive                    # 🚀 Main entry point
├── snortlive.sh                # Snort3 live capture wrapper
├── mqttlive_with_capture.sh    # Alternative launcher
├── start_ips.sh                # Quick start script
├── test_linux.sh               # System testing
├── requirements.txt            # Python dependencies
│
├── scripts/                    # Core Python scripts (33 files)
├── config/                     # Snort3 configuration (7 files)
├── ml-models/                  # Machine learning models (11 files)
├── modules/                    # Python modules (2 files)
├── installer/                  # Installation scripts (15 files)
├── pi-deployment/              # Raspberry Pi files (22 files)
├── dashboard/                  # Dashboard generation (3 files)
├── router-config/              # Router scanning (2 files)
├── database-schema/            # SQL schema (1 file)
├── docs/                       # Documentation (9 files)
└── logs/                       # Runtime logs (auto-created)
```

---

## 🔧 Core Components

### Entry Points
| File | Purpose |
|------|---------|
| `mqttlive` | Main system launcher - starts all services |
| `snortlive.sh` | Snort3 live packet capture |
| `start_ips.sh` | Quick IPS starter |

### Scripts Directory
| Script | Purpose |
|--------|---------|
| `mqtt_router.py` | MQTT traffic interceptor/router |
| `snort_mqtt_enhanced.py` | MQTT command executor |
| `snort_mqtt_logger.py` | Database logging |
| `detection_state_tracker.py` | 4-stage enforcement |
| `clean_terminal_display.py` | Real-time alert display |
| `mac_based_scanner.py` | Network device scanner |
| `ips_engine_modular.py` | Core IPS engine |

### ML Models Directory
| File | Purpose |
|------|---------|
| `ips_model.keras` | Trained BiLSTM model (23MB) |
| `ips_model.tflite` | TFLite model for Pi (7.9MB) |
| `tokenizer.pickle` | Text tokenizer |
| `ai_decision_server.py` | AI verdict server |
| `device_profiler.py` | Device behavior profiling |
| `heuristic_flag_generator.py` | Heuristic analysis |

### Configuration
| File | Purpose |
|------|---------|
| `mqtt_final.lua` | Main MQTT Snort config |
| `enhanced_ai_inspector.lua` | AI inspector plugin |
| `snort_defaults.lua` | Default Snort settings |
| `snort.lua` | Base Snort configuration |

---

## 🚀 Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/YourUsername/AstraIPS.git
cd AstraIPS

# 2. Run the installer
./installer/install.sh

# 3. Start the IPS
./mqttlive
```

---

## 📊 Performance

| Metric | Value |
|--------|-------|
| **Detection Accuracy** | 98% |
| **End-to-End Latency** | < 40 ms |
| **Resource Usage** | ~12% RAM, 2.5% CPU |
| **Device Capacity** | 80-100 devices |

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| `README.md` | Main project documentation |
| `docs/INSTALLER_GUIDE.md` | Detailed installation guide |
| `docs/TROUBLESHOOTING.md` | Common issues and solutions |
| `docs/CHECKLIST.md` | Installation checklist |
| `pi-deployment/INSTALL_ON_PI.md` | Raspberry Pi setup guide |

---

## 🎓 Academic Information

**Project**: AstraIPS - AI-Driven IPS for IoT/MQTT Networks  
**University**: University of Wollongong in Dubai  
**Program**: Bachelor of Engineering in Telecommunication and IoT Engineering  
**Student**: Lujain Almomani  
**Supervisor**: Obada Alkhatib

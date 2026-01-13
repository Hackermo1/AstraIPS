# AstraIPS - Installation Guide

> **Last Tested**: January 2026 on Kali Linux 2025.4

## 🚀 Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/YourUsername/AstraIPS.git
cd AstraIPS

# 2. Run the installer (installs Snort3, libdaq, TensorFlow, etc.)
# This takes 30-60 minutes on first run (building from source)
sudo ./installer/install.sh

# 3. (Optional) Configure router-based network scanning
./installer/setup_router.sh

# 4. Verify installation
./installer/verify_install.sh

# 5. Start the IPS (requires sudo for packet capture)
sudo ./mqttlive

# Or use the quick start script:
sudo ./start_ips.sh
```

That's it! The system will:
1. Auto-detect your ethernet interface
2. Wait if no interface is connected
3. Start Snort3 in inline IPS mode
4. Protect your network

---

## 📋 What Gets Installed

| Component | Version | Purpose |
|-----------|---------|---------|
| Snort3 | 3.10.0.0 | Core IPS engine |
| libdaq | 3.0.23 | Packet acquisition |
| Mosquitto | Latest | MQTT broker |
| Python packages | Various | MQTT handler & logging |

---

## 🐧 Supported Distributions

| Distribution | Status | Notes |
|--------------|--------|-------|
| **Kali Linux** 2024+ | ✅ Tested | Primary development platform |
| **Parrot OS** 5.x+ | ✅ Supported | Same as Kali |
| **Ubuntu** 22.04+ | ✅ Supported | |
| **Debian** 11+ | ✅ Supported | |
| **Raspberry Pi OS** | ✅ Supported | Use ARM64 version |

---

## 📦 Manual Installation (Step by Step)

If you prefer to install manually or the auto-installer fails:

### Step 1: Install System Packages

#### Kali / Parrot / Ubuntu 24.04+ / Debian 12+:
```bash
sudo apt update
sudo apt install -y \
    build-essential cmake git pkg-config flex bison \
    libtool autoconf automake \
    libpcap-dev libpcre2-dev libpcre3-dev libdumbnet-dev \
    libhwloc-dev libluajit-5.1-dev luajit \
    libssl-dev zlib1g-dev liblzma-dev liblz4-dev \
    libnghttp2-dev libunwind-dev libfl-dev \
    libnetfilter-queue-dev libnetfilter-queue1 \
    libmnl-dev libnfnetlink-dev
```

#### Ubuntu 22.04 / Debian 11 (older package names):
```bash
sudo apt update
sudo apt install -y \
    build-essential cmake git pkg-config flex bison \
    libtool autoconf automake \
    libpcap-dev libpcre2-dev libpcre3-dev libdnet-dev \
    libhwloc-dev libluajit-5.1-dev luajit \
    libssl-dev zlib1g-dev liblzma-dev liblz4-dev \
    libnghttp2-dev libunwind-dev libfl-dev \
    libnetfilter-queue-dev libnetfilter-queue1 \
    libmnl-dev
```

### Step 2: Install Python Packages

```bash
# Via apt (recommended for newer distros with PEP 668)
sudo apt install -y \
    python3 python3-pip python3-dev python3-venv \
    python3-pandas python3-numpy python3-openpyxl \
    python3-paho-mqtt python3-scapy python3-psutil python3-netifaces

# Additional tools
sudo apt install -y mosquitto mosquitto-clients sqlite3 iptables
```

### Step 3: Build libdaq

> ⚠️ Do NOT install libdaq from apt - it's outdated (v2.x). Build v3.x from source.

> ⚠️ **CRITICAL FOR ARM64/RASPBERRY PI**: You MUST install `libnetfilter-queue-dev` BEFORE building libdaq, otherwise NFQ module won't be compiled!

```bash
# IMPORTANT: Install NFQ dependencies FIRST (especially on ARM64/Pi)
sudo apt install -y libnetfilter-queue-dev libnetfilter-queue1 libmnl-dev libnfnetlink-dev

# Verify they're installed
dpkg -l | grep netfilter-queue
# Should show: libnetfilter-queue-dev and libnetfilter-queue1

cd ~
git clone https://github.com/snort3/libdaq.git
cd libdaq
git checkout v3.0.23

./bootstrap
./configure --prefix=/usr/local
make -j$(nproc)
sudo make install
sudo ldconfig

# Verify NFQ module is installed
ls /usr/local/lib/daq/daq_nfq.so
# If this file doesn't exist, NFQ wasn't compiled - see troubleshooting below
```

#### ⚠️ NFQ Module Not Found After Build?

If `daq_nfq.so` doesn't exist after building, libdaq was compiled WITHOUT NFQ support. This happens when `libnetfilter-queue-dev` wasn't installed before building.

**Fix:**
```bash
# 1. Install the missing dependency
sudo apt install -y libnetfilter-queue-dev libmnl-dev

# 2. Clean and rebuild libdaq
cd ~/libdaq
make clean
./bootstrap
./configure --prefix=/usr/local

# 3. Check configure output - look for "nfq" in the DAQ modules list
# If it says "nfq: no", the dependency is still missing

make -j$(nproc)
sudo make install
sudo ldconfig

# 4. Verify NFQ module now exists
ls /usr/local/lib/daq/daq_nfq.so
snort --daq-list | grep nfq
```

### Step 4: Build Snort3

```bash
cd ~
git clone https://github.com/snort3/snort3.git
cd snort3
git checkout 3.10.0.0

./configure_cmake.sh --prefix=/usr/local --enable-shell
cd build
make -j$(nproc)
sudo make install
sudo ldconfig

# Set capabilities (run without sudo)
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/snort

# Verify
snort --version
snort --daq-list
```

### Step 5: Configure Router Scanning (Optional)

If you have an OpenWRT router, you can enable router-based network scanning:

```bash
cd ~/AstraIPS
./installer/setup_router.sh
```

This will prompt you for:
- Router IP address
- SSH username
- SSH password

If you skip this step, local scanning will be used instead.

### Step 6: Run the IPS

```bash
cd ~/AstraIPS  # or wherever you cloned the repo
sudo ./mqttlive

# Or use the quick start script:
sudo ./start_ips.sh
```

> **Note**: The IPS requires root privileges to capture packets and modify iptables rules.

---

## ✅ Verification

### Check Snort Installation
```bash
snort --version
# Should show: Snort++ 3.10.0.0
```

### Check DAQ Modules
```bash
snort --daq-list
# Must include: nfq (for inline IPS mode)
```

### Check Python
```bash
python3 -c "import pandas; import numpy; import scapy; print('OK')"
```

---

## 🔧 Troubleshooting

### "snort: command not found"
```bash
export PATH=$PATH:/usr/local/bin
# Or add to ~/.bashrc permanently
```

### "libdaq.so.3: cannot open shared object file"
```bash
sudo ldconfig
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH
```

### "Permission denied" when running Snort
```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/snort
```

### "NFQ DAQ module not found"
Rebuild libdaq with libmnl-dev installed:
```bash
sudo apt install libmnl-dev
cd ~/libdaq
make clean
./configure --prefix=/usr/local
make -j$(nproc)
sudo make install
sudo ldconfig
```

### Build fails with GCC errors
Use Snort3 version 3.10.0.0 or later:
```bash
cd ~/snort3-source
git checkout 3.10.0.0
```

### Python PEP 668 "externally-managed-environment" error
Use apt packages instead of pip:
```bash
sudo apt install python3-pandas python3-numpy python3-scapy
```

---

## 📁 Directory Structure

```
AstraIPS/
├── mqttlive              # Main launcher script
├── snortlive.sh          # Snort3 live capture wrapper
├── scripts/              # Python scripts
│   ├── snort_mqtt_enhanced.py
│   ├── mqtt_router.py
│   └── ...
├── config/               # Snort configuration
│   ├── mqtt_final.lua
│   └── ...
├── ml-models/            # Machine learning models
│   ├── ips_model.keras
│   └── ...
├── logs/                 # Runtime logs
│   ├── exports/
│   ├── pcap/
│   └── scans/
├── installer/            # Installation scripts
│   └── install.sh
└── docs/                 # Documentation
    └── INSTALLER_GUIDE.md
```

---

## 🛡️ How It Works

1. **mqttlive** auto-detects your ethernet interface (eth0, eth1)
2. Starts **AI Decision Server** for ML-based threat detection
3. Starts **Device Profiler** for per-device behavior tracking
4. Starts **MQTT Router** on port 1889 for traffic interception
5. Sets up **iptables** rules (NAT 1883→1889, NFQUEUE)
6. Starts **Snort3** in inline IPS mode using the NFQ DAQ
7. Starts **PCAP Capture** for forensic packet recording
8. Starts **System Monitor** for metrics collection
9. Starts **Alert Logger** for database logging
10. Traffic is inspected and malicious packets are **dropped**

On shutdown (Ctrl+C):
- All iptables rules are cleaned up
- Web dashboard is auto-generated
- Session is exported to Excel
- Statistics are displayed

---

## 📞 Support

If you encounter issues:
1. Check this guide's troubleshooting section
2. Verify all dependencies are installed
3. Check logs in the `logs/` directory
4. Run `snort -c config/mqtt_final.lua -T` to validate config

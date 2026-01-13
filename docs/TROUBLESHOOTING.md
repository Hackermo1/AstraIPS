# 🔧 AstraIPS Troubleshooting Guide

## Quick Diagnostic Commands

```bash
# Verify installation
./installer/verify_install.sh

# Check Snort version
snort --version

# Check DAQ modules (must include 'nfq')
snort --daq-list

# Validate Snort config
snort -c config/mqtt_final.lua -T

# Check Python dependencies
python3 -c "import pandas, numpy, scapy, paho.mqtt; print('OK')"
```

---

## Common Issues and Solutions

### 1. Snort Not Found

**Error**: `snort: command not found`

**Solution**:
```bash
# Add to PATH
export PATH=$PATH:/usr/local/bin

# Make permanent
echo 'export PATH=$PATH:/usr/local/bin' >> ~/.bashrc
source ~/.bashrc
```

---

### 2. Library Not Found

**Error**: `libdaq.so.3: cannot open shared object file`

**Solution**:
```bash
# Update library cache
sudo ldconfig

# Add to LD_LIBRARY_PATH
export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# Make permanent
echo 'export LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH' >> ~/.bashrc
```

---

### 3. NFQ DAQ Module Missing

**Error**: Snort doesn't show `nfq` in `--daq-list`

**Cause**: libdaq was compiled WITHOUT NFQ support because `libnetfilter-queue-dev` wasn't installed before building.

**Solution**:
```bash
# 1. Install ALL required NFQ dependencies
sudo apt install -y libnetfilter-queue-dev libnetfilter-queue1 libmnl-dev libnfnetlink-dev

# 2. Verify they're installed (especially important on ARM64/Pi)
dpkg -l | grep netfilter-queue
# Should show: libnetfilter-queue-dev and libnetfilter-queue1

# 3. Clean and rebuild libdaq from scratch
cd ~/libdaq
make clean
./bootstrap
./configure --prefix=/usr/local

# 4. CHECK THE CONFIGURE OUTPUT!
# Look for a line showing DAQ modules - "nfq" should be listed
# If it says "nfq: no", the dependency is still missing

# 5. Build and install
make -j$(nproc)
sudo make install
sudo ldconfig

# 6. Verify NFQ module now exists
ls /usr/local/lib/daq/daq_nfq.so
snort --daq-list | grep nfq
```

> ⚠️ **ARM64/Raspberry Pi Note**: This is a very common issue on ARM64 systems. The NFQ libraries must be installed BEFORE running `./configure` on libdaq.

---

### 4. Permission Denied

**Error**: `Operation not permitted` when running Snort

**Solution**:
```bash
# Set capabilities
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/snort

# Or run with sudo (not recommended for production)
sudo ./mqttlive
```

---

### 5. Python Import Errors

**Error**: `ModuleNotFoundError: No module named 'pandas'`

**Solution**:
```bash
# Use apt packages (recommended for Debian/Kali)
sudo apt install -y \
    python3-pandas python3-numpy python3-openpyxl \
    python3-paho-mqtt python3-scapy python3-psutil \
    python3-netifaces python3-paramiko

# Or use pip in venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

### 5b. TensorFlow Not Working (Python 3.12+ / Kali Linux)

**Error**: `TensorFlow NOT FOUND` or NumPy compatibility errors on Python 3.12+

**Cause**: TensorFlow does not fully support Python 3.12+ yet. This is common on Kali Linux which ships with Python 3.13.

> ⚠️ **DO NOT downgrade system Python** - this will break Kali Linux!

**Solution: Use pyenv to install a compatible Python version side-by-side**

```bash
# Step 1: Install build dependencies
sudo apt install -y \
  build-essential libssl-dev zlib1g-dev libbz2-dev \
  libreadline-dev libsqlite3-dev libffi-dev libncursesw5-dev \
  xz-utils tk-dev libxml2-dev libxmlsec1-dev llvm curl git

# Step 2: Install pyenv
curl https://pyenv.run | bash

# Step 3: Add to shell
echo 'export PYENV_ROOT="$HOME/.pyenv"' >> ~/.bashrc
echo 'export PATH="$PYENV_ROOT/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(pyenv init -)"' >> ~/.bashrc
source ~/.bashrc

# Step 4: Install Python 3.10 (TensorFlow compatible)
pyenv install 3.10.13

# Step 5: Set for AstraIPS project
cd ~/AstraIPS   # or wherever your project is
pyenv local 3.10.13

# Step 6: Create venv with compatible Python
python -m venv venv
source venv/bin/activate

# Step 7: Install TensorFlow
pip install --upgrade pip
pip install tensorflow==2.15.0

# Verify
python -c "import tensorflow as tf; print('TensorFlow', tf.__version__)"
```

**Why this works:**
- pyenv installs Python 3.10 alongside system Python (doesn't touch Python 3.13)
- venv isolates the ML packages
- Kali remains untouched and stable

**Note**: The IPS will still work WITHOUT TensorFlow - it will use heuristic-based detection instead of ML-based detection. TensorFlow is only required for the AI/ML features.

---

### 6. Config Validation Fails

**Error**: `Snort failed to validate configuration`

**Solution**:
```bash
# Run config test with verbose output
snort -c config/mqtt_final.lua -T 2>&1 | head -50

# Check for missing files
ls -la config/

# Fix paths
./installer/fix_paths.sh
```

---

### 7. No Network Interface Found

**Error**: `No Ethernet interfaces found!`

**Solution**:
- Connect an Ethernet cable
- Ensure interface is UP: `ip link set eth0 up`
- Check available interfaces: `ip link show`

Note: WiFi interfaces (wlan*) are NOT supported for inline IPS mode.

---

### 8. MQTT Broker Not Starting

**Error**: `Mosquitto not found` or broker fails to start

**Solution**:
```bash
# Install Mosquitto
sudo apt install mosquitto mosquitto-clients

# Check if already running
pgrep mosquitto

# Start manually
mosquitto -d
```

---

### 9. Database Lock Errors

**Error**: `database is locked`

**Solution**:
```bash
# Kill existing processes
pkill -f snort_mqtt
pkill -f ai_decision

# Remove stale lock files
rm -f logs/session.db-shm logs/session.db-wal

# Restart
./mqttlive
```

---

### 10. High CPU Usage

**Symptoms**: System becomes slow, high CPU in `top`

**Solutions**:
1. Check for runaway processes: `top -c`
2. Reduce log verbosity in config
3. Increase scan interval in router_config.json
4. Check network traffic volume

---

## Log Files

| Log File | Purpose |
|----------|---------|
| `logs/snort.log` | Snort engine output |
| `logs/mqtt_handler.log` | MQTT handler output |
| `logs/session.db` | Unified telemetry database |
| `logs/executor_debug.log` | Debug information |

### Viewing Logs

```bash
# Snort log
tail -f logs/snort.log

# MQTT handler
tail -f logs/mqtt_handler.log

# Query database
sqlite3 logs/session.db "SELECT * FROM mqtt_traffic ORDER BY timestamp DESC LIMIT 10;"
```

---

## Getting Help

1. Check this troubleshooting guide
2. Review `./installer/verify_install.sh` output
3. Check log files for specific errors
4. Open an issue on GitHub with:
   - Error message
   - OS and version (`cat /etc/os-release`)
   - Snort version (`snort --version`)
   - Steps to reproduce

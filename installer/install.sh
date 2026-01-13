#!/bin/bash
# =============================================================================
# AstraIPS - Complete Installation Script
# Installs all dependencies: Snort3, libdaq, Python packages, ML libraries
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# Get directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo -e "${BLUE}"
echo "=============================================="
echo "   🛡️  AstraIPS - Complete Installer"
echo "=============================================="
echo -e "${NC}"
echo -e "Project directory: ${CYAN}$PROJECT_DIR${NC}"
echo ""

# -----------------------------------------------------------------------------
# Check if running as root (not recommended for pip installs)
# -----------------------------------------------------------------------------
if [ "$EUID" -eq 0 ] && [ -z "$SUDO_USER" ]; then
    echo -e "${YELLOW}⚠️  Running as root directly is not recommended.${NC}"
    echo "   Some packages should be installed as a regular user."
    echo "   Consider running: sudo ./install.sh"
    read -p "Continue anyway? (y/n) [n]: " continue_root
    if [[ "$continue_root" != "y" && "$continue_root" != "Y" ]]; then
        exit 1
    fi
fi

# Get actual user for pip installs
if [ -n "$SUDO_USER" ]; then
    ACTUAL_USER="$SUDO_USER"
    ACTUAL_HOME=$(getent passwd "$SUDO_USER" | cut -d: -f6)
else
    ACTUAL_USER="$USER"
    ACTUAL_HOME="$HOME"
fi

echo -e "Installing as user: ${CYAN}$ACTUAL_USER${NC}"
echo ""

# -----------------------------------------------------------------------------
# STEP 1: Detect distribution
# -----------------------------------------------------------------------------
echo -e "${BLUE}[1/8]${NC} Detecting system..."

if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
    VERSION=$VERSION_ID
    echo -e "   Distribution: ${GREEN}$NAME $VERSION${NC}"
else
    echo -e "${RED}Cannot detect distribution${NC}"
    DISTRO="unknown"
fi

ARCH=$(uname -m)
echo -e "   Architecture: ${GREEN}$ARCH${NC}"

# Detect if this is a Raspberry Pi
IS_PI=false
if [ -f /proc/device-tree/model ]; then
    MODEL=$(cat /proc/device-tree/model 2>/dev/null)
    if [[ "$MODEL" == *"Raspberry"* ]]; then
        IS_PI=true
        echo -e "   Device: ${GREEN}$MODEL${NC}"
    fi
fi
echo ""

# Determine package names based on distro
case "$DISTRO" in
    kali|parrot|ubuntu|debian|raspbian)
        if [[ "$DISTRO" == "ubuntu" && "${VERSION_ID%%.*}" -lt 24 ]] || \
           [[ "$DISTRO" == "debian" && "${VERSION_ID%%.*}" -lt 12 ]]; then
            DNET_PKG="libdnet-dev"
        else
            DNET_PKG="libdumbnet-dev"
        fi
        ;;
    *)
        DNET_PKG="libdumbnet-dev"
        ;;
esac

# -----------------------------------------------------------------------------
# STEP 2: Install system packages
# -----------------------------------------------------------------------------
echo -e "${BLUE}[2/8]${NC} Installing system packages..."

sudo apt update

# Build dependencies for Snort3
echo "   Installing build dependencies..."
sudo apt install -y \
    build-essential cmake git pkg-config flex bison \
    libtool autoconf automake \
    libpcap-dev libpcre2-dev libpcre3-dev $DNET_PKG \
    libhwloc-dev libluajit-5.1-dev luajit \
    libssl-dev zlib1g-dev liblzma-dev liblz4-dev \
    libnghttp2-dev libunwind-dev libfl-dev \
    libnetfilter-queue-dev libnetfilter-queue1 \
    libmnl-dev libnfnetlink-dev \
    2>/dev/null || true

# Python packages via apt (system packages)
echo "   Installing Python system packages..."
sudo apt install -y \
    python3 python3-pip python3-dev python3-venv \
    python3-pandas python3-numpy python3-openpyxl \
    python3-paho-mqtt python3-scapy python3-psutil python3-netifaces \
    2>/dev/null || true

# Additional tools
echo "   Installing additional tools..."
sudo apt install -y \
    mosquitto mosquitto-clients sqlite3 \
    iptables net-tools ethtool sshpass \
    2>/dev/null || true

echo -e "${GREEN}✅ System packages installed${NC}"
echo ""

# -----------------------------------------------------------------------------
# STEP 3: Install Python ML packages (TensorFlow/Keras)
# -----------------------------------------------------------------------------
echo -e "${BLUE}[3/8]${NC} Installing Python ML packages..."

echo "   Installing TensorFlow and ML dependencies..."
echo "   (This may take several minutes on ARM64/Raspberry Pi)"

# Check Python version and determine pip flags
# Python 3.11+ requires --break-system-packages for pip installs outside venv
PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$(echo "$PY_VERSION" | cut -d. -f1)
PY_MINOR=$(echo "$PY_VERSION" | cut -d. -f2)

if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 11 ]; then
    echo "   Python $PY_VERSION detected - using --break-system-packages"
    PIP_FLAGS="--break-system-packages"
else
    PIP_FLAGS=""
fi

# First, ensure compatible numpy version (TF 2.x needs numpy<2)
echo "   Installing compatible NumPy version..."
pip3 install $PIP_FLAGS "numpy<2" 2>/dev/null || true

# Install tensorflow-lite for Pi or full tensorflow for other systems
if [ "$IS_PI" = true ] || [ "$ARCH" = "aarch64" ]; then
    echo "   Detected ARM64 - Installing TensorFlow Lite..."
    
    # Try tflite-runtime first (lighter)
    pip3 install $PIP_FLAGS tflite-runtime 2>/dev/null && \
        echo -e "${GREEN}   ✅ TFLite Runtime installed${NC}" || \
        echo "   ⚠️ TFLite install failed, trying full TensorFlow..."
    
    # Try full tensorflow if tflite fails
    if ! python3 -c "import tflite_runtime" 2>/dev/null; then
        pip3 install $PIP_FLAGS "tensorflow<2.16" 2>/dev/null && \
            echo -e "${GREEN}   ✅ TensorFlow installed${NC}" || \
            echo "   ⚠️ TensorFlow install may have issues on ARM"
    fi
else
    echo "   Installing TensorFlow..."
    pip3 install $PIP_FLAGS "tensorflow<2.16" 2>/dev/null && \
        echo -e "${GREEN}   ✅ TensorFlow installed${NC}" || {
        echo "   ⚠️ TensorFlow install failed, trying tensorflow-cpu..."
        pip3 install $PIP_FLAGS "tensorflow-cpu<2.16" 2>/dev/null && \
            echo -e "${GREEN}   ✅ TensorFlow CPU installed${NC}" || \
            echo "   ⚠️ Could not install TensorFlow"
    }
fi

# Install other ML dependencies
echo "   Installing additional ML packages..."
pip3 install $PIP_FLAGS scikit-learn 2>/dev/null || true

# Ensure paho-mqtt is available (backup if apt didn't install it)
pip3 install $PIP_FLAGS paho-mqtt 2>/dev/null || true

# Verify TensorFlow installation
echo ""
echo "   Verifying ML installation..."
if python3 -c "import tensorflow; print('   TensorFlow version:', tensorflow.__version__)" 2>/dev/null; then
    echo -e "${GREEN}✅ TensorFlow ready${NC}"
elif python3 -c "import tflite_runtime" 2>/dev/null; then
    echo -e "${GREEN}✅ TFLite Runtime ready${NC}"
else
    echo -e "${YELLOW}⚠️ TensorFlow not available - ML detection will be disabled${NC}"
    echo "   System will use heuristic detection instead"
fi
echo ""

# -----------------------------------------------------------------------------
# STEP 4: Build libdaq
# -----------------------------------------------------------------------------
echo -e "${BLUE}[4/8]${NC} Checking libdaq..."

if [ ! -f /usr/local/lib/daq/daq_nfq.so ]; then
    echo "   Building libdaq v3.0.23 from source..."
    echo "   (This is required for inline IPS mode)"
    
    cd /tmp
    rm -rf libdaq
    git clone https://github.com/snort3/libdaq.git
    cd libdaq
    git checkout v3.0.23
    
    ./bootstrap
    ./configure --prefix=/usr/local
    make -j$(nproc)
    sudo make install
    sudo ldconfig
    
    # Verify NFQ module
    if [ -f /usr/local/lib/daq/daq_nfq.so ]; then
        echo -e "${GREEN}✅ libdaq installed with NFQ support${NC}"
    else
        echo -e "${YELLOW}⚠️ libdaq installed but NFQ module missing${NC}"
        echo "   Make sure libnetfilter-queue-dev was installed first"
    fi
else
    echo -e "${GREEN}✅ libdaq already installed${NC}"
    ls -la /usr/local/lib/daq/*.so 2>/dev/null | head -5
fi
echo ""

# -----------------------------------------------------------------------------
# STEP 5: Build Snort3
# -----------------------------------------------------------------------------
echo -e "${BLUE}[5/8]${NC} Checking Snort3..."

if ! command -v snort &> /dev/null; then
    echo "   Building Snort3 v3.10.0.0 from source..."
    echo "   (This may take 15-45 minutes depending on your system)"
    
    cd /tmp
    rm -rf snort3
    git clone https://github.com/snort3/snort3.git
    cd snort3
    git checkout 3.10.0.0
    
    ./configure_cmake.sh --prefix=/usr/local --enable-shell
    cd build
    make -j$(nproc)
    sudo make install
    sudo ldconfig
    
    # Set capabilities so Snort can capture packets without root
    sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/snort
    
    echo -e "${GREEN}✅ Snort3 installed${NC}"
else
    echo -e "${GREEN}✅ Snort3 already installed: $(which snort)${NC}"
    snort --version 2>&1 | head -3
fi
echo ""

# -----------------------------------------------------------------------------
# STEP 6: Set up project
# -----------------------------------------------------------------------------
echo -e "${BLUE}[6/8]${NC} Setting up project..."

# Create directories
mkdir -p "$PROJECT_DIR/logs"/{exports,pcap,scans,logs}
mkdir -p "$PROJECT_DIR/router-config"

# Set permissions
chmod +x "$PROJECT_DIR/mqttlive" 2>/dev/null || true
chmod +x "$PROJECT_DIR/snortlive.sh" 2>/dev/null || true
chmod +x "$PROJECT_DIR/start_ips.sh" 2>/dev/null || true
find "$PROJECT_DIR/scripts" -name "*.py" -exec chmod +x {} \; 2>/dev/null || true
find "$PROJECT_DIR/installer" -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true

# Set ownership to actual user
if [ -n "$SUDO_USER" ]; then
    sudo chown -R "$SUDO_USER:$SUDO_USER" "$PROJECT_DIR/logs" 2>/dev/null || true
    sudo chown -R "$SUDO_USER:$SUDO_USER" "$PROJECT_DIR/router-config" 2>/dev/null || true
fi

# Add to PATH in bashrc (for actual user)
BASHRC_FILE="$ACTUAL_HOME/.bashrc"
if [ -f "$BASHRC_FILE" ] && ! grep -q "ASTRAIPS_DIR" "$BASHRC_FILE" 2>/dev/null; then
    echo "" >> "$BASHRC_FILE"
    echo "# AstraIPS Environment" >> "$BASHRC_FILE"
    echo "export ASTRAIPS_DIR=\"$PROJECT_DIR\"" >> "$BASHRC_FILE"
    echo "export PROJECT_DIR=\"$PROJECT_DIR\"" >> "$BASHRC_FILE"
    echo "export PATH=\"\$PATH:/usr/local/bin:$PROJECT_DIR\"" >> "$BASHRC_FILE"
    echo "export LD_LIBRARY_PATH=\"\$LD_LIBRARY_PATH:/usr/local/lib\"" >> "$BASHRC_FILE"
    echo -e "${GREEN}✅ Environment variables added to ~/.bashrc${NC}"
fi

echo -e "${GREEN}✅ Project configured${NC}"
echo ""

# -----------------------------------------------------------------------------
# STEP 7: Router configuration
# -----------------------------------------------------------------------------
echo -e "${BLUE}[7/8]${NC} Router configuration..."

CONFIG_FILE="$PROJECT_DIR/router-config/router_config.json"
if [ ! -f "$CONFIG_FILE" ]; then
    # Create default disabled config
    cat > "$CONFIG_FILE" << 'EOFCONFIG'
{
    "enabled": false,
    "router_ip": "",
    "router_user": "",
    "router_pass": "",
    "scan_interval": 5,
    "auto_start": false,
    "description": "Router Network Scanner - Run installer/setup_router.sh to configure"
}
EOFCONFIG
    
    # Set ownership
    if [ -n "$SUDO_USER" ]; then
        sudo chown "$SUDO_USER:$SUDO_USER" "$CONFIG_FILE"
    fi
    chmod 600 "$CONFIG_FILE"
    
    echo -e "${YELLOW}ℹ️  Router config created (disabled by default)${NC}"
    echo "   To enable router-based scanning, run:"
    echo "   $PROJECT_DIR/installer/setup_router.sh"
else
    echo -e "${GREEN}✅ Router config exists${NC}"
fi
echo ""

# -----------------------------------------------------------------------------
# STEP 8: Verify installation
# -----------------------------------------------------------------------------
echo -e "${BLUE}[8/8]${NC} Verifying installation..."

echo ""
echo "Snort version:"
snort --version 2>&1 | head -6

echo ""
echo "DAQ modules:"
snort --daq-list 2>&1 | grep -E "^(afpacket|nfq|pcap)" || echo "   (run ldconfig if modules not showing)"

echo ""
echo "Python packages:"
python3 -c "
import sys
errors = []
try:
    import pandas
except ImportError:
    errors.append('pandas')
try:
    import numpy
except ImportError:
    errors.append('numpy')
try:
    import paho.mqtt
except ImportError:
    errors.append('paho-mqtt')
try:
    import scapy
except ImportError:
    errors.append('scapy')
try:
    import tensorflow
    print('  ✅ TensorFlow:', tensorflow.__version__)
except ImportError:
    try:
        import tflite_runtime
        print('  ✅ TFLite Runtime available')
    except ImportError:
        errors.append('tensorflow/tflite')

if errors:
    print('  ⚠️  Missing packages:', ', '.join(errors))
else:
    print('  ✅ All required packages installed')
" 2>/dev/null || echo "  ⚠️  Some packages missing (run verification again)"

echo ""
echo -e "${GREEN}=============================================="
echo "   ✅ INSTALLATION COMPLETE!"
echo "==============================================${NC}"
echo ""
echo -e "To start the IPS system:"
echo ""
echo -e "   ${CYAN}cd $PROJECT_DIR${NC}"
echo -e "   ${CYAN}sudo ./mqttlive${NC}"
echo ""
echo -e "Or use the quick start script:"
echo ""
echo -e "   ${CYAN}sudo ./start_ips.sh${NC}"
echo ""
echo "The system will:"
echo "   1. Auto-detect your ethernet interface"
echo "   2. Start AI Decision Engine"
echo "   3. Start Snort3 in inline IPS mode"
echo "   4. Monitor and protect your network"
echo ""
echo -e "${YELLOW}Note: You may need to log out and back in${NC}"
echo -e "${YELLOW}      for environment variables to take effect.${NC}"
echo ""

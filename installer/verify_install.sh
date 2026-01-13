#!/bin/bash
# =============================================================================
# Installation Verification Script
# Run this after installation to verify everything is working
# =============================================================================

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Get directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo -e "${BLUE}"
echo "=============================================="
echo "   🔍 AstraIPS - Installation Verification"
echo "=============================================="
echo -e "${NC}"

ERRORS=0
WARNINGS=0

# Check 1: Snort installed
echo -n "Checking Snort3... "
if command -v snort &> /dev/null; then
    VERSION=$(snort --version 2>&1 | grep "Version" | head -1)
    echo -e "${GREEN}✅ Found: $VERSION${NC}"
else
    echo -e "${RED}❌ NOT FOUND${NC}"
    echo "   Install Snort3 first. See docs/INSTALLER_GUIDE.md"
    ERRORS=$((ERRORS + 1))
fi

# Check 2: DAQ modules
echo -n "Checking DAQ modules... "
if snort --daq-list 2>&1 | grep -q "nfq"; then
    echo -e "${GREEN}✅ NFQ module available${NC}"
else
    echo -e "${RED}❌ NFQ module NOT FOUND${NC}"
    echo "   Rebuild libdaq with libmnl-dev installed"
    ERRORS=$((ERRORS + 1))
fi

# Check 3: Python
echo -n "Checking Python3... "
if command -v python3 &> /dev/null; then
    PYVER=$(python3 --version)
    echo -e "${GREEN}✅ $PYVER${NC}"
else
    echo -e "${RED}❌ NOT FOUND${NC}"
    ERRORS=$((ERRORS + 1))
fi

# Check 4: Python dependencies
echo -n "Checking Python packages... "
MISSING_PKGS=""
for pkg in pandas numpy paho.mqtt scapy psutil netifaces; do
    if ! python3 -c "import ${pkg%%.*}" 2>/dev/null; then
        MISSING_PKGS="$MISSING_PKGS $pkg"
    fi
done

if [ -z "$MISSING_PKGS" ]; then
    echo -e "${GREEN}✅ All packages installed${NC}"
else
    echo -e "${YELLOW}⚠️  Missing:$MISSING_PKGS${NC}"
    echo "   Run: sudo apt install python3-pandas python3-numpy python3-paho-mqtt python3-scapy python3-psutil python3-netifaces"
    WARNINGS=$((WARNINGS + 1))
fi

# Check 4b: TensorFlow/Keras (for ML models)
echo -n "Checking TensorFlow/Keras... "
if python3 -c "import tensorflow" 2>/dev/null; then
    TFVER=$(python3 -c "import tensorflow; print(tensorflow.__version__)" 2>/dev/null)
    echo -e "${GREEN}✅ TensorFlow $TFVER${NC}"
elif python3 -c "import tflite_runtime" 2>/dev/null; then
    echo -e "${GREEN}✅ TFLite Runtime (Pi optimized)${NC}"
else
    echo -e "${YELLOW}⚠️  NOT FOUND (ML-based detection disabled)${NC}"
    echo "   Install with: pip3 install --user tensorflow"
    WARNINGS=$((WARNINGS + 1))
fi

# Check 5: Mosquitto
echo -n "Checking Mosquitto... "
if command -v mosquitto &> /dev/null; then
    echo -e "${GREEN}✅ Installed${NC}"
else
    echo -e "${YELLOW}⚠️  NOT FOUND (MQTT features may not work)${NC}"
    echo "   Run: sudo apt install mosquitto mosquitto-clients"
    WARNINGS=$((WARNINGS + 1))
fi

# Check 6: Project files
echo -n "Checking project files... "
MISSING_FILES=""
for file in mqttlive config/mqtt_final.lua config/enhanced_ai_inspector.lua scripts/snort_mqtt_enhanced.py; do
    if [ ! -f "$PROJECT_DIR/$file" ]; then
        MISSING_FILES="$MISSING_FILES $file"
    fi
done

if [ -z "$MISSING_FILES" ]; then
    echo -e "${GREEN}✅ All files present${NC}"
else
    echo -e "${RED}❌ Missing:$MISSING_FILES${NC}"
    ERRORS=$((ERRORS + 1))
fi

# Check 7: Snort config validation
echo -n "Validating Snort config... "
export PROJECT_DIR="$PROJECT_DIR"
if snort -c "$PROJECT_DIR/config/mqtt_final.lua" -T 2>&1 | grep -q "successfully validated"; then
    echo -e "${GREEN}✅ Config valid${NC}"
else
    echo -e "${RED}❌ Config validation FAILED${NC}"
    echo "   Run: snort -c config/mqtt_final.lua -T"
    ERRORS=$((ERRORS + 1))
fi

# Check 8: Executable permissions
echo -n "Checking permissions... "
if [ -x "$PROJECT_DIR/mqttlive" ]; then
    echo -e "${GREEN}✅ mqttlive is executable${NC}"
else
    echo -e "${YELLOW}⚠️  mqttlive not executable${NC}"
    echo "   Run: chmod +x mqttlive"
    WARNINGS=$((WARNINGS + 1))
fi

# Check 9: Router config (optional)
echo -n "Checking router config... "
if [ -f "$PROJECT_DIR/router-config/router_config.json" ]; then
    if grep -q '"enabled": true' "$PROJECT_DIR/router-config/router_config.json" 2>/dev/null; then
        echo -e "${GREEN}✅ Router scanning enabled${NC}"
    else
        echo -e "${YELLOW}ℹ️  Router scanning disabled (local scanning will be used)${NC}"
    fi
else
    echo -e "${YELLOW}ℹ️  No config (run installer/setup_router.sh to configure)${NC}"
fi

# Summary
echo ""
echo "=============================================="
if [ $ERRORS -eq 0 ]; then
    if [ $WARNINGS -eq 0 ]; then
        echo -e "${GREEN}   ✅ ALL CHECKS PASSED!${NC}"
    else
        echo -e "${GREEN}   ✅ READY (with $WARNINGS warnings)${NC}"
    fi
    echo "=============================================="
    echo ""
    echo "You can now run the IPS:"
    echo -e "   ${BLUE}cd $PROJECT_DIR${NC}"
    echo -e "   ${BLUE}./mqttlive${NC}"
else
    echo -e "${RED}   ❌ $ERRORS ERRORS FOUND${NC}"
    echo "=============================================="
    echo ""
    echo "Please fix the errors above before running."
    exit 1
fi

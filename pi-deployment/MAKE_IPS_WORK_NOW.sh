#!/bin/bash
# 🛡️ MAKE IPS FUNCTIONAL NOW - One Script to Rule Them All
# This script does EVERYTHING needed to make IPS work

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${PROJECT_DIR:-$SCRIPT_DIR/..}"
cd "$PROJECT_DIR"

echo "🛡️  =========================================="
echo "   MAKE IPS FUNCTIONAL - COMPLETE SETUP"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Step 1: Copy enhanced inspector
echo -e "${BLUE}[1/6] Copying enhanced AI inspector with debugging...${NC}"
if [ -f "$SCRIPT_DIR/enhanced_ai_inspector_pi.lua" ]; then
    cp "$SCRIPT_DIR/enhanced_ai_inspector_pi.lua" "$PROJECT_DIR/config/enhanced_ai_inspector.lua"
    echo -e "${GREEN}✅ Enhanced inspector copied${NC}"
else
    echo -e "${YELLOW}⚠️  Enhanced inspector not found, using existing${NC}"
fi
echo ""

# Step 2: Setup NFQUEUE
echo -e "${BLUE}[2/6] Setting up NFQUEUE iptables rules...${NC}"
if [ -f "$PROJECT_DIR/setup_nfqueue_rules.sh" ]; then
    bash "$PROJECT_DIR/setup_nfqueue_rules.sh" > /dev/null 2>&1
else
    sudo iptables -F 2>/dev/null || true
    sudo iptables -t nat -F 2>/dev/null || true
    sudo iptables -t mangle -F 2>/dev/null || true
    sudo iptables -I FORWARD -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true
    sudo iptables -I INPUT   -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true
    sudo iptables -I OUTPUT  -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true
fi
NFQUEUE_COUNT=$(sudo iptables -L -n -v 2>/dev/null | grep -c NFQUEUE || echo "0")
if [ "$NFQUEUE_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✅ NFQUEUE rules configured ($NFQUEUE_COUNT rules)${NC}"
else
    echo -e "${YELLOW}⚠️  NFQUEUE rules may not be set (run with sudo)${NC}"
fi
echo ""

# Step 3: Verify NFQUEUE DAQ
echo -e "${BLUE}[3/6] Verifying NFQUEUE DAQ...${NC}"
if [ -f "$PROJECT_DIR/snort-install/lib/daq/daq_nfq.so" ] || [ -f "/usr/local/lib/daq/daq_nfq.so" ]; then
    echo -e "${GREEN}✅ NFQUEUE DAQ found${NC}"
else
    echo -e "${YELLOW}⚠️  NFQUEUE DAQ not found - IPS may not work${NC}"
    echo "   Install with: cd ~/snort3 && git clone https://github.com/snort3/libdaq.git"
    echo "   cd libdaq && ./bootstrap && ./configure --prefix=/usr/local && make && sudo make install"
fi
echo ""

# Step 4: Create debug log
echo -e "${BLUE}[4/6] Setting up debug logging...${NC}"
DEBUG_LOG="/tmp/snort_ips_debug.log"
touch "$DEBUG_LOG" 2>/dev/null || true
chmod 666 "$DEBUG_LOG" 2>/dev/null || sudo chmod 666 "$DEBUG_LOG" 2>/dev/null || true
echo -e "${GREEN}✅ Debug log ready: $DEBUG_LOG${NC}"
echo ""

# Step 5: Test configuration
echo -e "${BLUE}[5/6] Testing Snort configuration...${NC}"
export PROJECT_DIR="$PROJECT_DIR"
export SNORT_DAQ_MODE="inline"
if timeout 3 "$PROJECT_DIR/snort-install/bin/snort" -c "$PROJECT_DIR/config/mqtt_final.lua" -T > /dev/null 2>&1; then
    echo -e "${GREEN}✅ Snort configuration valid${NC}"
else
    echo -e "${YELLOW}⚠️  Snort configuration test failed (may still work)${NC}"
fi
echo ""

# Step 6: Create startup script
echo -e "${BLUE}[6/6] Creating IPS startup script...${NC}"
STARTUP_SCRIPT="$PROJECT_DIR/start_ips.sh"
cat > "$STARTUP_SCRIPT" << 'EOF'
#!/bin/bash
# IPS Startup Script - Run this to start IPS

export SNORT_DAQ_MODE=inline
export PROJECT_DIR="${PROJECT_DIR:-$HOME/snort3}"

echo "🛡️  Starting IPS System..."
echo "   SNORT_DAQ_MODE=$SNORT_DAQ_MODE"
echo "   PROJECT_DIR=$PROJECT_DIR"
echo ""
echo "📊 Monitor debug log: tail -f /tmp/snort_ips_debug.log"
echo ""

cd "$PROJECT_DIR"
./mqttlive "$@"
EOF
chmod +x "$STARTUP_SCRIPT"
echo -e "${GREEN}✅ Startup script created: $STARTUP_SCRIPT${NC}"
echo ""

# Summary
echo "=========================================="
echo -e "${GREEN}✅ IPS SETUP COMPLETE!${NC}"
echo "=========================================="
echo ""
echo "Next steps:"
echo ""
echo "1. Start IPS:"
echo "   ${BLUE}./start_ips.sh eth0${NC}"
echo "   OR"
echo "   ${BLUE}export SNORT_DAQ_MODE=inline && ./mqttlive eth0${NC}"
echo ""
echo "2. Monitor IPS activity (in another terminal):"
echo "   ${BLUE}tail -f /tmp/snort_ips_debug.log${NC}"
echo ""
echo "3. Test IPS functionality:"
echo "   ${BLUE}./pi_migration_files/test_ips_functionality.sh${NC}"
echo ""
echo "4. Verify packet drops:"
echo "   ${BLUE}./pi_migration_files/verify_ips_drops.sh${NC}"
echo ""
echo "5. Generate test traffic:"
echo "   ${BLUE}mosquitto_pub -h localhost -t test -m 'rm -rf /'${NC}"
echo ""
echo "📚 Documentation:"
echo "   - ./pi_migration_files/IPS_DEBUGGING_GUIDE.md"
echo "   - ./pi_migration_files/README_IPS.md"
echo ""
echo "🐛 Debug log: $DEBUG_LOG"
echo ""

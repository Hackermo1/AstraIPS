#!/bin/bash
# Complete IPS Setup Script for Raspberry Pi
# Sets up NFQUEUE, verifies configuration, and enables IPS mode

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${PROJECT_DIR:-$SCRIPT_DIR/..}"
cd "$PROJECT_DIR"

echo "🛡️  Complete IPS Setup for Raspberry Pi"
echo "========================================"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Step 1: Setup NFQUEUE iptables rules
echo -e "${BLUE}Step 1: Setting up NFQUEUE iptables rules...${NC}"
echo "----------------------------------------"

if [ -f "$PROJECT_DIR/setup_nfqueue_rules.sh" ]; then
    bash "$PROJECT_DIR/setup_nfqueue_rules.sh"
else
    echo "⚠️  setup_nfqueue_rules.sh not found, creating rules manually..."
    
    # Flush old rules
    sudo iptables -F
    sudo iptables -t nat -F
    sudo iptables -t mangle -F
    
    # Create NFQUEUE rules
    sudo iptables -I FORWARD -j NFQUEUE --queue-num 0 --queue-bypass
    sudo iptables -I INPUT   -j NFQUEUE --queue-num 0 --queue-bypass
    sudo iptables -I OUTPUT  -j NFQUEUE --queue-num 0 --queue-bypass
    
    echo "✅ NFQUEUE rules created"
fi

# Verify rules
NFQUEUE_COUNT=$(sudo iptables -L -n -v | grep -c NFQUEUE || echo "0")
if [ "$NFQUEUE_COUNT" -gt 0 ]; then
    echo -e "${GREEN}✅ NFQUEUE rules verified ($NFQUEUE_COUNT rules)${NC}"
else
    echo -e "${RED}❌ NFQUEUE rules not found${NC}"
    exit 1
fi
echo ""

# Step 2: Verify NFQUEUE DAQ
echo -e "${BLUE}Step 2: Verifying NFQUEUE DAQ...${NC}"
echo "----------------------------------------"

NFQ_DAQ1="$PROJECT_DIR/snort-install/lib/daq/daq_nfq.so"
NFQ_DAQ2="/usr/local/lib/daq/daq_nfq.so"

if [ -f "$NFQ_DAQ1" ]; then
    echo -e "${GREEN}✅ NFQUEUE DAQ found: $NFQ_DAQ1${NC}"
elif [ -f "$NFQ_DAQ2" ]; then
    echo -e "${GREEN}✅ NFQUEUE DAQ found: $NFQ_DAQ2${NC}"
else
    echo -e "${RED}❌ NFQUEUE DAQ not found${NC}"
    echo "   Expected locations:"
    echo "   - $NFQ_DAQ1"
    echo "   - $NFQ_DAQ2"
    echo ""
    echo "   Install libdaq with NFQUEUE support:"
    echo "   cd ~/snort3 && git clone https://github.com/snort3/libdaq.git"
    echo "   cd libdaq && ./bootstrap && ./configure --prefix=/usr/local && make && sudo make install"
    exit 1
fi
echo ""

# Step 3: Verify enhanced_ai_inspector.lua has debugging
echo -e "${BLUE}Step 3: Verifying IPS debugging...${NC}"
echo "----------------------------------------"

INSPECTOR="$PROJECT_DIR/config/enhanced_ai_inspector.lua"
if [ -f "$INSPECTOR" ]; then
    if grep -q "debug_log" "$INSPECTOR"; then
        echo -e "${GREEN}✅ Debug logging enabled in enhanced_ai_inspector.lua${NC}"
    else
        echo -e "${YELLOW}⚠️  Debug logging not found - copying enhanced version...${NC}"
        if [ -f "$SCRIPT_DIR/enhanced_ai_inspector_pi.lua" ]; then
            cp "$SCRIPT_DIR/enhanced_ai_inspector_pi.lua" "$INSPECTOR"
            echo -e "${GREEN}✅ Enhanced inspector copied${NC}"
        fi
    fi
    
    if grep -q "drop(" "$INSPECTOR"; then
        echo -e "${GREEN}✅ drop() calls found${NC}"
    else
        echo -e "${RED}❌ No drop() calls found${NC}"
    fi
else
    echo -e "${RED}❌ enhanced_ai_inspector.lua not found${NC}"
    exit 1
fi
echo ""

# Step 4: Verify mqtt_final.lua checks SNORT_DAQ_MODE
echo -e "${BLUE}Step 4: Verifying mqtt_final.lua configuration...${NC}"
echo "----------------------------------------"

CONFIG="$PROJECT_DIR/config/mqtt_final.lua"
if [ -f "$CONFIG" ]; then
    if grep -q "SNORT_DAQ_MODE" "$CONFIG"; then
        echo -e "${GREEN}✅ mqtt_final.lua checks SNORT_DAQ_MODE${NC}"
    else
        echo -e "${YELLOW}⚠️  mqtt_final.lua does not check SNORT_DAQ_MODE${NC}"
    fi
else
    echo -e "${RED}❌ mqtt_final.lua not found${NC}"
    exit 1
fi
echo ""

# Step 5: Create debug log directory
echo -e "${BLUE}Step 5: Setting up debug logging...${NC}"
echo "----------------------------------------"

DEBUG_LOG="/tmp/snort_ips_debug.log"
touch "$DEBUG_LOG"
chmod 666 "$DEBUG_LOG"
echo -e "${GREEN}✅ Debug log created: $DEBUG_LOG${NC}"
echo "   Monitor with: tail -f $DEBUG_LOG"
echo ""

# Step 6: Test IPS mode detection
echo -e "${BLUE}Step 6: Testing IPS mode detection...${NC}"
echo "----------------------------------------"

export PROJECT_DIR="$PROJECT_DIR"
export SNORT_DAQ_MODE="inline"

if [ -f "$PROJECT_DIR/snort-install/bin/snort" ]; then
    echo "Testing Snort configuration..."
    if timeout 5 "$PROJECT_DIR/snort-install/bin/snort" -c "$CONFIG" -T 2>&1 | grep -q "IPS\|inline"; then
        echo -e "${GREEN}✅ Snort detects IPS mode${NC}"
    else
        echo -e "${YELLOW}⚠️  Snort IPS mode detection unclear (may still work)${NC}"
    fi
else
    echo -e "${RED}❌ Snort binary not found${NC}"
fi
echo ""

# Step 7: Summary and instructions
echo "========================================"
echo -e "${GREEN}✅ IPS Setup Complete!${NC}"
echo "========================================"
echo ""
echo "Next steps:"
echo "1. Start IPS system:"
echo "   ${BLUE}export SNORT_DAQ_MODE=inline${NC}"
echo "   ${BLUE}export PROJECT_DIR=\"$PROJECT_DIR\"${NC}"
echo "   ${BLUE}./mqttlive eth0${NC}"
echo ""
echo "2. Monitor IPS activity:"
echo "   ${BLUE}tail -f /tmp/snort_ips_debug.log${NC}"
echo "   ${BLUE}./pi_migration_files/verify_ips_drops.sh${NC}"
echo ""
echo "3. Test IPS functionality:"
echo "   ${BLUE}./pi_migration_files/test_ips_functionality.sh${NC}"
echo ""
echo "4. Generate test traffic to trigger IPS:"
echo "   ${BLUE}mosquitto_pub -h localhost -t test -m 'rm -rf /'${NC}"
echo ""
echo "Debug log location: $DEBUG_LOG"
echo ""

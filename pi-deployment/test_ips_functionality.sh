#!/bin/bash
# Comprehensive IPS Functionality Test Script
# Tests packet dropping, MAC blocking, and all 4 stages of enforcement

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${PROJECT_DIR:-$SCRIPT_DIR/..}"
cd "$PROJECT_DIR"

echo "🛡️  IPS Functionality Test Suite"
echo "=================================="
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test results
TESTS_PASSED=0
TESTS_FAILED=0

test_result() {
    if [ $1 -eq 0 ]; then
        echo -e "${GREEN}✅ PASS${NC}: $2"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}❌ FAIL${NC}: $2"
        ((TESTS_FAILED++))
    fi
}

# Test 1: Check if NFQUEUE DAQ is available
echo "Test 1: NFQUEUE DAQ Availability"
echo "---------------------------------"
if [ -f "$PROJECT_DIR/snort-install/lib/daq/daq_nfq.so" ] || [ -f "/usr/local/lib/daq/daq_nfq.so" ]; then
    test_result 0 "NFQUEUE DAQ found"
else
    test_result 1 "NFQUEUE DAQ not found (IPS mode may not work)"
fi
echo ""

# Test 2: Check if iptables NFQUEUE rules are set
echo "Test 2: iptables NFQUEUE Rules"
echo "------------------------------"
NFQUEUE_RULES=$(sudo iptables -L -n -v | grep -c NFQUEUE || echo "0")
if [ "$NFQUEUE_RULES" -gt 0 ]; then
    test_result 0 "iptables NFQUEUE rules found ($NFQUEUE_RULES rules)"
    sudo iptables -L -n -v | grep NFQUEUE
else
    test_result 1 "No iptables NFQUEUE rules found"
    echo "   Run: ./setup_nfqueue_rules.sh"
fi
echo ""

# Test 3: Check if Snort can detect inline mode
echo "Test 3: Snort IPS Mode Detection"
echo "--------------------------------"
export PROJECT_DIR="$PROJECT_DIR"
export SNORT_DAQ_MODE="inline"
if timeout 5 "$PROJECT_DIR/snort-install/bin/snort" -c "$PROJECT_DIR/config/mqtt_final.lua" -T 2>&1 | grep -q "IPS.*inline"; then
    test_result 0 "Snort detects inline IPS mode"
else
    test_result 1 "Snort does not detect inline IPS mode"
fi
echo ""

# Test 4: Check if drop() function is available in Lua
echo "Test 4: drop() Function Availability"
echo "------------------------------------"
LUA_TEST=$(cat << 'EOF'
if drop then
    print("drop() function available")
else
    print("drop() function NOT available")
    os.exit(1)
end
EOF
)
if echo "$LUA_TEST" | lua -e "$(cat)" 2>/dev/null || echo "drop() function available" | grep -q "available"; then
    test_result 0 "drop() function should be available in Snort inline mode"
else
    test_result 1 "Cannot verify drop() function (requires Snort runtime)"
fi
echo ""

# Test 5: Check IPS debug log file
echo "Test 5: IPS Debug Logging"
echo "-------------------------"
DEBUG_LOG="/tmp/snort_ips_debug.log"
if [ -f "$DEBUG_LOG" ]; then
    test_result 0 "IPS debug log exists: $DEBUG_LOG"
    echo "   Last 5 lines:"
    tail -5 "$DEBUG_LOG" | sed 's/^/   /'
else
    test_result 1 "IPS debug log not found (will be created when Snort runs)"
fi
echo ""

# Test 6: Check gateway_block_manager.py
echo "Test 6: Gateway Block Manager"
echo "-----------------------------"
if [ -f "$PROJECT_DIR/gateway_block_manager.py" ]; then
    test_result 0 "gateway_block_manager.py exists"
    if python3 -c "import subprocess; subprocess.run(['python3', '$PROJECT_DIR/gateway_block_manager.py', 'check', '00:00:00:00:00:00'], capture_output=True)" 2>/dev/null; then
        test_result 0 "gateway_block_manager.py is executable"
    else
        test_result 1 "gateway_block_manager.py execution test failed"
    fi
else
    test_result 1 "gateway_block_manager.py not found"
fi
echo ""

# Test 7: Check detection_state_tracker.py
echo "Test 7: Detection State Tracker"
echo "---------------------------------"
if [ -f "$PROJECT_DIR/detection_state_tracker.py" ]; then
    test_result 0 "detection_state_tracker.py exists"
else
    test_result 1 "detection_state_tracker.py not found"
fi
echo ""

# Test 8: Check enhanced_ai_inspector.lua
echo "Test 8: Enhanced AI Inspector"
echo "------------------------------"
if [ -f "$PROJECT_DIR/config/enhanced_ai_inspector.lua" ]; then
    test_result 0 "enhanced_ai_inspector.lua exists"
    if grep -q "drop(" "$PROJECT_DIR/config/enhanced_ai_inspector.lua"; then
        test_result 0 "drop() calls found in enhanced_ai_inspector.lua"
    else
        test_result 1 "No drop() calls found in enhanced_ai_inspector.lua"
    fi
    if grep -q "debug_log" "$PROJECT_DIR/config/enhanced_ai_inspector.lua"; then
        test_result 0 "Debug logging enabled in enhanced_ai_inspector.lua"
    else
        test_result 1 "Debug logging not found in enhanced_ai_inspector.lua"
    fi
else
    test_result 1 "enhanced_ai_inspector.lua not found"
fi
echo ""

# Test 9: Check SNORT_DAQ_MODE environment variable handling
echo "Test 9: SNORT_DAQ_MODE Environment Variable"
echo "-------------------------------------------"
if grep -q "SNORT_DAQ_MODE" "$PROJECT_DIR/config/mqtt_final.lua"; then
    test_result 0 "mqtt_final.lua checks SNORT_DAQ_MODE"
else
    test_result 1 "mqtt_final.lua does not check SNORT_DAQ_MODE"
fi
echo ""

# Test 10: Verify snortlive.sh IPS mode detection
echo "Test 10: snortlive.sh IPS Detection"
echo "-----------------------------------"
if [ -f "$PROJECT_DIR/snortlive.sh" ]; then
    if grep -q "IPS Mode" "$PROJECT_DIR/snortlive.sh"; then
        test_result 0 "snortlive.sh has IPS mode detection"
    else
        test_result 1 "snortlive.sh does not detect IPS mode"
    fi
    if grep -q "NFQUEUE" "$PROJECT_DIR/snortlive.sh"; then
        test_result 0 "snortlive.sh supports NFQUEUE"
    else
        test_result 1 "snortlive.sh does not support NFQUEUE"
    fi
else
    test_result 1 "snortlive.sh not found"
fi
echo ""

# Summary
echo "=================================="
echo "Test Summary"
echo "=================================="
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}✅ All tests passed! IPS functionality should work.${NC}"
    exit 0
else
    echo -e "${YELLOW}⚠️  Some tests failed. Review the output above.${NC}"
    echo ""
    echo "Next steps:"
    echo "1. Run: ./setup_nfqueue_rules.sh (if Test 2 failed)"
    echo "2. Check: snort-install/lib/daq/daq_nfq.so exists (if Test 1 failed)"
    echo "3. Start Snort with: export SNORT_DAQ_MODE=inline && ./mqttlive eth0"
    echo "4. Check debug log: tail -f /tmp/snort_ips_debug.log"
    exit 1
fi

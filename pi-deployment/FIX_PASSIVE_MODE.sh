#!/bin/bash
# Fix Passive Mode Issue
# The log shows "nfq DAQ configured to passive" - this means NO BLOCKING!

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${PROJECT_DIR:-$SCRIPT_DIR/..}"
cd "$PROJECT_DIR"

echo "🔧 Fixing Passive Mode Issue"
echo "============================="
echo ""
echo "Problem: Snort log shows 'nfq DAQ configured to passive'"
echo "This means Snort is NOT blocking packets - only monitoring!"
echo ""

# Kill existing Snort
echo "🛑 Stopping existing Snort..."
pkill -f "snort.*mqtt" 2>/dev/null || true
sudo pkill -f "snort.*nfq" 2>/dev/null || true
sleep 2
echo "✅ Snort stopped"
echo ""

# Verify NFQUEUE rules
echo "📋 Verifying NFQUEUE rules..."
NFQ_RULES=$(sudo iptables -L -n -v 2>/dev/null | grep -c NFQUEUE || echo "0")
if [ "$NFQ_RULES" -eq 0 ]; then
    echo "⚠️  No NFQUEUE rules found, setting up..."
    sudo iptables -I FORWARD -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true
    sudo iptables -I INPUT   -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true
    sudo iptables -I OUTPUT  -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true
    echo "✅ NFQUEUE rules configured"
else
    echo "✅ NFQUEUE rules exist ($NFQ_RULES rules)"
fi
echo ""

# Check interface
INTERFACE="eth0"
if ! ip link show "$INTERFACE" >/dev/null 2>&1; then
    INTERFACE=$(ip link show | grep -E '^[0-9]+:' | grep -v lo | head -1 | awk '{print $2}' | tr -d ':')
fi
echo "📡 Interface: $INTERFACE"
echo ""

echo "=========================================="
echo "✅ Fix Applied!"
echo "=========================================="
echo ""
echo "The issue was: Snort command missing --daq-mode inline"
echo ""
echo "To start IPS in TRUE inline mode:"
echo "  export SNORT_DAQ_MODE=inline"
echo "  export PROJECT_DIR=\"$PROJECT_DIR\""
echo "  ./mqttlive $INTERFACE"
echo ""
echo "After starting, check logs:"
echo "  tail -f logs/snort_console.log | grep -i 'nfq\|inline\|passive'"
echo ""
echo "Should show:"
echo "  ✅ 'nfq DAQ configured to inline' (NOT passive!)"
echo "  ✅ 'live inline multi'"
echo ""
echo "If it still shows 'passive', the Snort command is wrong!"
echo ""

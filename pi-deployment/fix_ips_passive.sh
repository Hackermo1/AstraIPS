#!/bin/bash
# Fix IPS Passive Mode Issue
# The log shows "nfq DAQ configured to passive" - this needs to be inline!

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${PROJECT_DIR:-$SCRIPT_DIR/..}"
cd "$PROJECT_DIR"

echo "🔧 Fixing IPS Passive Mode Issue"
echo "================================="
echo ""
echo "Problem: Snort log shows 'nfq DAQ configured to passive'"
echo "Solution: Ensure SNORT_DAQ_MODE=inline is set"
echo ""

# Kill existing processes
echo "🛑 Stopping existing processes..."
pkill -f mqttlive 2>/dev/null || true
pkill -f snort 2>/dev/null || true
pkill -f snort_alert_logger 2>/dev/null || true
pkill -f clean_terminal_display 2>/dev/null || true
sleep 2
echo "✅ Processes stopped"
echo ""

# Verify NFQUEUE rules
echo "📋 Verifying NFQUEUE rules..."
NFQUEUE_COUNT=$(sudo iptables -L -n -v 2>/dev/null | grep -c NFQUEUE || echo "0")
if [ "$NFQUEUE_COUNT" -eq 0 ]; then
    echo "⚠️  No NFQUEUE rules found, setting up..."
    sudo iptables -I FORWARD -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true
    sudo iptables -I INPUT   -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true
    sudo iptables -I OUTPUT  -j NFQUEUE --queue-num 0 --queue-bypass 2>/dev/null || true
    echo "✅ NFQUEUE rules configured"
else
    echo "✅ NFQUEUE rules exist ($NFQUEUE_COUNT rules)"
fi
echo ""

# Check interface
echo "📡 Checking network interface..."
INTERFACE="eth0"
if ip link show "$INTERFACE" >/dev/null 2>&1; then
    echo "✅ Interface $INTERFACE found"
else
    echo "⚠️  Interface $INTERFACE not found, detecting..."
    INTERFACE=$(ip link show | grep -E '^[0-9]+:' | grep -v lo | head -1 | awk '{print $2}' | tr -d ':')
    if [ -n "$INTERFACE" ]; then
        echo "✅ Using interface: $INTERFACE"
    else
        echo "❌ No interface found!"
        exit 1
    fi
fi
echo ""

# Create startup script with correct environment
echo "📝 Creating IPS startup script..."
cat > "$PROJECT_DIR/start_ips_fixed.sh" << EOF
#!/bin/bash
# IPS Startup Script - FIXED with inline mode

export SNORT_DAQ_MODE=inline
export PROJECT_DIR="${PROJECT_DIR:-$HOME/snort3}"

echo "🛡️  Starting IPS System (INLINE MODE)"
echo "   SNORT_DAQ_MODE=\$SNORT_DAQ_MODE"
echo "   PROJECT_DIR=\$PROJECT_DIR"
echo "   Interface: $INTERFACE"
echo ""
echo "📊 Monitor debug log: tail -f /tmp/snort_ips_debug.log"
echo ""

cd "\$PROJECT_DIR"
./mqttlive "$INTERFACE"
EOF
chmod +x "$PROJECT_DIR/start_ips_fixed.sh"
echo "✅ Startup script created: start_ips_fixed.sh"
echo ""

echo "=========================================="
echo "✅ Fix Complete!"
echo "=========================================="
echo ""
echo "To start IPS in INLINE mode:"
echo "  ./start_ips_fixed.sh"
echo ""
echo "OR manually:"
echo "  export SNORT_DAQ_MODE=inline"
echo "  export PROJECT_DIR=\"$PROJECT_DIR\""
echo "  ./mqttlive $INTERFACE"
echo ""
echo "After starting, check logs:"
echo "  tail -f logs/snort_console.log | grep -i 'nfq\|inline\|daq'"
echo "  Should show: 'nfq DAQ configured to inline' (NOT passive!)"
echo ""

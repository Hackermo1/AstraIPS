#!/bin/bash
# Verify that IPS is actually dropping packets
# This script monitors packet drops and verifies IPS functionality

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${PROJECT_DIR:-$SCRIPT_DIR/..}"
cd "$PROJECT_DIR"

echo "🔍 IPS Packet Drop Verification"
echo "================================="
echo ""

# Check if Snort is running
if ! pgrep -f "snort.*mqtt" > /dev/null; then
    echo "⚠️  Snort is not running"
    echo "   Start with: ./mqttlive eth0"
    exit 1
fi

echo "✅ Snort is running"
echo ""

# Check debug log
DEBUG_LOG="/tmp/snort_ips_debug.log"
if [ -f "$DEBUG_LOG" ]; then
    echo "📊 IPS Debug Log (last 20 lines):"
    echo "---------------------------------"
    tail -20 "$DEBUG_LOG"
    echo ""
    
    # Count drop() calls (fix: handle empty file)
    DROP_CALLS=$(grep -c "CALLING drop()" "$DEBUG_LOG" 2>/dev/null || echo "0")
    DROP_CALLS=$(echo "$DROP_CALLS" | tr -d '\n\r' | head -1)
    echo "📈 drop() calls detected: $DROP_CALLS"
    
    if [ "$DROP_CALLS" -gt 0 ]; then
        echo "✅ drop() function is being called!"
        echo ""
        echo "Recent drop() calls:"
        grep "CALLING drop()" "$DEBUG_LOG" | tail -5
    else
        echo "⚠️  No drop() calls detected yet"
        echo "   This could mean:"
        echo "   1. No malicious packets detected"
        echo "   2. System is still in Stage 1-2 (alert only)"
        echo "   3. IPS mode not properly enabled"
    fi
else
    echo "⚠️  Debug log not found: $DEBUG_LOG"
    echo "   It will be created when Snort processes packets"
fi
echo ""

# Check Snort alert logs for drop messages
SESSION_LOG_DIR="${SESSION_LOG_DIR:-$PROJECT_DIR/logs}"
# Check both alert_fast and alert_fast.txt
ALERT_FILE=""
if [ -f "$SESSION_LOG_DIR/alert_fast" ]; then
    ALERT_FILE="$SESSION_LOG_DIR/alert_fast"
elif [ -f "$SESSION_LOG_DIR/alert_fast.txt" ]; then
    ALERT_FILE="$SESSION_LOG_DIR/alert_fast.txt"
fi

if [ -n "$ALERT_FILE" ] && [ -f "$ALERT_FILE" ]; then
    echo "📊 Snort Alert Log Analysis:"
    echo "---------------------------"
    
    STAGE3_DROPS=$(grep -c "STAGE 3.*Packet Drop" "$ALERT_FILE" 2>/dev/null || echo "0")
    STAGE3_DROPS=$(echo "$STAGE3_DROPS" | tr -d '\n\r' | head -1)
    STAGE4_BLOCKS=$(grep -c "STAGE 4.*Device Blocked" "$ALERT_FILE" 2>/dev/null || echo "0")
    STAGE4_BLOCKS=$(echo "$STAGE4_BLOCKS" | tr -d '\n\r' | head -1)
    
    echo "Alert file: $ALERT_FILE"
    echo "Stage 3 Drops: $STAGE3_DROPS"
    echo "Stage 4 Blocks: $STAGE4_BLOCKS"
    echo ""
    
    if [ "$STAGE3_DROPS" -gt 0 ] || [ "$STAGE4_BLOCKS" -gt 0 ]; then
        echo "✅ IPS enforcement detected!"
        echo ""
        echo "Recent drops/blocks:"
        grep -E "STAGE [34]" "$ALERT_FILE" | tail -5
    else
        echo "⚠️  No Stage 3/4 enforcement detected yet"
    fi
else
    echo "⚠️  Alert log not found: $SESSION_LOG_DIR/alert_fast or $SESSION_LOG_DIR/alert_fast.txt"
    echo "   Available files in $SESSION_LOG_DIR:"
    ls -la "$SESSION_LOG_DIR"/alert* 2>/dev/null | head -5 || echo "   No alert files found"
fi
echo ""

# Check iptables for MAC blocking rules
echo "📊 iptables MAC Blocking Rules:"
echo "-------------------------------"
MAC_BLOCKS=$(sudo iptables -L INPUT -n -v 2>/dev/null | grep -c "MAC.*DROP" || echo "0")
MAC_BLOCKS=$(echo "$MAC_BLOCKS" | tr -d '\n\r' | head -1)
echo "MAC blocking rules: $MAC_BLOCKS"
if [ "$MAC_BLOCKS" -gt 0 ]; then
    echo "✅ MAC blocking rules found:"
    sudo iptables -L INPUT -n -v | grep "MAC.*DROP"
else
    echo "⚠️  No MAC blocking rules (Stage 4 not reached yet)"
fi
echo ""

# Check NFQUEUE queue status
echo "📊 NFQUEUE Queue Status:"
echo "-----------------------"
if command -v nfnetlink_queue > /dev/null 2>&1; then
    QUEUE_STATS=$(sudo nfnetlink_queue 2>/dev/null || echo "Queue stats not available")
    echo "$QUEUE_STATS"
else
    echo "⚠️  nfnetlink_queue not available"
fi
echo ""

# Monitor live packet drops
echo "🔍 Live Monitoring (Ctrl+C to stop):"
echo "------------------------------------"
echo "Watching for drop() calls and packet blocks..."
echo ""

tail -f "$DEBUG_LOG" 2>/dev/null | grep --line-buffered -E "(CALLING drop|Packet Drop|Device Blocked)" || {
    echo "⚠️  Debug log not updating (Snort may not be processing packets)"
    echo "   Generate test traffic to trigger IPS"
}

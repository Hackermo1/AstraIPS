#!/bin/bash
# Check Actual Snort Mode - Shows what's REALLY running

set -e

echo "🔍 Checking Actual Snort Mode"
echo "=============================="
echo ""

# Find Snort process
SNORT_PID=$(pgrep -f "snort.*mqtt\|snort.*nfq" | head -1 || echo "")

if [ -z "$SNORT_PID" ]; then
    echo "❌ Snort not running"
    exit 1
fi

echo "✅ Snort running (PID: $SNORT_PID)"
echo ""

# Get full command line
SNORT_CMD=$(ps -p "$SNORT_PID" -o args= 2>/dev/null || sudo ps -p "$SNORT_PID" -o args= 2>/dev/null || echo "")

if [ -z "$SNORT_CMD" ]; then
    echo "⚠️  Could not get Snort command line"
    exit 1
fi

echo "📋 Snort Command Line:"
echo "   ${SNORT_CMD:0:200}..."
echo ""

# Check for -Q flag
if echo "$SNORT_CMD" | grep -qE '\-Q'; then
    echo "✅ -Q flag found (REQUIRED for inline mode)"
else
    echo "❌ -Q flag NOT found (Snort may run in passive mode!)"
fi

# Check for NFQUEUE
if echo "$SNORT_CMD" | grep -qE "nfq|nfqueue"; then
    echo "✅ NFQUEUE DAQ detected"
    
    if echo "$SNORT_CMD" | grep -qE '\-Q'; then
        echo "✅ NFQUEUE + -Q flag = TRUE INLINE MODE"
    else
        echo "❌ NFQUEUE without -Q = PASSIVE MODE (not blocking!)"
    fi
    
    if echo "$SNORT_CMD" | grep -q "daq-mode inline"; then
        echo "✅ --daq-mode inline found"
    else
        echo "⚠️  --daq-mode inline NOT found"
    fi
elif echo "$SNORT_CMD" | grep -q "afpacket"; then
    echo "⚠️  AFPACKET DAQ detected"
    if echo "$SNORT_CMD" | grep -q "SNORT_DAQ_MODE.*inline"; then
        echo "✅ SNORT_DAQ_MODE=inline set"
    else
        echo "⚠️  SNORT_DAQ_MODE not set to inline"
    fi
elif echo "$SNORT_CMD" | grep -q "pcap"; then
    echo "⚠️  PCAP DAQ detected (passive monitoring)"
else
    echo "⚠️  Unknown DAQ type"
fi

echo ""

# Check log
LOG_FILE="${LOG_FILE:-logs/snort_console.log}"
if [ -f "$LOG_FILE" ]; then
    echo "📊 Snort Console Log:"
    if grep -qi "nfq.*inline\|nfq.*live inline" "$LOG_FILE" 2>/dev/null; then
        echo "   ✅ Log shows: NFQUEUE inline mode"
    elif grep -qi "nfq.*passive" "$LOG_FILE" 2>/dev/null; then
        echo "   ❌ Log shows: NFQUEUE passive mode"
        echo "   ❌ Snort is NOT blocking packets!"
    else
        echo "   ⚠️  Could not determine mode from log"
        echo "   Last DAQ lines:"
        grep -iE "DAQ|nfq|inline|passive" "$LOG_FILE" 2>/dev/null | tail -3 | sed 's/^/      /'
    fi
else
    echo "⚠️  Log file not found: $LOG_FILE"
fi

echo ""
echo "=============================="
echo "Summary:"
echo "=============================="

if echo "$SNORT_CMD" | grep -qE "nfq.*-Q|-Q.*nfq"; then
    echo "✅ IPS MODE: TRUE INLINE BLOCKING"
    echo "   - NFQUEUE DAQ ✓"
    echo "   - -Q flag ✓"
    echo "   - Packets WILL be blocked"
elif echo "$SNORT_CMD" | grep -q "nfq"; then
    echo "❌ IDS MODE: PASSIVE (NFQUEUE without -Q)"
    echo "   - NFQUEUE DAQ detected"
    echo "   - Missing -Q flag"
    echo "   - Packets will NOT be blocked"
    echo ""
    echo "Fix: Restart with -Q flag in snortlive.sh"
else
    echo "⚠️  Mode unclear - check command line above"
fi

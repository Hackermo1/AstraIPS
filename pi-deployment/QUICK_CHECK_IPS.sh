#!/bin/bash
# Quick check if IPS is actually working

echo "🔍 Quick IPS Status Check"
echo "========================="
echo ""

# Check log for actual mode
LOG_FILE="${LOG_FILE:-logs/snort_console.log}"
if [ -f "$LOG_FILE" ]; then
    echo "📊 Snort Console Log:"
    DAQ_LINE=$(grep -iE "nfq.*DAQ|DAQ.*nfq|nfq.*configured|nfq.*inline|nfq.*passive|live inline" "$LOG_FILE" 2>/dev/null | tail -1)
    if [ -n "$DAQ_LINE" ]; then
        echo "   $DAQ_LINE"
        if echo "$DAQ_LINE" | grep -qiE "inline|live inline"; then
            echo ""
            echo "✅ IPS MODE: TRUE INLINE BLOCKING"
            echo "   Packets WILL be blocked!"
        elif echo "$DAQ_LINE" | grep -qi "passive"; then
            echo ""
            echo "❌ IDS MODE: PASSIVE (NOT blocking!)"
            echo "   Missing -Q flag or --daq-mode inline"
        else
            echo ""
            echo "⚠️  Mode unclear from log"
        fi
    else
        echo "   No NFQUEUE DAQ line found yet"
        echo "   Checking if Snort is using -Q flag (most reliable indicator)..."
        # If -Q flag is present, Snort is in inline mode regardless of log message
        SNORT_PID=$(pgrep -f "snort-install/bin/snort" | head -1)
        if [ -n "$SNORT_PID" ]; then
            SNORT_CMD=$(sudo ps -p "$SNORT_PID" -o args= 2>/dev/null || ps -p "$SNORT_PID" -o args= 2>/dev/null || echo "")
            if echo "$SNORT_CMD" | grep -qE "\-Q"; then
                echo "   ✅ -Q flag found in command → INLINE MODE"
                echo "   ✅ IPS should be blocking packets!"
            fi
        fi
    fi
else
    echo "⚠️  Log file not found: $LOG_FILE"
fi

echo ""

# Check for actual Snort process
echo "📋 Snort Process:"
SNORT_PID=$(pgrep -f "snort-install/bin/snort" | head -1)
if [ -n "$SNORT_PID" ]; then
    echo "   ✅ Snort running (PID: $SNORT_PID)"
    SNORT_CMD=$(sudo ps -p "$SNORT_PID" -o args= 2>/dev/null || ps -p "$SNORT_PID" -o args= 2>/dev/null || echo "")
    if echo "$SNORT_CMD" | grep -qE "\-Q"; then
        echo "   ✅ -Q flag found"
    else
        echo "   ❌ -Q flag NOT found"
    fi
    if echo "$SNORT_CMD" | grep -q "nfq"; then
        echo "   ✅ NFQUEUE DAQ"
    else
        echo "   ⚠️  Not using NFQUEUE"
    fi
else
    echo "   ❌ Snort not running"
fi

echo ""
echo "========================="

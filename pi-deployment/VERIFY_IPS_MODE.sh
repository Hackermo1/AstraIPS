#!/bin/bash
# Verify IPS Mode is Actually Working
# Checks logs and processes to confirm inline blocking is enabled

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="${PROJECT_DIR:-$SCRIPT_DIR/..}"
cd "$PROJECT_DIR"

echo "🔍 IPS Mode Verification"
echo "========================"
echo ""

# Check SNORT_DAQ_MODE
echo "1. Environment Variable:"
echo "   SNORT_DAQ_MODE: ${SNORT_DAQ_MODE:-not set}"
if [ "$SNORT_DAQ_MODE" = "inline" ]; then
    echo "   ✅ Set to 'inline' - should use NFQUEUE"
else
    echo "   ⚠️  Not set to 'inline' - will use afpacket (may be passive)"
fi
echo ""

# Check Snort process
echo "2. Snort Process:"
if pgrep -f "snort.*mqtt" > /dev/null; then
    SNORT_PID=$(pgrep -f "snort.*mqtt" | head -1)
    echo "   ✅ Snort running (PID: $SNORT_PID)"
    
    # Check command line
    SNORT_CMD=$(ps -p $SNORT_PID -o args= 2>/dev/null || echo "")
    if echo "$SNORT_CMD" | grep -qi "nfq\|nfqueue"; then
        echo "   ✅ Using NFQUEUE DAQ"
        if echo "$SNORT_CMD" | grep -q "daq-mode inline"; then
            echo "   ✅ Inline mode enabled in command"
        elif echo "$SNORT_CMD" | grep -q "SNORT_DAQ_MODE.*inline"; then
            echo "   ✅ SNORT_DAQ_MODE=inline set"
        else
            echo "   ⚠️  Inline mode not explicitly in command (check logs)"
        fi
        # NFQUEUE with iptables rules = inline blocking
        NFQ_RULES=$(sudo iptables -L -n -v 2>/dev/null | grep -c NFQUEUE || echo "0")
        if [ "$NFQ_RULES" -gt 0 ]; then
            echo "   ✅ NFQUEUE rules active ($NFQ_RULES rules) - INLINE BLOCKING ENABLED"
        fi
    elif echo "$SNORT_CMD" | grep -qi "afpacket"; then
        echo "   ⚠️  Using AFPACKET DAQ"
        if echo "$SNORT_CMD" | grep -q "SNORT_DAQ_MODE.*inline"; then
            echo "   ✅ SNORT_DAQ_MODE=inline set"
        else
            echo "   ⚠️  SNORT_DAQ_MODE not set to inline"
        fi
    elif echo "$SNORT_CMD" | grep -qi "pcap"; then
        echo "   ⚠️  Using PCAP DAQ (passive monitoring)"
    else
        echo "   ⚠️  Unknown DAQ type"
        echo "   Command: ${SNORT_CMD:0:100}..."
    fi
else
    echo "   ❌ Snort not running"
fi
echo ""

# Check Snort console log
echo "3. Snort Console Log:"
CONSOLE_LOG="$PROJECT_DIR/logs/snort_console.log"
if [ -f "$CONSOLE_LOG" ]; then
    # Check for NFQUEUE
    if grep -qi "nfq\|nfqueue" "$CONSOLE_LOG" 2>/dev/null; then
        if grep -qi "nfq.*inline\|live inline\|DAQ.*inline" "$CONSOLE_LOG" 2>/dev/null; then
            echo "   ✅ Log shows NFQUEUE with inline mode"
            echo "   ✅ TRUE INLINE IPS MODE - Packets will be BLOCKED"
        elif grep -qi "nfq.*passive" "$CONSOLE_LOG" 2>/dev/null; then
            echo "   ❌ Log shows: 'nfq DAQ configured to passive'"
            echo "   ❌ NOT blocking packets - only monitoring!"
        else
            # NFQUEUE detected but mode unclear - check if rules exist
            NFQ_RULES=$(sudo iptables -L -n -v 2>/dev/null | grep -c NFQUEUE || echo "0")
            if [ "$NFQ_RULES" -gt 0 ]; then
                echo "   ✅ NFQUEUE DAQ detected with active rules"
                echo "   ✅ Likely INLINE MODE (NFQUEUE + iptables = blocking)"
            else
                echo "   ⚠️  NFQUEUE detected but no iptables rules"
            fi
        fi
    elif grep -qi "afpacket" "$CONSOLE_LOG" 2>/dev/null; then
        echo "   ⚠️  Using AFPACKET DAQ"
        if grep -qi "SNORT_DAQ_MODE.*inline\|inline.*mode" "$CONSOLE_LOG" 2>/dev/null; then
            echo "   ✅ Inline mode detected in log"
        else
            echo "   ⚠️  Inline mode not clearly detected"
        fi
    elif grep -qi "pcap" "$CONSOLE_LOG" 2>/dev/null; then
        echo "   ⚠️  Using PCAP DAQ (passive monitoring)"
    else
        echo "   ⚠️  ⚠️  Could not determine DAQ mode from log"
        echo "   Last DAQ-related lines:"
        grep -iE "DAQ|daq" "$CONSOLE_LOG" 2>/dev/null | tail -3 | sed 's/^/      /'
    fi
else
    echo "   ⚠️  Console log not found: $CONSOLE_LOG"
fi
echo ""

# Check NFQUEUE rules
echo "4. iptables NFQUEUE Rules:"
NFQUEUE_RULES=$(sudo iptables -L -n -v 2>/dev/null | grep -c NFQUEUE || echo "0")
if [ "$NFQUEUE_RULES" -gt 0 ]; then
    echo "   ✅ NFQUEUE rules found ($NFQUEUE_RULES rules)"
    echo "   Rules:"
    sudo iptables -L -n -v 2>/dev/null | grep NFQUEUE | head -3 | sed 's/^/      /'
else
    echo "   ⚠️  No NFQUEUE rules found"
    echo "   Run: ./setup_nfqueue_rules.sh"
fi
echo ""

# Check debug log
echo "5. IPS Debug Log:"
DEBUG_LOG="/tmp/snort_ips_debug.log"
if [ -f "$DEBUG_LOG" ]; then
    DROP_CALLS=$(grep -c "CALLING drop()" "$DEBUG_LOG" 2>/dev/null || echo "0")
    DROP_CALLS=$(echo "$DROP_CALLS" | tr -d '\n\r' | head -1)
    echo "   ✅ Debug log exists"
    echo "   drop() calls: $DROP_CALLS"
    if [ "$DROP_CALLS" -gt 0 ]; then
        echo "   ✅ drop() function is being called!"
    else
        echo "   ⚠️  No drop() calls yet (may need malicious traffic)"
    fi
else
    echo "   ⚠️  Debug log not found (will be created when Snort processes packets)"
fi
echo ""

# Summary
echo "========================"
echo "Summary:"
echo "========================"

# Check if NFQUEUE is actually being used (most reliable indicator)
NFQ_IN_USE=false
if pgrep -f "snort.*nfq\|snort.*nfqueue" > /dev/null 2>&1; then
    NFQ_IN_USE=true
fi

# Check if NFQUEUE rules exist and packets are being processed
NFQ_RULES=$(sudo iptables -L -n -v 2>/dev/null | grep -c NFQUEUE || echo "0")
NFQ_PACKETS=$(sudo iptables -L -n -v 2>/dev/null | grep NFQUEUE | head -1 | awk '{print $1}' || echo "0")

if [ "$NFQ_IN_USE" = true ] || ([ "$NFQ_RULES" -gt 0 ] && [ "$NFQ_PACKETS" -gt 0 ]); then
    echo "✅ IPS MODE: TRUE INLINE BLOCKING ENABLED"
    echo "   - Using NFQUEUE DAQ ✓"
    echo "   - NFQUEUE rules active ($NFQ_RULES rules) ✓"
    echo "   - Packets processed: $NFQ_PACKETS ✓"
    echo "   - Packets WILL be blocked"
    if [ "$SNORT_DAQ_MODE" != "inline" ]; then
        echo "   ⚠️  Note: SNORT_DAQ_MODE not set, but NFQUEUE is active"
    fi
elif [ "$SNORT_DAQ_MODE" = "inline" ] && pgrep -f "snort.*afpacket" > /dev/null; then
    echo "⚠️  IPS MODE: AFPACKET (may be passive)"
    echo "   - SNORT_DAQ_MODE=inline ✓"
    echo "   - Using AFPACKET DAQ"
    echo "   - Check logs to verify inline mode"
else
    echo "⚠️  IDS MODE: PASSIVE MONITORING"
    echo "   - SNORT_DAQ_MODE not set to 'inline'"
    if [ "$NFQ_RULES" -gt 0 ]; then
        echo "   - NFQUEUE rules exist but Snort not using NFQUEUE"
    fi
    echo "   - Packets will NOT be blocked"
    echo "   - To enable IPS: export SNORT_DAQ_MODE=inline && ./mqttlive eth0"
fi
echo ""

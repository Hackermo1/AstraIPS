#!/bin/bash
#
# Wrapper script for mqttlive that captures full terminal output
# Usage: ./mqttlive_with_capture.sh [mqttlive arguments]
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MQTTLIVE_SCRIPT="$SCRIPT_DIR/mqttlive"

# Check if mqttlive exists
if [ ! -f "$MQTTLIVE_SCRIPT" ]; then
    echo "❌ Error: mqttlive not found at $MQTTLIVE_SCRIPT"
    exit 1
fi

# Make sure mqttlive is executable
chmod +x "$MQTTLIVE_SCRIPT" 2>/dev/null

# Get session directory (will be created by mqttlive)
# We'll capture output and move it to the session directory after
TEMP_OUTPUT="/tmp/mqttlive_terminal_output_$$.txt"

# Start script command to capture all output
# script command captures everything including colors and control characters
script -q -c "bash '$MQTTLIVE_SCRIPT' $@" "$TEMP_OUTPUT"

# Get the actual session directory from mqttlive's output or find latest
SESSION_DIR=$(find "$SCRIPT_DIR/logs" -type d -name "20*" -maxdepth 1 2>/dev/null | sort | tail -1)

if [ -z "$SESSION_DIR" ]; then
    # Try to find session.db to get directory
    SESSION_DIR=$(find "$SCRIPT_DIR/logs" -name "session.db" -type f 2>/dev/null | head -1 | xargs dirname)
fi

if [ -n "$SESSION_DIR" ] && [ -d "$SESSION_DIR" ]; then
    FINAL_OUTPUT="$SESSION_DIR/terminal_output_full.txt"
    if [ -f "$TEMP_OUTPUT" ]; then
        mv "$TEMP_OUTPUT" "$FINAL_OUTPUT" 2>/dev/null || cp "$TEMP_OUTPUT" "$FINAL_OUTPUT" 2>/dev/null
        echo ""
        echo "💾 Full terminal output saved to: $FINAL_OUTPUT"
        chmod 644 "$FINAL_OUTPUT" 2>/dev/null
    fi
else
    # Fallback: keep in temp location
    if [ -f "$TEMP_OUTPUT" ]; then
        echo ""
        echo "💾 Terminal output saved to: $TEMP_OUTPUT"
        echo "   (Session directory not found, output kept in temp location)"
    fi
fi

# Cleanup temp file if it still exists
rm -f "$TEMP_OUTPUT" 2>/dev/null

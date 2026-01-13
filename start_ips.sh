#!/bin/bash
# =============================================================================
# AstraIPS Quick Start Script
# Simple wrapper to start the IPS system
# =============================================================================

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export PROJECT_DIR="$SCRIPT_DIR"
export SNORT_DAQ_MODE="inline"

echo "🛡️  Starting AstraIPS..."
echo "   PROJECT_DIR=$PROJECT_DIR"
echo "   SNORT_DAQ_MODE=$SNORT_DAQ_MODE"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  IPS mode requires root privileges."
    echo "   Running with sudo..."
    exec sudo -E "$SCRIPT_DIR/mqttlive" "$@"
else
    exec "$SCRIPT_DIR/mqttlive" "$@"
fi

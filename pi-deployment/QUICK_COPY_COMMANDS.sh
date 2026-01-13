#!/bin/bash
# Quick copy commands - Run this on Pi after files are copied

cd ~/snort3 || cd "$(dirname "$0")/.."

echo "🔄 Replacing files with universal versions..."

# Replace originals with universal versions
cp pi_migration_files/mqttlive_pi mqttlive
cp pi_migration_files/snortlive_pi.sh snortlive.sh
cp pi_migration_files/mqtt_final_pi.lua config/mqtt_final.lua
cp pi_migration_files/enhanced_ai_inspector_pi.lua config/enhanced_ai_inspector.lua

# Make executable
chmod +x mqttlive snortlive.sh

echo "✅ Files replaced with universal versions!"
echo ""
echo "📋 Next steps:"
echo "   1. source set_paths.sh"
echo "   2. source venv/bin/activate"
echo "   3. ./mqttlive eth0"

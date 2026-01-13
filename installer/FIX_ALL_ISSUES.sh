#!/bin/bash
# Fix common issues - Run this if you encounter problems

# Get project directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "🔧 Fixing common issues..."
echo "   Project: $PROJECT_DIR"
echo ""

cd "$PROJECT_DIR"

# 1. Kill port 1883/1889
echo "1️⃣  Killing processes on MQTT ports..."
sudo lsof -ti:1883 | xargs -r sudo kill -9 2>/dev/null || true
sudo lsof -ti:1889 | xargs -r sudo kill -9 2>/dev/null || true
sudo lsof -ti:9998 | xargs -r sudo kill -9 2>/dev/null || true
sudo systemctl stop mosquitto 2>/dev/null || true
pkill -f "mqtt_router.py" 2>/dev/null || true
pkill -f "ai_decision_server.py" 2>/dev/null || true
sleep 2
echo "✅ Ports cleared"
echo ""

# 2. Delete old database (optional)
echo "2️⃣  Checking database..."
if [ -f "$PROJECT_DIR/logs/session.db" ]; then
    read -p "   Delete old database? (y/n) [n]: " del_db
    if [[ "$del_db" == "y" || "$del_db" == "Y" ]]; then
        rm -f "$PROJECT_DIR/logs/session.db"
        echo "✅ Database deleted (will be recreated)"
    else
        echo "✅ Database kept"
    fi
else
    echo "✅ No old database found"
fi
mkdir -p "$PROJECT_DIR/logs"/{exports,pcap,scans}
echo ""

# 3. Fix permissions
echo "3️⃣  Fixing permissions..."
chmod +x "$PROJECT_DIR/mqttlive" 2>/dev/null || true
chmod +x "$PROJECT_DIR/snortlive.sh" 2>/dev/null || true
chmod +x "$PROJECT_DIR/start_ips.sh" 2>/dev/null || true
chmod +x "$PROJECT_DIR/installer/"*.sh 2>/dev/null || true
echo "✅ Permissions fixed"
echo ""

# 4. Set environment variables
echo "4️⃣  Setting environment variables..."
export PROJECT_DIR
export CONFIG_DIR="$PROJECT_DIR/config"
export LD_LIBRARY_PATH="/usr/local/lib:$LD_LIBRARY_PATH"
export PATH="/usr/local/bin:$PATH"
echo "✅ Environment set"
echo ""

# 5. Check Snort
echo "5️⃣  Checking Snort..."
if command -v snort &> /dev/null; then
    snort --version 2>&1 | head -3
    echo "✅ Snort found"
else
    echo "❌ Snort not found - run ./installer/install.sh"
fi
echo ""

echo "✅ All fixes complete!"
echo ""
echo "🚀 Now run:"
echo "   sudo ./mqttlive"
echo ""

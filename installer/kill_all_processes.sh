#!/bin/bash
# Kill ALL processes related to Snort, MQTT, and mqttlive
# Run this before starting mqttlive to avoid conflicts

echo "🛑 KILLING ALL PROCESSES..."
echo "============================"
echo ""

# Kill mqttlive and related scripts
echo "1️⃣  Killing mqttlive processes..."
pkill -9 -f mqttlive 2>/dev/null
pkill -9 -f "bash.*mqttlive" 2>/dev/null
sleep 1

# Kill Snort processes
echo "2️⃣  Killing Snort processes..."
pkill -9 -f "snort-install/bin/snort" 2>/dev/null
pkill -9 -f "snort.*nfq" 2>/dev/null
pkill -9 -f "snort.*afpacket" 2>/dev/null
pkill -9 -f "snort.*pcap" 2>/dev/null
sudo pkill -9 -f "snort-install/bin/snort" 2>/dev/null
sleep 1

# Kill MQTT processes
echo "3️⃣  Killing MQTT processes..."
pkill -9 -f mosquitto 2>/dev/null
pkill -9 -f mqtt_router 2>/dev/null
pkill -9 -f "python.*mqtt_router" 2>/dev/null
pkill -9 -f snort_mqtt_enhanced 2>/dev/null
pkill -9 -f "python.*snort_mqtt" 2>/dev/null
sudo pkill -9 -f mosquitto 2>/dev/null
sleep 1

# Kill executor processes
echo "4️⃣  Killing executor processes..."
pkill -9 -f "snort_mqtt_enhanced.py" 2>/dev/null
pkill -9 -f "mqtt.*executor" 2>/dev/null
sleep 1

# Kill AI server and device profiler
echo "5️⃣  Killing AI components..."
pkill -9 -f ai_decision_server 2>/dev/null
pkill -9 -f device_profiler 2>/dev/null
pkill -9 -f "python.*ai_server" 2>/dev/null
pkill -9 -f "python.*device_profiler" 2>/dev/null
sleep 1

# Kill system monitor
echo "6️⃣  Killing system monitor..."
pkill -9 -f system_monitor 2>/dev/null
pkill -9 -f "python.*system_monitor" 2>/dev/null
sleep 1

# Kill alert logger
echo "7️⃣  Killing alert logger..."
pkill -9 -f snort_alert_logger 2>/dev/null
pkill -9 -f "python.*snort_alert_logger" 2>/dev/null
sleep 1

# Kill display processes
echo "8️⃣  Killing display processes..."
pkill -9 -f clean_terminal_display 2>/dev/null
pkill -9 -f "python.*clean_terminal_display" 2>/dev/null
sleep 1

# Kill router scanner
echo "9️⃣  Killing router scanner..."
pkill -9 -f pull_scanner 2>/dev/null
pkill -9 -f router_manager 2>/dev/null
pkill -9 -f "python.*pull_scanner" 2>/dev/null
sleep 1

# Kill any processes using port 1883 (MQTT)
echo "🔟 Killing processes on port 1883..."
sudo lsof -ti:1883 | xargs -r sudo kill -9 2>/dev/null
sudo fuser -k 1883/tcp 2>/dev/null
sleep 1

# Kill any processes using port 9998 (AI server)
echo "1️⃣1️⃣  Killing processes on port 9998..."
sudo lsof -ti:9998 | xargs -r sudo kill -9 2>/dev/null
sudo fuser -k 9998/tcp 2>/dev/null
sleep 1

# Stop systemd services if they exist
echo "1️⃣2️⃣  Stopping systemd services..."
sudo systemctl stop mosquitto 2>/dev/null
sudo systemctl stop snort 2>/dev/null
sleep 1

# Clean up PID files
echo "1️⃣3️⃣  Cleaning up PID files..."
rm -f /tmp/mqttlive*.pid 2>/dev/null
rm -f ~/snort3/logs/.snort*.pid 2>/dev/null
rm -f ~/snort3/logs/.mqtt*.pid 2>/dev/null
rm -f ~/snort3/logs/.executor*.pid 2>/dev/null
rm -f ~/snort3/logs/.ai_server*.pid 2>/dev/null
rm -f ~/snort3/logs/.device_profiler*.pid 2>/dev/null
rm -f ~/snort3/logs/.system_monitor*.pid 2>/dev/null
rm -f ~/snort3/logs/.router_scanner*.pid 2>/dev/null
rm -f ~/snort3/logs/.pcap_capture.pid 2>/dev/null

# Final check - show what's still running
echo ""
echo "📊 Checking for remaining processes..."
echo "====================================="
REMAINING=$(pgrep -f "mqttlive|snort|mosquitto|mqtt_router|snort_mqtt|ai_server|device_profiler|system_monitor|snort_alert_logger|clean_terminal_display" | wc -l)
if [ "$REMAINING" -gt 0 ]; then
    echo "⚠️  Warning: $REMAINING processes still running:"
    pgrep -f "mqttlive|snort|mosquitto|mqtt_router|snort_mqtt|ai_server|device_profiler|system_monitor|snort_alert_logger|clean_terminal_display" | xargs ps -p 2>/dev/null | head -10
    echo ""
    echo "💡 Try running with sudo if processes persist"
else
    echo "✅ All processes killed successfully!"
fi

# Check ports
echo ""
echo "📡 Checking ports..."
echo "==================="
if lsof -ti:1883 >/dev/null 2>&1; then
    echo "⚠️  Port 1883 still in use:"
    sudo lsof -i:1883 | head -5
else
    echo "✅ Port 1883 is free"
fi

if lsof -ti:9998 >/dev/null 2>&1; then
    echo "⚠️  Port 9998 still in use:"
    sudo lsof -i:9998 | head -5
else
    echo "✅ Port 9998 is free"
fi

echo ""
echo "✅ Cleanup complete!"
echo ""
echo "💡 Now you can safely run: ./mqttlive eth0"

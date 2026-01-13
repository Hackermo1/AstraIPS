#!/bin/bash
# Setup NFQUEUE iptables rules for Snort inline IPS mode
# Run this BEFORE starting mqttlive in IPS mode

echo "🔧 Setting up NFQUEUE iptables rules for Snort inline IPS..."

# Flush old rules (clean start)
echo "📋 Flushing old iptables rules..."
sudo iptables -F
sudo iptables -t nat -F
sudo iptables -t mangle -F

# Create NFQUEUE rules so kernel sends traffic to Snort
echo "🔗 Creating NFQUEUE rules..."
sudo iptables -I FORWARD -j NFQUEUE --queue-num 0 --queue-bypass
sudo iptables -I INPUT   -j NFQUEUE --queue-num 0 --queue-bypass
sudo iptables -I OUTPUT  -j NFQUEUE --queue-num 0 --queue-bypass

echo "✅ NFQUEUE rules configured!"
echo ""
echo "📋 Current iptables rules:"
sudo iptables -L -n -v | grep NFQUEUE
echo ""
echo "✅ Ready for REAL inline IPS mode!"
echo "   Snort will use: --daq nfq --daq-mode inline --daq-var fail_open=no --daq-var mode=inline"
echo "   This ensures malicious packets are ACTUALLY DROPPED (not just logged)"
echo ""
echo "   Run: ./mqttlive eth0"

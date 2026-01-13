# AstraIPS - Quick Start Guide

## 🚀 Fastest Way to Get Started

```bash
cd AstraIPS
sudo ./installer/install.sh   # One-time setup (30-60 min)
sudo ./mqttlive               # Start the IPS
```

That's it! The system will:
1. Auto-detect your ethernet interface
2. Start the AI Decision Server
3. Start Snort3 in inline IPS mode
4. Protect your network

## What Happens When You Run `./mqttlive`

1. **AI Decision Server** starts on port 9998
2. **Device Profiler** tracks connected devices
3. **MQTT Router** listens on port 1889
4. **iptables** redirects port 1883 → 1889
5. **Snort3** inspects packets via NFQUEUE
6. **Malicious packets** get DROPPED

## Stopping the System

Press `Ctrl+C` - cleanup happens automatically.

## Logs

All logs are in the `logs/` folder:
- `logs/snort.log` - Snort output
- `logs/ai_server.log` - AI decisions
- `logs/mqtt_router.log` - MQTT traffic
- `logs/session.db` - SQLite database with all events

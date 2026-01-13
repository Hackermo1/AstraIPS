# AstraIPS Debugging Guide

## Common Issues

### 1. Snort Not Starting

**Check config:**
```bash
snort -c config/mqtt_final.lua -T
```

**Check DAQ modules:**
```bash
snort --daq-list | grep nfq
```

If NFQ missing, rebuild libdaq with `libnetfilter-queue-dev` installed.

### 2. No Traffic Being Inspected

**Check iptables rules:**
```bash
sudo iptables -t nat -L -n -v
sudo iptables -L -n -v | grep NFQUEUE
```

**Check MQTT Router is listening:**
```bash
ss -tlnp | grep 1889
```

### 3. AI Server Not Responding

**Check port 9998:**
```bash
ss -tlnp | grep 9998
```

**Check logs:**
```bash
cat logs/logs/ai_server.log
```

**Check TensorFlow:**
```bash
python3 -c "import tensorflow; print(tensorflow.__version__)"
```

### 4. Permission Denied

**Run with sudo:**
```bash
sudo ./mqttlive
```

**Or set capabilities:**
```bash
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/snort
```

### 5. Port Already in Use

**Kill existing processes:**
```bash
sudo ./installer/kill_all_processes.sh
```

**Or manually:**
```bash
sudo lsof -ti:1883 | xargs -r sudo kill -9
sudo lsof -ti:1889 | xargs -r sudo kill -9
sudo lsof -ti:9998 | xargs -r sudo kill -9
```

## Debug Mode

Check the debug log:
```bash
tail -f /tmp/snort_ips_debug.log
```

## Log Locations

| Log | Location |
|-----|----------|
| Snort | `logs/logs/snort.log` |
| AI Server | `logs/logs/ai_server.log` |
| MQTT Router | `logs/logs/mqtt_router.log` |
| System Monitor | `logs/logs/system_monitor.log` |
| IPS Debug | `/tmp/snort_ips_debug.log` |

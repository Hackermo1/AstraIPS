# AstraIPS - Dashboard Documentation

## 📊 Dashboard Features

The dashboard generator creates an HTML dashboard with interactive visualizations.

### Summary Statistics (8 cards)
- Total Devices
- Total Alerts  
- Blocked Devices
- MQTT Packets
- Heuristic Flags
- AI Blocks
- Confirmed Malicious
- Critical Alerts

### Interactive Graphs (4 charts)
1. **Alert Priority Distribution** - Doughnut chart (Critical/High/Medium/Low)
2. **Device Detection Stages** - Bar chart (Stages 0-4)
3. **Active Devices Over Time** - Line chart (time series)
4. **Alert Timeline** - Multi-line chart (alerts by priority over time)

### Top Threats Table
- Top 10 threat commands
- Occurrence counts
- Heuristic flags
- AI blocks

---

## 🚀 Usage

### Generate Dashboard After Session

```bash
cd ~/AstraIPS
./dashboard/create_session_summary.sh
```

### Or specify session directory

```bash
SESSION_LOG_DIR=logs/your_session ./dashboard/create_session_summary.sh
```

### View Dashboard

```bash
firefox logs/dashboard/session_dashboard.html
# Or open in any browser
```

### Dashboard Auto-Generation

The dashboard is **automatically generated** when you stop `mqttlive` (Ctrl+C).
You'll see output like:
```
📊 Generating session summary...
   ✅ Web dashboard generated
   ✅ Session exported to Excel

📁 Session data saved to: logs/
   📊 Dashboard: logs/dashboard/session_dashboard.html
   📈 Exports:   logs/exports/
   📦 PCAP:      logs/pcap/
```

---

## 📁 Dashboard Files

| File | Purpose |
|------|---------|
| `dashboard/generate_dashboard.py` | HTML dashboard generator |
| `dashboard/create_session_summary.sh` | Shell wrapper script |
| `dashboard/README.md` | Dashboard documentation |

---

## 📈 Metrics Tracked

The dashboard displays all metrics from the unified `session.db` database:

- **Device Metrics**: Count, MAC addresses, detection stages
- **Alert Metrics**: Priorities, types, timestamps
- **Traffic Metrics**: MQTT messages, packets processed
- **Security Metrics**: Heuristic flags, AI blocks, drops
- **Performance Metrics**: Latency, resource usage

---

## 📦 PCAP Capture

AstraIPS automatically captures all MQTT traffic for forensic analysis.

### PCAP Files Location

```
logs/pcap/mqtt_traffic_YYYYMMDD_HHMMSS.pcap
```

### View PCAP in Wireshark

```bash
wireshark logs/pcap/mqtt_traffic_*.pcap
```

### PCAP Filter (MQTT Traffic Only)

```
tcp port 1883 or tcp port 1889
```

---

## 🎨 Customization

The dashboard can be customized by editing `dashboard/generate_dashboard.py`:

1. Modify HTML template for different layouts
2. Adjust chart types and colors
3. Add additional metrics from the database
4. Change time ranges and aggregations

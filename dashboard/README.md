# Session Dashboard Generator

## Overview
Generates a comprehensive HTML dashboard with interactive graphs and summary statistics after an IPS session ends.

## Usage

### After Session Ends
```bash
# Generate dashboard for latest session
./create_session_summary.sh

# Or specify session directory
SESSION_LOG_DIR=logs/YOUR_SESSION ./create_session_summary.sh

# Or use Python directly
python3 generate_dashboard.py logs/LATEST_SESSION/session.db
```

## Dashboard Features

### Summary Statistics Cards
- Total Devices
- Total Alerts
- Blocked Devices
- MQTT Packets
- Heuristic Flags
- AI Blocks
- Confirmed Malicious
- Critical Alerts

### Interactive Graphs
1. **Alert Priority Distribution** - Doughnut chart showing Critical/High/Medium/Low alerts
2. **Device Detection Stages** - Bar chart showing devices at each enforcement stage (0-4)
3. **Active Devices Over Time** - Line chart showing device count over session duration
4. **Alert Timeline** - Multi-line chart showing alert counts by priority over time

### Top Threats Table
- Lists top 10 most frequent threat commands
- Shows occurrence count, heuristic flags, and AI blocks per command

## Output
Dashboard is saved to: `logs/LATEST_SESSION/dashboard/session_dashboard.html`

Open in browser:
```bash
firefox logs/LATEST_SESSION/dashboard/session_dashboard.html
# Or
xdg-open logs/LATEST_SESSION/dashboard/session_dashboard.html
```

## Dependencies
- pandas
- numpy
- sqlite3 (built-in)
- Chart.js (loaded from CDN in HTML)
